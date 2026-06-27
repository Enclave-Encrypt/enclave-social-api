create or replace function public.cleanup_unverified_auth_users(
  p_batch_size integer default 500,
  p_older_than interval default interval '1 month'
)
returns integer
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  deleted_count integer := 0;
begin
  with doomed as (
    select id
    from auth.users
    where email is not null
      and email_confirmed_at is null
      and confirmed_at is null
      and created_at < now() - p_older_than
    order by created_at asc
    limit greatest(1, p_batch_size)
  ),
  deleted as (
    delete from auth.users au
    using doomed d
    where au.id = d.id
    returning au.id
  )
  select count(*) into deleted_count from deleted;

  return coalesce(deleted_count, 0);
end;
$$;

revoke all on function public.cleanup_unverified_auth_users(integer, interval) from public;

do $$
begin
  create extension if not exists pg_cron with schema extensions;
exception
  when others then
    null;
end;
$$;

do $$
begin
  if exists (select 1 from pg_namespace where nspname = 'cron') then
    perform cron.unschedule(jobid)
    from cron.job
    where jobname = 'cleanup-unverified-auth-users';

    perform cron.schedule(
      'cleanup-unverified-auth-users',
      '23 8 * * *',
      $cron$select public.cleanup_unverified_auth_users(500, interval '1 month');$cron$
    );
  end if;
exception
  when others then
    null;
end;
$$;
