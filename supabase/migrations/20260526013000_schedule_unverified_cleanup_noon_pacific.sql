do $$
begin
  if exists (select 1 from pg_namespace where nspname = 'cron') then
    perform cron.unschedule(jobid)
    from cron.job
    where jobname in (
      'cleanup-unverified-auth-users',
      'cleanup-unverified-auth-users-noon-pacific-pdt',
      'cleanup-unverified-auth-users-noon-pacific-pst'
    );

    perform cron.schedule(
      'cleanup-unverified-auth-users-noon-pacific-pdt',
      '0 19 * * *',
      $cron$
        select case
          when extract(hour from timezone('America/Los_Angeles', now())) = 12
          then public.cleanup_unverified_auth_users(500, interval '1 month')
          else 0
        end;
      $cron$
    );

    perform cron.schedule(
      'cleanup-unverified-auth-users-noon-pacific-pst',
      '0 20 * * *',
      $cron$
        select case
          when extract(hour from timezone('America/Los_Angeles', now())) = 12
          then public.cleanup_unverified_auth_users(500, interval '1 month')
          else 0
        end;
      $cron$
    );
  end if;
exception
  when others then
    null;
end;
$$;
