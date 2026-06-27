-- Resend audience views and sync triggers for Social users and Verify accounts.

create or replace view public.resend_social_users_audience as
select
  u.auth_id,
  u.email,
  u.username,
  u.display_name
from public.users u
where u.email is not null
  and btrim(u.email) <> '';

revoke all on public.resend_social_users_audience from anon;
revoke all on public.resend_social_users_audience from authenticated;

create or replace view public.resend_verify_users_audience as
select
  va.enclave_user_id as auth_id,
  u.email,
  u.username,
  u.display_name
from public.verify_accounts va
inner join public.users u
  on u.auth_id = va.enclave_user_id
where u.email is not null
  and btrim(u.email) <> '';

revoke all on public.resend_verify_users_audience from anon;
revoke all on public.resend_verify_users_audience from authenticated;

create or replace function public.queue_social_users_resend_sync()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_secret text;
  v_url text := 'https://eyqaeigblulbtnorqyts.supabase.co/functions/v1/sync-resend-contacts';
  v_email text;
  v_old_email text;
  v_enabled boolean := false;
  v_username text;
  v_display_name text;
begin
  if TG_OP = 'DELETE' then
    v_email := nullif(btrim(coalesce(OLD.email, '')), '');
    v_username := nullif(btrim(coalesce(OLD.username, '')), '');
    v_display_name := nullif(btrim(coalesce(OLD.display_name, '')), '');
    v_enabled := false;
  else
    if TG_OP = 'UPDATE'
      and NEW.email is not distinct from OLD.email
      and NEW.username is not distinct from OLD.username
      and NEW.display_name is not distinct from OLD.display_name then
      return NEW;
    end if;

    v_old_email := nullif(btrim(coalesce(OLD.email, '')), '');
    v_email := nullif(btrim(coalesce(NEW.email, '')), '');
    v_username := nullif(btrim(coalesce(NEW.username, '')), '');
    v_display_name := nullif(btrim(coalesce(NEW.display_name, '')), '');
    v_enabled := v_email is not null;

    if v_old_email is not null
      and v_email is not null
      and lower(v_old_email) <> lower(v_email) then
      select secret_value
      into v_secret
      from public.internal_job_secrets
      where job_key = 'resend_sync'
      limit 1;

      if v_secret is not null and btrim(v_secret) <> '' then
        perform net.http_post(
          url := v_url,
          headers := jsonb_build_object(
            'Content-Type', 'application/json',
            'x-resend-sync-secret', v_secret
          ),
          body := jsonb_build_object(
            'mode', 'event',
            'segment', 'social_users',
            'email', v_old_email,
            'enabled', false
          )
        );
      end if;
    end if;
  end if;

  if v_email is null and TG_OP <> 'DELETE' then
    return coalesce(NEW, OLD);
  end if;

  if v_email is null then
    return OLD;
  end if;

  select secret_value
  into v_secret
  from public.internal_job_secrets
  where job_key = 'resend_sync'
  limit 1;

  if v_secret is null or btrim(v_secret) = '' then
    raise warning 'Social users Resend sync skipped: internal_job_secrets.resend_sync is not configured';
    return coalesce(NEW, OLD);
  end if;

  perform net.http_post(
    url := v_url,
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-resend-sync-secret', v_secret
    ),
    body := jsonb_build_object(
      'mode', 'event',
      'segment', 'social_users',
      'email', v_email,
      'enabled', v_enabled,
      'display_name', v_display_name,
      'first_name', coalesce(v_username, split_part(v_email, '@', 1))
    )
  );

  return coalesce(NEW, OLD);
exception
  when undefined_function then
    raise warning 'Social users Resend sync skipped: pg_net extension is unavailable';
    return coalesce(NEW, OLD);
  when others then
    raise warning 'Social users Resend sync failed: %', sqlerrm;
    return coalesce(NEW, OLD);
end;
$$;

create or replace function public.queue_verify_users_resend_sync()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_secret text;
  v_url text := 'https://eyqaeigblulbtnorqyts.supabase.co/functions/v1/sync-resend-contacts';
  v_auth_id uuid;
  v_email text;
  v_username text;
  v_display_name text;
  v_enabled boolean := false;
begin
  v_auth_id := case when TG_OP = 'DELETE' then OLD.enclave_user_id else NEW.enclave_user_id end;

  select
    nullif(btrim(coalesce(u.email, '')), ''),
    nullif(btrim(coalesce(u.username, '')), ''),
    nullif(btrim(coalesce(u.display_name, '')), '')
  into v_email, v_username, v_display_name
  from public.users u
  where u.auth_id = v_auth_id;

  v_enabled := TG_OP <> 'DELETE' and v_email is not null;

  if v_email is null then
    return coalesce(NEW, OLD);
  end if;

  select secret_value
  into v_secret
  from public.internal_job_secrets
  where job_key = 'resend_sync'
  limit 1;

  if v_secret is null or btrim(v_secret) = '' then
    raise warning 'Verify users Resend sync skipped: internal_job_secrets.resend_sync is not configured';
    return coalesce(NEW, OLD);
  end if;

  perform net.http_post(
    url := v_url,
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-resend-sync-secret', v_secret
    ),
    body := jsonb_build_object(
      'mode', 'event',
      'segment', 'verify_users',
      'email', v_email,
      'enabled', v_enabled,
      'display_name', v_display_name,
      'first_name', coalesce(v_username, split_part(v_email, '@', 1))
    )
  );

  return coalesce(NEW, OLD);
exception
  when undefined_function then
    raise warning 'Verify users Resend sync skipped: pg_net extension is unavailable';
    return coalesce(NEW, OLD);
  when others then
    raise warning 'Verify users Resend sync failed: %', sqlerrm;
    return coalesce(NEW, OLD);
end;
$$;

drop trigger if exists social_users_resend_sync on public.users;
create trigger social_users_resend_sync
after insert or update of email, username, display_name or delete
on public.users
for each row
execute function public.queue_social_users_resend_sync();

drop trigger if exists verify_users_resend_sync on public.verify_accounts;
create trigger verify_users_resend_sync
after insert or delete
on public.verify_accounts
for each row
execute function public.queue_verify_users_resend_sync();

-- Keep Verify segment in sync when a Verify holder's Social profile email changes.
create or replace function public.queue_verify_users_resend_sync_from_profile()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_secret text;
  v_url text := 'https://eyqaeigblulbtnorqyts.supabase.co/functions/v1/sync-resend-contacts';
  v_auth_id uuid := coalesce(NEW.auth_id, OLD.auth_id);
  v_email text;
  v_username text;
  v_display_name text;
begin
  if not exists (
    select 1 from public.verify_accounts va where va.enclave_user_id = v_auth_id
  ) then
    return coalesce(NEW, OLD);
  end if;

  if TG_OP = 'UPDATE'
    and NEW.email is not distinct from OLD.email
    and NEW.username is not distinct from OLD.username
    and NEW.display_name is not distinct from OLD.display_name then
    return NEW;
  end if;

  if TG_OP = 'UPDATE' then
    declare
      v_old_email text := nullif(btrim(coalesce(OLD.email, '')), '');
    begin
      if v_old_email is not null
        and v_old_email is distinct from nullif(btrim(coalesce(NEW.email, '')), '') then
        select secret_value into v_secret
        from public.internal_job_secrets
        where job_key = 'resend_sync'
        limit 1;

        if v_secret is not null and btrim(v_secret) <> '' then
          perform net.http_post(
            url := v_url,
            headers := jsonb_build_object(
              'Content-Type', 'application/json',
              'x-resend-sync-secret', v_secret
            ),
            body := jsonb_build_object(
              'mode', 'event',
              'segment', 'verify_users',
              'email', v_old_email,
              'enabled', false
            )
          );
        end if;
      end if;
    end;
  end if;

  v_email := nullif(btrim(coalesce(NEW.email, OLD.email, '')), '');
  if v_email is null then
    return coalesce(NEW, OLD);
  end if;

  v_username := nullif(btrim(coalesce(NEW.username, OLD.username, '')), '');
  v_display_name := nullif(btrim(coalesce(NEW.display_name, OLD.display_name, '')), '');

  select secret_value into v_secret
  from public.internal_job_secrets
  where job_key = 'resend_sync'
  limit 1;

  if v_secret is null or btrim(v_secret) = '' then
    return coalesce(NEW, OLD);
  end if;

  perform net.http_post(
    url := v_url,
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-resend-sync-secret', v_secret
    ),
    body := jsonb_build_object(
      'mode', 'event',
      'segment', 'verify_users',
      'email', v_email,
      'enabled', true,
      'display_name', v_display_name,
      'first_name', coalesce(v_username, split_part(v_email, '@', 1))
    )
  );

  return coalesce(NEW, OLD);
exception
  when others then
    raise warning 'Verify profile Resend sync failed: %', sqlerrm;
    return coalesce(NEW, OLD);
end;
$$;

drop trigger if exists verify_users_profile_resend_sync on public.users;
create trigger verify_users_profile_resend_sync
after update of email, username, display_name
on public.users
for each row
execute function public.queue_verify_users_resend_sync_from_profile();
