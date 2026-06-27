-- Social marketing Loops sync: recompute effective audience (Account + Social prefs).

create or replace function public.queue_social_marketing_loops_sync()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_secret text;
  v_url text := 'https://eyqaeigblulbtnorqyts.supabase.co/functions/v1/sync-loops-contacts';
  v_email text;
begin
  if TG_OP = 'UPDATE'
    and NEW.marketing_emails_enabled is not distinct from OLD.marketing_emails_enabled
    and NEW.email is not distinct from OLD.email
    and NEW.display_name is not distinct from OLD.display_name
    and NEW.username is not distinct from OLD.username then
    return NEW;
  end if;

  v_email := nullif(btrim(coalesce(NEW.email, '')), '');
  if v_email is null then
    return NEW;
  end if;

  select secret_value
  into v_secret
  from public.internal_job_secrets
  where job_key = 'loops_sync'
  limit 1;

  if v_secret is null or btrim(v_secret) = '' then
    raise warning 'Social marketing Loops sync skipped: internal_job_secrets.loops_sync is not configured';
    return NEW;
  end if;

  perform net.http_post(
    url := v_url,
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-loops-sync-secret', v_secret
    ),
    body := jsonb_build_object(
      'mode', 'event',
      'email', v_email,
      'recompute', true,
      'display_name', NEW.display_name,
      'first_name', NEW.username
    )
  );
  return NEW;
exception
  when undefined_function then
    raise warning 'Social marketing Loops sync skipped: pg_net extension is unavailable';
    return NEW;
  when others then
    raise warning 'Social marketing Loops sync failed: %', sqlerrm;
    return NEW;
end;
$$;

drop trigger if exists social_marketing_resend_sync on public.users;
create trigger social_marketing_loops_sync
after insert or update of marketing_emails_enabled, email, display_name, username
on public.users
for each row
execute function public.queue_social_marketing_loops_sync();

insert into public.internal_job_secrets (job_key, secret_value)
select 'loops_sync', secret_value
from public.internal_job_secrets
where job_key = 'resend_sync'
on conflict (job_key) do nothing;
