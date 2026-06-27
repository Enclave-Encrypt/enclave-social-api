-- Social marketing Resend sync: recompute effective audience (Account + Social prefs).

create or replace function public.queue_social_marketing_resend_sync()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_secret text;
  v_url text := 'https://eyqaeigblulbtnorqyts.supabase.co/functions/v1/sync-resend-contacts';
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
  where job_key = 'resend_sync'
  limit 1;

  if v_secret is null or btrim(v_secret) = '' then
    raise warning 'Social marketing Resend sync skipped: internal_job_secrets.resend_sync is not configured';
    return NEW;
  end if;

  perform net.http_post(
    url := v_url,
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-resend-sync-secret', v_secret
    ),
    body := jsonb_build_object(
      'mode', 'event',
      'segment', 'social_marketing',
      'email', v_email,
      'recompute', true,
      'display_name', NEW.display_name,
      'first_name', NEW.username
    )
  );
exception
  when undefined_function then
    raise warning 'Social marketing Resend sync skipped: pg_net extension is unavailable';
  when others then
    raise warning 'Social marketing Resend sync failed: %', sqlerrm;
end;
$$;
