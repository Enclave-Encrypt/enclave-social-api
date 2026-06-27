alter table public.users
  add column if not exists marketing_emails_enabled boolean not null default false,
  add column if not exists marketing_emails_opted_in_at timestamptz,
  add column if not exists marketing_emails_opted_in_source text,
  add column if not exists marketing_emails_unsubscribed_at timestamptz;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path to public
as $$
declare
  wants_marketing boolean :=
    coalesce((new.raw_user_meta_data ->> 'marketing_emails_enabled')::boolean, false);
begin
  insert into public.users (
    auth_id,
    email,
    username,
    display_name,
    age_range,
    nsfw_enabled,
    marketing_emails_enabled,
    marketing_emails_opted_in_at,
    marketing_emails_opted_in_source
  )
  values (
    new.id,
    new.email,
    new.raw_user_meta_data ->> 'username',
    new.raw_user_meta_data ->> 'display_name',
    case
      when (new.raw_user_meta_data ->> 'age_range') in ('under_13', '13_17', '18_plus')
      then (new.raw_user_meta_data ->> 'age_range')::age_range_type
      else null
    end,
    false,
    wants_marketing,
    case when wants_marketing then now() else null end,
    case when wants_marketing then 'signup' else null end
  )
  on conflict (auth_id) do nothing;
  return new;
end;
$$;

create or replace view public.marketing_email_audience as
select
  auth_id,
  email,
  username,
  display_name,
  marketing_emails_opted_in_at,
  marketing_emails_opted_in_source
from public.users
where marketing_emails_enabled = true
  and email is not null
  and btrim(email) <> '';

revoke all on public.marketing_email_audience from anon;
revoke all on public.marketing_email_audience from authenticated;
