create table if not exists public.blocked_auth_email_domains (
  domain text primary key,
  reason text,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  constraint blocked_auth_email_domains_domain_not_empty check (btrim(domain) <> '')
);

alter table public.blocked_auth_email_domains enable row level security;

insert into public.blocked_auth_email_domains (domain, reason)
values
  ('10minutemail.com', 'disposable email provider'),
  ('guerrillamail.com', 'disposable email provider'),
  ('guerrillamail.net', 'disposable email provider'),
  ('mailinator.com', 'disposable email provider'),
  ('sharklasers.com', 'disposable email provider'),
  ('tempmail.com', 'disposable email provider'),
  ('temp-mail.org', 'disposable email provider'),
  ('temp.ly', 'bot signup burst'),
  ('throwawaymail.com', 'disposable email provider'),
  ('yopmail.com', 'disposable email provider')
on conflict (domain) do update
set reason = excluded.reason,
    active = true;

create or replace function public.auth_email_domain(p_email text)
returns text
language sql
immutable
as $$
  select trim(trailing '.' from lower(split_part(coalesce(p_email, ''), '@', 2)));
$$;

create or replace function public.is_blocked_auth_email_domain(p_email text)
returns boolean
language sql
stable
security definer
set search_path to public
as $$
  select exists (
    select 1
    from public.blocked_auth_email_domains blocked
    where blocked.active
      and blocked.domain = public.auth_email_domain(p_email)
  );
$$;

create or replace function public.enforce_auth_signup_email_domain()
returns trigger
language plpgsql
security definer
set search_path to public
as $$
begin
  if public.is_blocked_auth_email_domain(new.email) then
    raise exception 'Use a permanent email address to create your account';
  end if;

  return new;
end;
$$;

drop trigger if exists enforce_auth_signup_email_domain on auth.users;
create trigger enforce_auth_signup_email_domain
before insert or update of email on auth.users
for each row
execute function public.enforce_auth_signup_email_domain();
