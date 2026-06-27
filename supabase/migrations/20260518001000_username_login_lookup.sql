-- Resolve a public username to the auth email used by Supabase sign-in.
-- This keeps username login working without requiring broad anonymous reads on
-- public.users.

create or replace function public.lookup_login_email_by_username(p_username text)
returns text
language sql
security definer
set search_path = public
as $$
  select u.email
  from public.users u
  where u.username = lower(regexp_replace(coalesce(p_username, ''), '[^a-z0-9_]', '', 'g'))
  limit 1;
$$;

grant execute on function public.lookup_login_email_by_username(text) to anon, authenticated;
