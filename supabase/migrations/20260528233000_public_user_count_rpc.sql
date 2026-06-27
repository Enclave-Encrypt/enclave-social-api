-- Public aggregate user count for the marketing site (enclave.talk).
-- Returns only a total; no row-level user data is exposed.

create or replace function public.get_public_user_count()
returns bigint
language sql
stable
security definer
set search_path = public
as $$
  select count(*)::bigint from public.users;
$$;

revoke all on function public.get_public_user_count() from public;
grant execute on function public.get_public_user_count() to anon, authenticated;
