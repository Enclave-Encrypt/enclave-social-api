-- Phase 1c: Remove over-permissive SELECT on public.users.
-- Cross-user reads must use public.public_user_profiles or search_public_profiles().
-- Private self reads must use get_my_account().

drop policy if exists "Users can read all profiles" on public.users;
drop policy if exists "Users can read profiles of people in shared servers" on public.users;
