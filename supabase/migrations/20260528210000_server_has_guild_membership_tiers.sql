-- Lets previewers know a public server offers paid membership tiers in the sidebar.

create or replace function public.server_has_guild_membership_tiers(p_server_id bigint)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.subscription_tiers st
    where st.server_id = p_server_id
  )
  and public.user_can_view_server(p_server_id);
$$;

revoke all on function public.server_has_guild_membership_tiers(bigint) from public;
grant execute on function public.server_has_guild_membership_tiers(bigint) to authenticated;
grant execute on function public.server_has_guild_membership_tiers(bigint) to anon;
