-- Member list: flag users with paid/free custom roles for sidebar grouping.

create or replace function public.member_has_custom_server_role(
  p_server_id bigint,
  p_user_id uuid,
  p_primary_role text
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.server_member_roles smr
    join public.server_roles sr
      on sr.id = smr.role_id
    where smr.server_id = p_server_id
      and smr.user_id = p_user_id
      and (
        smr.source = 'subscription'
        or lower(trim(coalesce(sr.name, ''))) not in (
          'owner',
          'admin',
          'mod',
          'moderator',
          'member',
          lower(trim(coalesce(p_primary_role, 'member')))
        )
      )
  );
$$;

drop function if exists public.get_server_member_list(bigint);

create or replace function public.get_server_member_list(p_server_id bigint)
returns table (
  auth_id uuid,
  username text,
  display_name text,
  avatar_url text,
  presence text,
  tier text,
  status_message text,
  last_seen timestamptz,
  role text,
  owned_guild_plan text,
  has_custom_role boolean
)
language sql
stable
security definer
set search_path = public
as $$
  with current_server_plan as (
    select public.get_server_verified_guild_plan(p_server_id) as guild_plan
  ),
  members as (
    select
      u.auth_id,
      u.username,
      u.display_name,
      u.avatar_url,
      u.presence,
      u.tier,
      u.status_message,
      u.last_seen,
      case
        when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
        else lower(trim(coalesce(sm.role, 'member')))
      end as normalized_role,
      public.pick_higher_guild_plan(
        (
          select ggp.guild_plan
          from public.get_users_owned_guild_plans(array[u.auth_id]) ggp
          where ggp.user_id = u.auth_id
          limit 1
        ),
        case
          when lower(trim(coalesce(sm.role, ''))) = 'owner'
            then (select guild_plan from current_server_plan)
          else null
        end
      ) as owned_guild_plan
    from public.server_members sm
    join public.users u on u.auth_id = sm.user_id
    where sm.server_id = p_server_id
      and public.user_can_view_server(p_server_id)
  )
  select
    m.auth_id,
    m.username,
    m.display_name,
    m.avatar_url,
    m.presence,
    m.tier,
    m.status_message,
    m.last_seen,
    m.normalized_role as role,
    m.owned_guild_plan,
    public.member_has_custom_server_role(p_server_id, m.auth_id, m.normalized_role) as has_custom_role
  from members m;
$$;

revoke all on function public.member_has_custom_server_role(bigint, uuid, text) from public;
grant execute on function public.member_has_custom_server_role(bigint, uuid, text) to authenticated;

revoke all on function public.get_server_member_list(bigint) from public;
grant execute on function public.get_server_member_list(bigint) to authenticated;
grant execute on function public.get_server_member_list(bigint) to anon;
