-- Guild tier gem: creators (servers.owner_id) and co-owners (server_members.role = 'owner').

create or replace function public.get_users_owned_guild_plans(p_user_ids uuid[])
returns table (user_id uuid, guild_plan text)
language sql
stable
security definer
set search_path = public
as $$
  with owned as (
    select
      s.owner_id as user_id,
      lower(trim(coalesce(s.server_type, 'stone'))) as guild_plan,
      case lower(trim(coalesce(s.server_type, 'stone')))
        when 'diamond' then 4
        when 'business_pro' then 4
        when 'ruby' then 3
        when 'business' then 3
        when 'emerald' then 2
        when 'business_lite' then 2
        else 1
      end as plan_rank,
      s.id as server_id
    from public.servers s
    where s.owner_id = any(coalesce(p_user_ids, array[]::uuid[]))

    union all

    select
      sm.user_id,
      lower(trim(coalesce(s.server_type, 'stone'))),
      case lower(trim(coalesce(s.server_type, 'stone')))
        when 'diamond' then 4
        when 'business_pro' then 4
        when 'ruby' then 3
        when 'business' then 3
        when 'emerald' then 2
        when 'business_lite' then 2
        else 1
      end,
      s.id
    from public.server_members sm
    join public.servers s on s.id = sm.server_id
    where sm.user_id = any(coalesce(p_user_ids, array[]::uuid[]))
      and lower(trim(coalesce(sm.role, ''))) = 'owner'
  )
  select distinct on (owned.user_id)
    owned.user_id,
    owned.guild_plan
  from owned
  order by owned.user_id, owned.plan_rank desc, owned.server_id asc;
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
  owned_guild_plan text
)
language sql
stable
security definer
set search_path = public
as $$
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
    end as role,
    (
      with owned as (
        select
          lower(trim(coalesce(s.server_type, 'stone'))) as guild_plan,
          case lower(trim(coalesce(s.server_type, 'stone')))
            when 'diamond' then 4
            when 'business_pro' then 4
            when 'ruby' then 3
            when 'business' then 3
            when 'emerald' then 2
            when 'business_lite' then 2
            else 1
          end as plan_rank,
          s.id as server_id
        from public.servers s
        where s.owner_id = u.auth_id

        union all

        select
          lower(trim(coalesce(s.server_type, 'stone'))),
          case lower(trim(coalesce(s.server_type, 'stone')))
            when 'diamond' then 4
            when 'business_pro' then 4
            when 'ruby' then 3
            when 'business' then 3
            when 'emerald' then 2
            when 'business_lite' then 2
            else 1
          end,
          s.id
        from public.server_members sm2
        join public.servers s on s.id = sm2.server_id
        where sm2.user_id = u.auth_id
          and lower(trim(coalesce(sm2.role, ''))) = 'owner'
      )
      select owned.guild_plan
      from owned
      order by owned.plan_rank desc, owned.server_id asc
      limit 1
    ) as owned_guild_plan
  from public.server_members sm
  join public.users u on u.auth_id = sm.user_id
  where sm.server_id = p_server_id
    and public.user_can_view_server(p_server_id)
  order by sm.created_at asc;
$$;

revoke all on function public.get_users_owned_guild_plans(uuid[]) from public;
grant execute on function public.get_users_owned_guild_plans(uuid[]) to authenticated;
grant execute on function public.get_users_owned_guild_plans(uuid[]) to anon;

revoke all on function public.get_server_member_list(bigint) from public;
grant execute on function public.get_server_member_list(bigint) to authenticated;
grant execute on function public.get_server_member_list(bigint) to anon;
