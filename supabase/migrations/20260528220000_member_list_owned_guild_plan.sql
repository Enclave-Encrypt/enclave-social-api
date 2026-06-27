-- Expose guild plan for members who own at least one server (member list badges).

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
      select lower(trim(coalesce(s.server_type, 'stone')))
      from public.servers s
      where s.owner_id = u.auth_id
      order by
        case lower(trim(coalesce(s.server_type, 'stone')))
          when 'diamond' then 4
          when 'business_pro' then 4
          when 'ruby' then 3
          when 'business' then 3
          when 'emerald' then 2
          when 'business_lite' then 2
          else 1
        end desc,
        s.id asc
      limit 1
    ) as owned_guild_plan
  from public.server_members sm
  join public.users u on u.auth_id = sm.user_id
  where sm.server_id = p_server_id
    and public.user_can_view_server(p_server_id)
  order by sm.created_at asc;
$$;

revoke all on function public.get_server_member_list(bigint) from public;
grant execute on function public.get_server_member_list(bigint) to authenticated;
grant execute on function public.get_server_member_list(bigint) to anon;
