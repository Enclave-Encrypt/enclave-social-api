-- Batch guild-plan lookup for member list / profile (works without changing get_server_member_list).

create or replace function public.get_users_owned_guild_plans(p_user_ids uuid[])
returns table (user_id uuid, guild_plan text)
language sql
stable
security definer
set search_path = public
as $$
  select distinct on (s.owner_id)
    s.owner_id as user_id,
    lower(trim(coalesce(s.server_type, 'stone'))) as guild_plan
  from public.servers s
  where s.owner_id = any(coalesce(p_user_ids, array[]::uuid[]))
  order by
    s.owner_id,
    case lower(trim(coalesce(s.server_type, 'stone')))
      when 'diamond' then 4
      when 'business_pro' then 4
      when 'ruby' then 3
      when 'business' then 3
      when 'emerald' then 2
      when 'business_lite' then 2
      else 1
    end desc,
    s.id asc;
$$;

revoke all on function public.get_users_owned_guild_plans(uuid[]) from public;
grant execute on function public.get_users_owned_guild_plans(uuid[]) to authenticated;
grant execute on function public.get_users_owned_guild_plans(uuid[]) to anon;
