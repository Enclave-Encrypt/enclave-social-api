-- Show guild tier gem in member list when the current server has a verified paid plan.

create or replace function public.guild_plan_rank(p_plan text)
returns integer
language sql
immutable
as $$
  select case lower(trim(coalesce(p_plan, 'stone')))
    when 'diamond' then 4
    when 'business_pro' then 4
    when 'ruby' then 3
    when 'business' then 3
    when 'emerald' then 2
    when 'business_lite' then 2
    else 1
  end;
$$;

create or replace function public.get_server_verified_guild_plan(p_server_id bigint)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select lower(trim(coalesce(s.server_type, 'stone')))
  from public.servers s
  where s.id = p_server_id
    and public.is_paid_guild_plan(s.server_type)
    and coalesce(s.billing_status, '') = 'active'
    and coalesce(s.plan_token_cost, 0) > 0
    and exists (
      select 1
      from public.server_members sm
      join public.token_ledger_entries tle
        on tle.user_id = sm.user_id
       and tle.server_id = s.id
       and tle.kind = 'guild_plan'
       and tle.direction = 'debit'
      where sm.server_id = s.id
        and lower(trim(coalesce(sm.role, ''))) = 'owner'
    );
$$;

create or replace function public.pick_higher_guild_plan(p_left text, p_right text)
returns text
language sql
immutable
as $$
  select case
    when p_left is null then p_right
    when p_right is null then p_left
    when public.guild_plan_rank(p_left) >= public.guild_plan_rank(p_right) then p_left
    else p_right
  end;
$$;

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
  with current_server_plan as (
    select public.get_server_verified_guild_plan(p_server_id) as guild_plan
  )
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
  order by sm.created_at asc;
$$;

revoke all on function public.get_server_verified_guild_plan(bigint) from public;
grant execute on function public.get_server_verified_guild_plan(bigint) to authenticated;

revoke all on function public.get_server_member_list(bigint) from public;
grant execute on function public.get_server_member_list(bigint) to authenticated;
grant execute on function public.get_server_member_list(bigint) to anon;
