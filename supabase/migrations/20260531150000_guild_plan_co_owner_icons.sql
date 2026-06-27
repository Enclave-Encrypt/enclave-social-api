-- Co-owners inherit the verified guild plan icon when any owner paid for the server.

create or replace function public.server_has_verified_guild_plan(p_server_id bigint)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.servers s
    where s.id = p_server_id
      and public.is_paid_guild_plan(s.server_type)
      and coalesce(s.billing_status, '') = 'active'
      and coalesce(s.plan_token_cost, 0) > 0
      and exists (
        select 1
        from public.server_members paying_owner
        join public.token_ledger_entries tle
          on tle.user_id = paying_owner.user_id
         and tle.server_id = s.id
         and tle.kind = 'guild_plan'
         and tle.direction = 'debit'
        where paying_owner.server_id = s.id
          and lower(trim(coalesce(paying_owner.role, ''))) = 'owner'
      )
  );
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
    and public.server_has_verified_guild_plan(p_server_id);
$$;

create or replace function public.get_users_owned_guild_plans(p_user_ids uuid[])
returns table (user_id uuid, guild_plan text)
language sql
stable
security definer
set search_path = public
as $$
  with owned as (
    select
      sm.user_id,
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
    from public.server_members sm
    join public.servers s on s.id = sm.server_id
    where sm.user_id = any(coalesce(p_user_ids, array[]::uuid[]))
      and lower(trim(coalesce(sm.role, ''))) = 'owner'
      and public.server_has_verified_guild_plan(s.id)
  )
  select distinct on (owned.user_id)
    owned.user_id,
    owned.guild_plan
  from owned
  order by owned.user_id, owned.plan_rank desc, owned.server_id asc;
$$;

revoke all on function public.server_has_verified_guild_plan(bigint) from public;
grant execute on function public.server_has_verified_guild_plan(bigint) to authenticated;

revoke all on function public.get_server_verified_guild_plan(bigint) from public;
grant execute on function public.get_server_verified_guild_plan(bigint) to authenticated;

revoke all on function public.get_users_owned_guild_plans(uuid[]) from public;
grant execute on function public.get_users_owned_guild_plans(uuid[]) to authenticated;
grant execute on function public.get_users_owned_guild_plans(uuid[]) to anon;
