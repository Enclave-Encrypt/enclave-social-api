-- Unify server ownership on server_members.role = 'owner'.

create or replace function public.is_server_owner(
  p_server_id bigint,
  p_user_id uuid default auth.uid()
)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = coalesce(p_user_id, auth.uid())
      and lower(coalesce(sm.role, '')) = 'owner'
  );
$$;

grant execute on function public.is_server_owner(bigint, uuid) to authenticated;
grant execute on function public.is_server_owner(bigint) to authenticated;

create or replace function public.spend_tokens_for_guild_plan(
  p_server_id bigint,
  p_plan_key text
)
returns integer
language plpgsql
security definer
set search_path to public
as $$
declare
  normalized_plan text;
  cost_tokens integer;
begin
  normalized_plan := lower(trim(coalesce(p_plan_key, '')));
  cost_tokens := case normalized_plan
    when 'stone' then 0
    when 'community' then 0
    when 'emerald' then 1000
    when 'business_lite' then 1000
    when 'ruby' then 2500
    when 'business' then 2500
    when 'diamond' then 5000
    when 'business_pro' then 5000
    else null
  end;

  if cost_tokens is null then
    raise exception 'Invalid guild plan';
  end if;

  if not public.is_server_owner(p_server_id) then
    raise exception 'Only guild owners can buy this plan';
  end if;

  if cost_tokens > 0 then
    perform public.spend_tokens(
      auth.uid(),
      cost_tokens,
      'guild_plan',
      p_server_id,
      null,
      jsonb_build_object('plan_key', normalized_plan)
    );
  end if;

  update public.servers
     set server_type = case normalized_plan
           when 'community' then 'stone'
           when 'business_lite' then 'emerald'
           when 'business' then 'ruby'
           when 'business_pro' then 'diamond'
           else normalized_plan
         end,
         billing_status = case when cost_tokens > 0 then 'active' else 'free' end,
         plan_token_cost = cost_tokens
   where id = p_server_id;

  return (
    select token_balance
    from public.users
    where auth_id = auth.uid()
  );
end;
$$;

grant execute on function public.spend_tokens_for_guild_plan(bigint, text) to authenticated;

create or replace function public.apply_platform_server_subscription(
  p_user_id uuid,
  p_server_id bigint,
  p_status text,
  p_stripe_customer_id text,
  p_stripe_subscription_id text
)
returns void
language plpgsql
security definer
set search_path to public
as $$
begin
  if not public.is_server_owner(p_server_id, p_user_id) then
    raise exception 'Only guild owners can apply server billing';
  end if;

  update public.servers
     set billing_status = case
         when p_status in ('active', 'trialing') then p_status
         when p_status in ('past_due', 'unpaid') then p_status
         else 'canceled'
       end,
       stripe_customer_id = p_stripe_customer_id,
       stripe_subscription_id = p_stripe_subscription_id
   where id = p_server_id;

  update public.users
     set platform_stripe_customer_id = p_stripe_customer_id
   where auth_id = p_user_id;

  insert into public.platform_billing_events (
    user_id,
    kind,
    server_id,
    stripe_customer_id,
    stripe_subscription_id,
    status
  )
  values (
    p_user_id,
    'platform_server',
    p_server_id,
    p_stripe_customer_id,
    p_stripe_subscription_id,
    p_status
  );
end;
$$;

create or replace function public.get_my_servers()
returns setof public.servers
language sql
stable
set search_path to public
as $$
  select distinct s.*
  from public.servers s
  join public.server_members sm
    on sm.server_id = s.id
   and sm.user_id = auth.uid()
  where auth.uid() is not null
  order by s.created_at asc;
$$;

create or replace function public.user_can_view_server(p_server_id bigint)
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
      and (
        coalesce(s.visibility, 'public') = 'public'
        or (
          auth.uid() is not null
          and exists (
            select 1
            from public.server_members sm
            where sm.server_id = s.id
              and sm.user_id = auth.uid()
          )
        )
      )
  );
$$;

drop function if exists public.get_server_settings_context(bigint);

create or replace function public.get_server_settings_context(p_server_id bigint)
returns table (
  id bigint,
  display_name text,
  description text,
  category text,
  visibility text,
  rules text,
  welcome_message text,
  banner_url text,
  icon_url text,
  invite_code text,
  show_posts_in_global_feed boolean,
  monetization_enabled boolean,
  theme_enabled boolean,
  theme_id text,
  appearance_preferences jsonb,
  use_server_theme boolean,
  forward_encryption boolean,
  require_approval boolean,
  my_role text,
  nickname text
)
language sql
stable
set search_path to public
as $$
  select
    s.id,
    s.display_name,
    s.description,
    s.category,
    s.visibility,
    s.rules,
    s.welcome_message,
    s.banner_url,
    s.icon_url,
    s.invite_code,
    coalesce(s.show_posts_in_global_feed, true),
    coalesce(s.monetization_enabled, false),
    coalesce(s.theme_enabled, false),
    coalesce(s.theme_id, 'default'),
    coalesce(s.appearance_preferences, '{}'::jsonb),
    coalesce(stp.use_server_theme, true),
    coalesce(s.forward_encryption, false),
    coalesce(s.require_approval, false),
    coalesce(
      case
        when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
        else lower(trim(coalesce(sm.role, 'member')))
      end,
      'member'
    ),
    sn.nickname
  from public.servers s
  left join public.server_members sm
    on sm.server_id = s.id
   and sm.user_id = auth.uid()
  left join public.server_nicknames sn
    on sn.server_id = s.id
   and sn.user_id = auth.uid()
  left join public.server_theme_preferences stp
    on stp.server_id = s.id
   and stp.user_id = auth.uid()
  where s.id = p_server_id
  limit 1;
$$;

create or replace function public.user_can_manage_guild_tiers(
  p_server_id bigint,
  p_user_id uuid default auth.uid()
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.servers s
    left join public.server_members sm
      on sm.server_id = s.id
      and sm.user_id = p_user_id
    left join public.server_roles primary_role
      on primary_role.id = sm.role_id
    where s.id = p_server_id
      and p_user_id is not null
      and (
        lower(coalesce(sm.role, '')) in ('owner', 'admin')
        or coalesce((primary_role.permissions ->> 'manage_guild_tiers')::boolean, false)
        or exists (
          select 1
          from public.server_member_roles smr
          join public.server_roles sr
            on sr.id = smr.role_id
          where smr.server_id = p_server_id
            and smr.user_id = p_user_id
            and coalesce((sr.permissions ->> 'manage_guild_tiers')::boolean, false)
        )
      )
  );
$$;

grant execute on function public.user_can_manage_guild_tiers(bigint, uuid) to authenticated;

create or replace function public.user_has_server_mod_power(
  p_server_id bigint,
  p_user_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.servers s
    left join public.server_members sm
      on sm.server_id = s.id
      and sm.user_id = p_user_id
    left join public.server_roles primary_role
      on primary_role.id = sm.role_id
    where s.id = p_server_id
      and p_user_id is not null
      and (
        lower(coalesce(sm.role, '')) in ('owner', 'admin', 'mod', 'moderator')
        or coalesce((primary_role.permissions ->> 'manage_server')::boolean, false)
        or coalesce((primary_role.permissions ->> 'manage_roles')::boolean, false)
        or coalesce((primary_role.permissions ->> 'manage_guild_tiers')::boolean, false)
        or coalesce((primary_role.permissions ->> 'manage_channels')::boolean, false)
        or coalesce((primary_role.permissions ->> 'ban_members')::boolean, false)
        or coalesce((primary_role.permissions ->> 'kick_members')::boolean, false)
        or coalesce((primary_role.permissions ->> 'manage_messages')::boolean, false)
        or exists (
          select 1
          from public.server_member_roles smr
          join public.server_roles sr
            on sr.id = smr.role_id
          where smr.server_id = p_server_id
            and smr.user_id = p_user_id
            and (
              coalesce((sr.permissions ->> 'manage_server')::boolean, false)
              or coalesce((sr.permissions ->> 'manage_roles')::boolean, false)
              or coalesce((sr.permissions ->> 'manage_guild_tiers')::boolean, false)
              or coalesce((sr.permissions ->> 'manage_channels')::boolean, false)
              or coalesce((sr.permissions ->> 'ban_members')::boolean, false)
              or coalesce((sr.permissions ->> 'kick_members')::boolean, false)
              or coalesce((sr.permissions ->> 'manage_messages')::boolean, false)
            )
        )
      )
  );
$$;

create or replace function public.user_can_access_channel(
  p_channel_id bigint,
  p_user_id uuid
)
returns boolean
language sql
security definer
set search_path = public
as $$
  with channel_row as (
    select
      c.id,
      c.server_id,
      c.tier_id,
      st.role_id,
      coalesce(st.price, 0) as tier_price,
      coalesce(s.visibility, 'public') as visibility
    from public.channels c
    join public.servers s
      on s.id = c.server_id
    left join public.subscription_tiers st
      on st.id = c.tier_id
    where c.id = p_channel_id
    limit 1
  ),
  member_row as (
    select sm.server_id, sm.role, sm.role_id
    from public.server_members sm
    join channel_row c
      on c.server_id = sm.server_id
    where sm.user_id = p_user_id
    limit 1
  )
  select exists (
    select 1
    from channel_row c
    left join member_row sm
      on sm.server_id = c.server_id
    where
      p_user_id is not null
      and (
        sm.server_id is not null
        or c.visibility = 'public'
      )
      and (
        c.tier_id is null
        or c.tier_price <= 0
        or public.user_has_server_mod_power(c.server_id, p_user_id)
        or (c.role_id is not null and public.user_has_server_role(c.server_id, p_user_id, c.role_id))
        or exists (
          select 1
          from public.server_tier_subscriptions sts
          where sts.server_id = c.server_id
            and sts.tier_id = c.tier_id
            and sts.user_id = p_user_id
            and sts.status in ('active', 'trialing')
        )
      )
  );
$$;

create or replace function public.leave_server(p_server_id bigint)
returns void
language plpgsql
security definer
set search_path to public
as $$
declare
  current_user_id uuid := auth.uid();
  current_member public.server_members%rowtype;
  other_owner_count bigint;
begin
  if current_user_id is null then
    raise exception 'Authentication required';
  end if;

  select *
  into current_member
  from public.server_members
  where server_id = p_server_id
    and user_id = current_user_id;

  if not found then
    raise exception 'You are not a member of this server';
  end if;

  if lower(coalesce(current_member.role, '')) = 'owner' then
    select count(*)
    into other_owner_count
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id <> current_user_id
      and lower(coalesce(sm.role, '')) = 'owner';

    if other_owner_count = 0 then
      raise exception 'You cannot leave this server because you are the only owner. Add another owner first.';
    end if;
  end if;

  delete from public.server_nicknames
  where server_id = p_server_id
    and user_id = current_user_id;

  delete from public.server_members
  where server_id = p_server_id
    and user_id = current_user_id;
end;
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
