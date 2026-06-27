-- Block client-side writes to billing columns; only security-definer RPCs may mutate them.

create or replace function public.begin_billing_mutation()
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  perform set_config('app.billing_mutation', 'allowed', true);
end;
$$;

create or replace function public.billing_mutation_allowed()
returns boolean
language sql
stable
as $$
  select coalesce(current_setting('app.billing_mutation', true), '') = 'allowed';
$$;

create or replace function public.is_paid_guild_plan(p_plan text)
returns boolean
language sql
immutable
as $$
  select lower(trim(coalesce(p_plan, ''))) in (
    'emerald', 'business_lite', 'ruby', 'business', 'diamond', 'business_pro'
  );
$$;

create or replace function public.guard_users_billing_columns()
returns trigger
language plpgsql
as $$
begin
  if public.billing_mutation_allowed() then
    return new;
  end if;

  if new.tier is distinct from old.tier
     or new.token_balance is distinct from old.token_balance
     or new.key_credit_balance is distinct from old.key_credit_balance
     or new.platform_stripe_customer_id is distinct from old.platform_stripe_customer_id
     or new.creator_pending_tokens is distinct from old.creator_pending_tokens
     or new.creator_available_tokens is distinct from old.creator_available_tokens
     or new.creator_stripe_account_id is distinct from old.creator_stripe_account_id then
    raise exception 'Billing fields on users cannot be updated directly';
  end if;

  return new;
end;
$$;

create or replace function public.guard_users_billing_columns_insert()
returns trigger
language plpgsql
as $$
begin
  if public.billing_mutation_allowed() then
    return new;
  end if;

  if coalesce(new.tier, 'bronze') <> 'bronze'
     or coalesce(new.token_balance, 0) <> 0
     or coalesce(new.key_credit_balance, 0) <> 0
     or new.platform_stripe_customer_id is not null
     or coalesce(new.creator_pending_tokens, 0) <> 0
     or coalesce(new.creator_available_tokens, 0) <> 0
     or new.creator_stripe_account_id is not null then
    raise exception 'Billing fields on users cannot be set directly';
  end if;

  return new;
end;
$$;

drop trigger if exists guard_users_billing_columns on public.users;
create trigger guard_users_billing_columns
before update on public.users
for each row
execute function public.guard_users_billing_columns();

drop trigger if exists guard_users_billing_columns_insert on public.users;
create trigger guard_users_billing_columns_insert
before insert on public.users
for each row
execute function public.guard_users_billing_columns_insert();

create or replace function public.guard_servers_billing_columns()
returns trigger
language plpgsql
as $$
begin
  if public.billing_mutation_allowed() then
    return new;
  end if;

  if tg_op = 'INSERT' then
    if public.is_paid_guild_plan(new.server_type) then
      new.server_type := 'stone';
      new.billing_status := 'free';
      new.plan_token_cost := 0;
    end if;
    return new;
  end if;

  if new.server_type is distinct from old.server_type
     or new.billing_status is distinct from old.billing_status
     or new.plan_token_cost is distinct from old.plan_token_cost
     or new.stripe_customer_id is distinct from old.stripe_customer_id
     or new.stripe_subscription_id is distinct from old.stripe_subscription_id then
    raise exception 'Guild billing fields on servers cannot be updated directly';
  end if;

  return new;
end;
$$;

drop trigger if exists guard_servers_billing_columns on public.servers;
create trigger guard_servers_billing_columns
before insert or update on public.servers
for each row
execute function public.guard_servers_billing_columns();

-- Ensure billing RPCs can mutate protected columns.
create or replace function public.spend_tokens(
  p_user_id uuid,
  p_amount_tokens integer,
  p_kind text,
  p_server_id bigint default null,
  p_tier_id bigint default null,
  p_metadata jsonb default '{}'::jsonb
)
returns integer
language plpgsql
security definer
set search_path to public
as $$
declare
  safe_amount integer;
  next_balance integer;
begin
  perform public.begin_billing_mutation();

  safe_amount := greatest(coalesce(p_amount_tokens, 0), 0);
  if safe_amount <= 0 then
    raise exception 'Token amount must be greater than 0';
  end if;

  if auth.uid() is distinct from p_user_id then
    raise exception 'Cannot spend tokens for another user';
  end if;

  update public.users
     set token_balance = token_balance - safe_amount,
         key_credit_balance = greatest(coalesce(key_credit_balance, token_balance) - safe_amount, 0)
   where auth_id = p_user_id
     and token_balance >= safe_amount
   returning token_balance into next_balance;

  if next_balance is null then
    raise exception 'Not enough tokens';
  end if;

  insert into public.token_ledger_entries (
    user_id,
    direction,
    amount_tokens,
    balance_after_tokens,
    kind,
    server_id,
    tier_id,
    metadata
  )
  values (
    p_user_id,
    'debit',
    safe_amount,
    next_balance,
    p_kind,
    p_server_id,
    p_tier_id,
    coalesce(p_metadata, '{}'::jsonb)
  );

  return next_balance;
end;
$$;

create or replace function public.apply_platform_key_purchase(
  p_user_id uuid,
  p_quantity integer,
  p_stripe_customer_id text,
  p_checkout_session_id text
)
returns void
language plpgsql
security definer
set search_path to public
as $$
declare
  safe_quantity integer;
  next_balance integer;
begin
  perform public.begin_billing_mutation();

  safe_quantity := greatest(coalesce(p_quantity, 0), 0);
  if safe_quantity <= 0 then
    raise exception 'Token quantity must be greater than 0';
  end if;

  if exists (
    select 1
    from public.platform_billing_events
    where stripe_checkout_session_id = p_checkout_session_id
      and kind in ('platform_token_pack', 'platform_key_pack')
  ) then
    return;
  end if;

  update public.users
     set token_balance = token_balance + safe_quantity,
         key_credit_balance = coalesce(key_credit_balance, 0) + safe_quantity,
         platform_stripe_customer_id = p_stripe_customer_id
   where auth_id = p_user_id
   returning token_balance into next_balance;

  if next_balance is null then
    raise exception 'User not found for token purchase';
  end if;

  insert into public.token_ledger_entries (
    user_id,
    direction,
    amount_tokens,
    balance_after_tokens,
    kind,
    stripe_checkout_session_id
  )
  values (
    p_user_id,
    'credit',
    safe_quantity,
    next_balance,
    'token_pack',
    p_checkout_session_id
  );

  insert into public.platform_billing_events (
    user_id,
    kind,
    stripe_customer_id,
    stripe_checkout_session_id,
    status,
    quantity
  )
  values (
    p_user_id,
    'platform_token_pack',
    p_stripe_customer_id,
    p_checkout_session_id,
    'paid',
    safe_quantity
  )
  on conflict (stripe_checkout_session_id) where stripe_checkout_session_id is not null do nothing;
end;
$$;

create or replace function public.spend_tokens_for_account_key(p_tier text)
returns integer
language plpgsql
security definer
set search_path to public
as $$
declare
  normalized_tier text;
  cost_tokens integer;
begin
  perform public.begin_billing_mutation();

  normalized_tier := lower(trim(coalesce(p_tier, '')));
  cost_tokens := case normalized_tier
    when 'bronze' then 0
    when 'silver' then 100
    when 'gold' then 500
    when 'platinum' then 1000
    else null
  end;

  if cost_tokens is null then
    raise exception 'Invalid account key';
  end if;

  if cost_tokens > 0 then
    perform public.spend_tokens(
      auth.uid(),
      cost_tokens,
      'account_key',
      null,
      null,
      jsonb_build_object('account_key', normalized_tier)
    );
  end if;

  update public.users
     set tier = normalized_tier
   where auth_id = auth.uid();

  return (
    select token_balance
    from public.users
    where auth_id = auth.uid()
  );
end;
$$;

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
  perform public.begin_billing_mutation();

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

-- Only show guild gems when a paid plan was purchased through the ledger.
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
      and coalesce(s.billing_status, '') = 'active'
      and coalesce(s.plan_token_cost, 0) > 0
      and exists (
        select 1
        from public.token_ledger_entries tle
        where tle.user_id = sm.user_id
          and tle.server_id = s.id
          and tle.kind = 'guild_plan'
          and tle.direction = 'debit'
      )
  )
  select distinct on (owned.user_id)
    owned.user_id,
    owned.guild_plan
  from owned
  order by owned.user_id, owned.plan_rank desc, owned.server_id asc;
$$;

-- Revoke unpaid / unledgered premium that was granted via direct writes or create-server bug.
select set_config('app.billing_mutation', 'allowed', true);

update public.servers s
   set server_type = 'stone',
       billing_status = 'free',
       plan_token_cost = 0
 where public.is_paid_guild_plan(s.server_type)
   and not exists (
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

update public.users u
   set tier = 'bronze'
 where lower(coalesce(u.tier, 'bronze')) <> 'bronze'
   and not exists (
     select 1
     from public.token_ledger_entries tle
     where tle.user_id = u.auth_id
       and tle.kind = 'account_key'
       and tle.direction = 'debit'
       and lower(coalesce(tle.metadata->>'account_key', '')) = lower(u.tier)
   );

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
      select ggp.guild_plan
      from public.get_users_owned_guild_plans(array[u.auth_id]) ggp
      where ggp.user_id = u.auth_id
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

revoke all on function public.begin_billing_mutation() from public;
grant execute on function public.begin_billing_mutation() to service_role;
