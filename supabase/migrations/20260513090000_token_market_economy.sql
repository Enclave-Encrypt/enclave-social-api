alter table public.users
  add column if not exists token_balance integer not null default 0,
  add column if not exists creator_pending_tokens integer not null default 0,
  add column if not exists creator_available_tokens integer not null default 0,
  add column if not exists creator_stripe_account_id text;

alter table public.users
  alter column tier set default 'bronze';

alter table public.users
  drop constraint if exists users_tier_check;

update public.users
   set tier = 'bronze'
 where tier = 'free';

alter table public.users
  add constraint users_tier_check
  check (tier in ('bronze', 'silver', 'gold', 'platinum'));

update public.users
   set token_balance = greatest(token_balance, coalesce(key_credit_balance, 0))
 where coalesce(key_credit_balance, 0) > 0;

alter table public.subscription_tiers
  add column if not exists price_tokens integer;

update public.subscription_tiers
   set price_tokens = greatest(round(coalesce(price, 0) * 100)::integer, 0)
 where price_tokens is null;

alter table public.servers
  add column if not exists plan_token_cost integer;

update public.servers
   set plan_token_cost = case server_type
     when 'community' then 0
     when 'stone' then 0
     when 'business_lite' then 1000
     when 'emerald' then 1000
     when 'business' then 2500
     when 'ruby' then 2500
     when 'business_pro' then 5000
     when 'diamond' then 5000
     else 0
   end
 where plan_token_cost is null;

update public.servers
   set server_type = case server_type
     when 'community' then 'stone'
     when 'business_lite' then 'emerald'
     when 'business' then 'ruby'
     when 'business_pro' then 'diamond'
     else server_type
   end;

alter table public.servers
  alter column member_limit drop default;

update public.servers
   set member_limit = null;

create table if not exists public.token_ledger_entries (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.users(auth_id) on delete cascade,
  direction text not null,
  amount_tokens integer not null,
  balance_after_tokens integer,
  kind text not null,
  related_user_id uuid references public.users(auth_id) on delete set null,
  server_id bigint references public.servers(id) on delete set null,
  tier_id bigint references public.subscription_tiers(id) on delete set null,
  stripe_checkout_session_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint token_ledger_direction_check check (direction in ('credit', 'debit')),
  constraint token_ledger_amount_positive_check check (amount_tokens > 0)
);

create table if not exists public.creator_earning_entries (
  id bigint generated always as identity primary key,
  creator_user_id uuid not null references public.users(auth_id) on delete cascade,
  buyer_user_id uuid references public.users(auth_id) on delete set null,
  server_id bigint references public.servers(id) on delete set null,
  tier_id bigint references public.subscription_tiers(id) on delete set null,
  gross_tokens integer not null,
  platform_fee_tokens integer not null,
  net_tokens integer not null,
  net_usd_cents integer not null,
  status text not null default 'pending',
  available_at timestamptz not null default now() + interval '14 days',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint creator_earning_tokens_check check (
    gross_tokens > 0
    and platform_fee_tokens >= 0
    and net_tokens >= 0
    and gross_tokens = platform_fee_tokens + net_tokens
  ),
  constraint creator_earning_status_check check (status in ('pending', 'available', 'paid', 'reversed'))
);

create table if not exists public.creator_payouts (
  id bigint generated always as identity primary key,
  creator_user_id uuid not null references public.users(auth_id) on delete cascade,
  amount_tokens integer not null,
  amount_usd_cents integer not null,
  status text not null default 'requested',
  stripe_account_id text,
  stripe_payout_id text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint creator_payout_amount_check check (amount_tokens > 0 and amount_usd_cents > 0),
  constraint creator_payout_status_check check (status in ('requested', 'processing', 'paid', 'failed', 'canceled'))
);

create index if not exists token_ledger_entries_user_created_idx
  on public.token_ledger_entries (user_id, created_at desc);

create index if not exists creator_earning_entries_creator_created_idx
  on public.creator_earning_entries (creator_user_id, created_at desc);

create index if not exists creator_payouts_creator_created_idx
  on public.creator_payouts (creator_user_id, created_at desc);

alter table public.token_ledger_entries enable row level security;
alter table public.creator_earning_entries enable row level security;
alter table public.creator_payouts enable row level security;

drop policy if exists "Users can read their token ledger" on public.token_ledger_entries;
create policy "Users can read their token ledger"
on public.token_ledger_entries
for select
to authenticated
using (user_id = auth.uid());

drop policy if exists "Creators can read their earnings" on public.creator_earning_entries;
create policy "Creators can read their earnings"
on public.creator_earning_entries
for select
to authenticated
using (creator_user_id = auth.uid() or buyer_user_id = auth.uid());

drop policy if exists "Creators can read their payouts" on public.creator_payouts;
create policy "Creators can read their payouts"
on public.creator_payouts
for select
to authenticated
using (creator_user_id = auth.uid());

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
  safe_quantity := greatest(coalesce(p_quantity, 0), 0);
  if safe_quantity <= 0 then
    raise exception 'Token quantity must be greater than 0';
  end if;

  update public.users
     set token_balance = token_balance + safe_quantity,
         key_credit_balance = coalesce(key_credit_balance, 0) + safe_quantity,
         platform_stripe_customer_id = p_stripe_customer_id
   where auth_id = p_user_id
   returning token_balance into next_balance;

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
  );
end;
$$;

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

revoke execute on function public.spend_tokens(uuid, integer, text, bigint, bigint, jsonb) from anon, authenticated;

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

grant execute on function public.spend_tokens_for_account_key(text) to authenticated;

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

  if not exists (
    select 1
    from public.servers
    where id = p_server_id
      and owner_id = auth.uid()
  ) then
    raise exception 'Only the guild owner can buy this plan';
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

create or replace function public.spend_tokens_for_guild_membership(p_tier_id bigint)
returns integer
language plpgsql
security definer
set search_path to public
as $$
declare
  tier_row record;
  guild_owner_id uuid;
  cost_tokens integer;
  platform_fee_tokens integer;
  creator_net_tokens integer;
begin
  select st.id, st.server_id, st.name, st.price_tokens, st.role_id, s.owner_id
    into tier_row
  from public.subscription_tiers st
  join public.servers s
    on s.id = st.server_id
  where st.id = p_tier_id;

  if tier_row.id is null or tier_row.role_id is null then
    raise exception 'Guild membership is not available';
  end if;

  guild_owner_id := tier_row.owner_id;
  cost_tokens := greatest(coalesce(tier_row.price_tokens, 0), 0);
  if cost_tokens <= 0 then
    raise exception 'Guild membership price is invalid';
  end if;

  platform_fee_tokens := ceil(cost_tokens * 0.10)::integer;
  creator_net_tokens := cost_tokens - platform_fee_tokens;

  perform public.spend_tokens(
    auth.uid(),
    cost_tokens,
    'guild_membership',
    tier_row.server_id,
    tier_row.id,
    jsonb_build_object(
      'membership_name', tier_row.name,
      'platform_fee_tokens', platform_fee_tokens,
      'creator_net_tokens', creator_net_tokens
    )
  );

  update public.users
     set creator_pending_tokens = creator_pending_tokens + creator_net_tokens
   where auth_id = guild_owner_id;

  insert into public.creator_earning_entries (
    creator_user_id,
    buyer_user_id,
    server_id,
    tier_id,
    gross_tokens,
    platform_fee_tokens,
    net_tokens,
    net_usd_cents,
    status
  )
  values (
    guild_owner_id,
    auth.uid(),
    tier_row.server_id,
    tier_row.id,
    cost_tokens,
    platform_fee_tokens,
    creator_net_tokens,
    creator_net_tokens,
    'pending'
  );

  perform public.grant_server_tier_role(
    tier_row.server_id,
    tier_row.id,
    auth.uid(),
    'active',
    null,
    null,
    now() + interval '1 month'
  );

  return (
    select token_balance
    from public.users
    where auth_id = auth.uid()
  );
end;
$$;

grant execute on function public.spend_tokens_for_guild_membership(bigint) to authenticated;

revoke execute on function public.apply_platform_key_purchase(uuid, integer, text, text) from anon, authenticated;
grant execute on function public.apply_platform_key_purchase(uuid, integer, text, text) to service_role;

create or replace function public.release_available_creator_earnings()
returns integer
language plpgsql
security definer
set search_path to public
as $$
declare
  released_total integer := 0;
begin
  with due as (
    update public.creator_earning_entries
       set status = 'available'
     where status = 'pending'
       and available_at <= now()
     returning creator_user_id, net_tokens
  ),
  totals as (
    select creator_user_id, sum(net_tokens)::integer as amount_tokens
    from due
    group by creator_user_id
  ),
  updated_users as (
    update public.users u
       set creator_pending_tokens = greatest(u.creator_pending_tokens - t.amount_tokens, 0),
           creator_available_tokens = u.creator_available_tokens + t.amount_tokens
      from totals t
     where u.auth_id = t.creator_user_id
     returning t.amount_tokens
  )
  select coalesce(sum(amount_tokens), 0)::integer
    into released_total
  from updated_users;

  return released_total;
end;
$$;

create or replace function public.request_creator_payout(p_amount_tokens integer)
returns bigint
language plpgsql
security definer
set search_path to public
as $$
declare
  safe_amount integer;
  stripe_account text;
  payout_id bigint;
begin
  perform public.release_available_creator_earnings();

  safe_amount := greatest(coalesce(p_amount_tokens, 0), 0);
  if safe_amount <= 0 then
    raise exception 'Payout amount must be greater than 0 tokens';
  end if;

  select creator_stripe_account_id
    into stripe_account
  from public.users
  where auth_id = auth.uid();

  if nullif(trim(coalesce(stripe_account, '')), '') is null then
    raise exception 'Connect a payout account before cashing out';
  end if;

  update public.users
     set creator_available_tokens = creator_available_tokens - safe_amount
   where auth_id = auth.uid()
     and creator_available_tokens >= safe_amount;

  if not found then
    raise exception 'Not enough available creator earnings';
  end if;

  insert into public.creator_payouts (
    creator_user_id,
    amount_tokens,
    amount_usd_cents,
    stripe_account_id,
    status
  )
  values (
    auth.uid(),
    safe_amount,
    safe_amount,
    stripe_account,
    'requested'
  )
  returning id into payout_id;

  return payout_id;
end;
$$;

grant execute on function public.release_available_creator_earnings() to authenticated;
grant execute on function public.request_creator_payout(integer) to authenticated;
