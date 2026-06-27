alter table public.users
  add column if not exists key_credit_balance integer not null default 0,
  add column if not exists platform_stripe_customer_id text;

alter table public.servers
  add column if not exists billing_status text not null default 'free',
  add column if not exists stripe_subscription_id text,
  add column if not exists stripe_customer_id text;

alter table public.servers
  drop constraint if exists servers_billing_status_check;

alter table public.servers
  add constraint servers_billing_status_check
  check (billing_status in ('free', 'pending', 'active', 'trialing', 'past_due', 'canceled', 'unpaid'));

create table if not exists public.platform_billing_events (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.users(auth_id) on delete cascade,
  kind text not null,
  server_id bigint references public.servers(id) on delete set null,
  stripe_customer_id text,
  stripe_subscription_id text,
  stripe_checkout_session_id text,
  status text,
  quantity integer not null default 1,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists users_platform_stripe_customer_id_idx
  on public.users (platform_stripe_customer_id)
  where platform_stripe_customer_id is not null;

create index if not exists servers_stripe_subscription_id_idx
  on public.servers (stripe_subscription_id)
  where stripe_subscription_id is not null;

create index if not exists platform_billing_events_user_id_idx
  on public.platform_billing_events (user_id, created_at desc);

alter table public.platform_billing_events enable row level security;

drop policy if exists "Users can read their platform billing events" on public.platform_billing_events;
create policy "Users can read their platform billing events"
on public.platform_billing_events
for select
to authenticated
using (user_id = auth.uid());

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
  if not exists (
    select 1
    from public.servers
    where id = p_server_id
      and owner_id = p_user_id
  ) then
    raise exception 'Only the server owner can apply server billing';
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
begin
  safe_quantity := greatest(coalesce(p_quantity, 0), 0);
  if safe_quantity <= 0 then
    raise exception 'Key quantity must be greater than 0';
  end if;

  update public.users
     set key_credit_balance = key_credit_balance + safe_quantity,
         platform_stripe_customer_id = p_stripe_customer_id
   where auth_id = p_user_id;

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
    'platform_key_pack',
    p_stripe_customer_id,
    p_checkout_session_id,
    'paid',
    safe_quantity
  );
end;
$$;
