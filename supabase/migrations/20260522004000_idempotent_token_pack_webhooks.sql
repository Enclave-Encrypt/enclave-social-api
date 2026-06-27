delete from public.platform_billing_events p
using public.platform_billing_events keep
where p.stripe_checkout_session_id is not null
  and keep.stripe_checkout_session_id = p.stripe_checkout_session_id
  and keep.id < p.id;

create unique index if not exists platform_billing_events_checkout_session_unique
  on public.platform_billing_events (stripe_checkout_session_id)
  where stripe_checkout_session_id is not null;

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

revoke execute on function public.apply_platform_key_purchase(uuid, integer, text, text) from anon, authenticated;
grant execute on function public.apply_platform_key_purchase(uuid, integer, text, text) to service_role;
