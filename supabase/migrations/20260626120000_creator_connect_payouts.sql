-- Stripe Connect account linking and creator payout fulfillment helpers.

create or replace function public.set_creator_stripe_account(
  p_user_id uuid,
  p_stripe_account_id text
)
returns void
language plpgsql
security definer
set search_path to public
as $$
begin
  perform public.begin_billing_mutation();

  if nullif(trim(coalesce(p_stripe_account_id, '')), '') is null then
    raise exception 'Stripe account id required';
  end if;

  update public.users
     set creator_stripe_account_id = trim(p_stripe_account_id)
   where auth_id = p_user_id;

  if not found then
    raise exception 'User not found';
  end if;
end;
$$;

revoke all on function public.set_creator_stripe_account(uuid, text) from public;
grant execute on function public.set_creator_stripe_account(uuid, text) to service_role;

create or replace function public.get_server_creator_earnings_summary(p_server_id bigint)
returns json
language plpgsql
security definer
set search_path to public
as $$
declare
  result json;
begin
  if p_server_id is null then
    raise exception 'Server id required';
  end if;

  select json_build_object(
    'pending_tokens', coalesce(sum(net_tokens) filter (where status = 'pending'), 0),
    'available_tokens', coalesce(sum(net_tokens) filter (where status = 'available'), 0),
    'paid_tokens', coalesce(sum(net_tokens) filter (where status = 'paid'), 0),
    'total_gross_tokens', coalesce(sum(gross_tokens), 0),
    'purchase_count', count(*)
  )
    into result
  from public.creator_earning_entries
  where server_id = p_server_id
    and creator_user_id = auth.uid();

  return coalesce(
    result,
    json_build_object(
      'pending_tokens', 0,
      'available_tokens', 0,
      'paid_tokens', 0,
      'total_gross_tokens', 0,
      'purchase_count', 0
    )
  );
end;
$$;

grant execute on function public.get_server_creator_earnings_summary(bigint) to authenticated;

create or replace function public.mark_creator_payout_processing(p_payout_id bigint)
returns void
language plpgsql
security definer
set search_path to public
as $$
begin
  perform public.begin_billing_mutation();

  update public.creator_payouts
     set status = 'processing',
         updated_at = now()
   where id = p_payout_id
     and status = 'requested';

  if not found then
    raise exception 'Payout is not eligible for processing';
  end if;
end;
$$;

revoke all on function public.mark_creator_payout_processing(bigint) from public;
grant execute on function public.mark_creator_payout_processing(bigint) to service_role;

create or replace function public.complete_creator_payout(
  p_payout_id bigint,
  p_stripe_transfer_id text
)
returns void
language plpgsql
security definer
set search_path to public
as $$
begin
  perform public.begin_billing_mutation();

  update public.creator_payouts
     set status = 'paid',
         stripe_payout_id = nullif(trim(coalesce(p_stripe_transfer_id, '')), ''),
         updated_at = now(),
         metadata = metadata || jsonb_build_object('fulfilled_at', now())
   where id = p_payout_id
     and status in ('requested', 'processing');

  if not found then
    raise exception 'Payout is not eligible for completion';
  end if;
end;
$$;

revoke all on function public.complete_creator_payout(bigint, text) from public;
grant execute on function public.complete_creator_payout(bigint, text) to service_role;

create or replace function public.fail_creator_payout(
  p_payout_id bigint,
  p_reason text default null
)
returns void
language plpgsql
security definer
set search_path to public
as $$
declare
  refund_user_id uuid;
  refund_tokens integer;
begin
  perform public.begin_billing_mutation();

  update public.creator_payouts
     set status = 'failed',
         updated_at = now(),
         metadata = metadata || jsonb_build_object(
           'failure_reason', coalesce(p_reason, 'payout_failed'),
           'failed_at', now()
         )
   where id = p_payout_id
     and status in ('requested', 'processing')
  returning creator_user_id, amount_tokens
    into refund_user_id, refund_tokens;

  if not found then
    raise exception 'Payout is not eligible for failure handling';
  end if;

  update public.users
     set creator_available_tokens = creator_available_tokens + refund_tokens
   where auth_id = refund_user_id;
end;
$$;

revoke all on function public.fail_creator_payout(bigint, text) from public;
grant execute on function public.fail_creator_payout(bigint, text) to service_role;
