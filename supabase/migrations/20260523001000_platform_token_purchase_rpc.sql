create or replace function public.apply_platform_token_purchase(
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
begin
  perform public.apply_platform_key_purchase(
    p_user_id,
    p_quantity,
    p_stripe_customer_id,
    p_checkout_session_id
  );
end;
$$;

revoke execute on function public.apply_platform_token_purchase(uuid, integer, text, text) from anon, authenticated;
grant execute on function public.apply_platform_token_purchase(uuid, integer, text, text) to service_role;
