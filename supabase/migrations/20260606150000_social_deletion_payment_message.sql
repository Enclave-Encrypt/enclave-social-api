-- Align delete_my_account blocker message with any-active-payment rule.

create or replace function public.delete_my_account()
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  current_user_id uuid := auth.uid();
  status jsonb;
  blocking_server_count integer;
  blocking_subscription_count integer;
  stripe_targets jsonb;
  storage_targets jsonb;
begin
  if current_user_id is null then
    raise exception 'Not authenticated';
  end if;

  status := public.get_my_account_deletion_status();
  blocking_server_count := coalesce(jsonb_array_length(status->'blocking_servers'), 0);
  blocking_subscription_count := coalesce(jsonb_array_length(status->'blocking_subscriptions'), 0);

  if blocking_server_count > 0 then
    raise exception 'Delete blocked. Add another owner or delete these servers first: %',
      (
        select string_agg(value->>'name', ', ')
        from jsonb_array_elements(status->'blocking_servers')
      );
  end if;

  if blocking_subscription_count > 0 then
    raise exception 'Delete blocked. Cancel active payments first: %',
      (
        select string_agg(
          coalesce(value->>'name', 'Subscription')
            || case
                 when coalesce(value->>'tier_name', '') <> '' then ' (' || (value->>'tier_name') || ')'
                 else ''
               end,
          ', '
        )
        from jsonb_array_elements(status->'blocking_subscriptions')
      );
  end if;

  storage_targets := public.collect_user_storage_cleanup_targets(current_user_id);
  stripe_targets := public.collect_user_stripe_cleanup_targets(current_user_id);
  perform public.queue_delete_account_cleanup(current_user_id, stripe_targets, storage_targets);
  perform public.cleanup_user_storage_for_account_deletion(current_user_id);

  delete from public.server_nicknames
  where user_id = current_user_id;

  delete from public.server_members
  where user_id = current_user_id;

  delete from auth.users
  where id = current_user_id;

  return jsonb_build_object(
    'deleted', true,
    'transferred_servers', 0
  );
end;
$$;

comment on function public.delete_my_account() is
  'Deletes the authenticated Social user after blocking on sole-owned servers or any active payment.';
