-- Account deletion must not DELETE from storage.objects (Supabase blocks direct DML).
-- Collect paths in Postgres, delete blobs via delete-account-cleanup Edge Function + Storage API.

create or replace function public.collect_user_storage_cleanup_targets(p_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  attachment_objects jsonb := '[]'::jsonb;
begin
  if p_user_id is null then
    return jsonb_build_object('objects', '[]'::jsonb);
  end if;

  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'bucket', ma.storage_bucket,
        'path', ma.storage_path
      )
      order by ma.created_at
    ),
    '[]'::jsonb
  )
  into attachment_objects
  from public.message_attachments ma
  where ma.owner_id = p_user_id;

  return jsonb_build_object('objects', attachment_objects);
end;
$$;

create or replace function public.cleanup_user_storage_for_account_deletion(p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_user_id is null then
    return;
  end if;

  -- Metadata only; blob removal is handled by the Storage API in delete-account-cleanup.
  delete from public.message_attachments
  where owner_id = p_user_id;
end;
$$;

create or replace function public.queue_delete_account_cleanup(
  p_user_id uuid,
  p_stripe_targets jsonb,
  p_storage_targets jsonb
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_request_id bigint;
  v_secret text;
  v_url text := 'https://kltykhkcvdwhfjgvevbt.supabase.co/functions/v1/delete-account-cleanup';
begin
  begin
    select decrypted_secret
    into v_secret
    from vault.decrypted_secrets
    where name = 'account_deletion_secret'
    limit 1;
  exception
    when others then
      v_secret := null;
  end;

  if v_secret is null or length(trim(v_secret)) = 0 then
    raise warning 'Account cleanup skipped: vault secret account_deletion_secret is not configured';
    return;
  end if;

  select net.http_post(
    url := v_url,
    headers := jsonb_build_object(
      'Content-Type', 'application/json',
      'x-account-deletion-secret', v_secret
    ),
    body := jsonb_build_object(
      'user_id', p_user_id,
      'stripe_customer_ids', coalesce(p_stripe_targets->'stripe_customer_ids', '[]'::jsonb),
      'stripe_subscription_ids', coalesce(p_stripe_targets->'stripe_subscription_ids', '[]'::jsonb),
      'storage_objects', coalesce(p_storage_targets->'objects', '[]'::jsonb)
    )
  )
  into v_request_id;
exception
  when undefined_function then
    raise warning 'Account cleanup skipped: pg_net extension is unavailable';
  when others then
    raise warning 'Account cleanup queue failed: %', sqlerrm;
end;
$$;

-- Backward-compatible name used by earlier migrations.
create or replace function public.queue_delete_account_stripe_cleanup(
  p_user_id uuid,
  p_stripe_targets jsonb
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  perform public.queue_delete_account_cleanup(
    p_user_id,
    p_stripe_targets,
    jsonb_build_object('objects', '[]'::jsonb)
  );
end;
$$;

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
    raise exception 'Delete blocked. Cancel active recurring payments first: %',
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

revoke all on function public.collect_user_storage_cleanup_targets(uuid) from public;
revoke all on function public.cleanup_user_storage_for_account_deletion(uuid) from public;
revoke all on function public.queue_delete_account_cleanup(uuid, jsonb, jsonb) from public;
revoke all on function public.queue_delete_account_stripe_cleanup(uuid, jsonb) from public;

grant execute on function public.get_my_account_deletion_status() to authenticated;
grant execute on function public.delete_my_account() to authenticated;
