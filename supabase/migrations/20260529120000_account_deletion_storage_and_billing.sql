-- Account deletion: storage cleanup, Stripe cleanup hook, recurring-payment blockers.

create extension if not exists pg_net with schema extensions;

create or replace function public.cleanup_user_storage_for_account_deletion(p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = public, storage
as $$
begin
  if p_user_id is null then
    return;
  end if;

  delete from storage.objects so
  using public.message_attachments ma
  where so.bucket_id = ma.storage_bucket
    and so.name = ma.storage_path
    and ma.owner_id = p_user_id;

  delete from public.message_attachments
  where owner_id = p_user_id;

  delete from storage.objects
  where bucket_id = 'avatars'
    and (
      owner_id = p_user_id::text
      or name like p_user_id::text || '-%'
      or name like p_user_id::text || '/%'
      or name like 'banners/' || p_user_id::text || '-%'
    );
end;
$$;

create or replace function public.collect_user_stripe_cleanup_targets(p_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  customer_ids text[];
  subscription_ids text[];
begin
  select coalesce(array_agg(distinct customer_id), array[]::text[])
  into customer_ids
  from (
    select u.platform_stripe_customer_id as customer_id
    from public.users u
    where u.auth_id = p_user_id
      and u.platform_stripe_customer_id is not null

    union

    select sts.stripe_customer_id
    from public.server_tier_subscriptions sts
    where sts.user_id = p_user_id
      and sts.stripe_customer_id is not null

    union

    select s.stripe_customer_id
    from public.servers s
    where s.stripe_customer_id is not null
      and public.is_server_owner(s.id, p_user_id)
  ) customers;

  select coalesce(array_agg(distinct subscription_id), array[]::text[])
  into subscription_ids
  from (
    select sts.stripe_subscription_id as subscription_id
    from public.server_tier_subscriptions sts
    where sts.user_id = p_user_id
      and sts.stripe_subscription_id is not null

    union

    select s.stripe_subscription_id
    from public.servers s
    where s.stripe_subscription_id is not null
      and public.is_server_owner(s.id, p_user_id)
  ) subscriptions;

  return jsonb_build_object(
    'stripe_customer_ids', to_jsonb(customer_ids),
    'stripe_subscription_ids', to_jsonb(subscription_ids)
  );
end;
$$;

create or replace function public.queue_delete_account_stripe_cleanup(
  p_user_id uuid,
  p_stripe_targets jsonb
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
    raise warning 'Stripe cleanup skipped: vault secret account_deletion_secret is not configured';
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
      'stripe_subscription_ids', coalesce(p_stripe_targets->'stripe_subscription_ids', '[]'::jsonb)
    )
  )
  into v_request_id;
exception
  when undefined_function then
    raise warning 'Stripe cleanup skipped: pg_net extension is unavailable';
  when others then
    raise warning 'Stripe cleanup queue failed: %', sqlerrm;
end;
$$;

create or replace function public.get_my_account_deletion_status()
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  current_user_id uuid := auth.uid();
  blocking_servers jsonb := '[]'::jsonb;
  blocking_subscriptions jsonb := '[]'::jsonb;
begin
  if current_user_id is null then
    raise exception 'Not authenticated';
  end if;

  with owned_servers as (
    select distinct
      s.id,
      coalesce(s.display_name, s.handle, 'Untitled Server') as name
    from public.server_members sm
    join public.servers s
      on s.id = sm.server_id
    where sm.user_id = current_user_id
      and lower(coalesce(sm.role, '')) = 'owner'
  )
  select coalesce(
    (
      select jsonb_agg(
        jsonb_build_object(
          'server_id', os.id,
          'name', os.name
        )
        order by os.name
      )
      from owned_servers os
      where not exists (
        select 1
        from public.server_members sm
        where sm.server_id = os.id
          and sm.user_id <> current_user_id
          and lower(coalesce(sm.role, '')) = 'owner'
      )
    ),
    '[]'::jsonb
  )
  into blocking_servers;

  select coalesce(
    (
      select jsonb_agg(entry order by entry->>'name')
      from (
        select jsonb_build_object(
          'server_id', sts.server_id,
          'name', coalesce(s.display_name, s.handle, 'Untitled Server'),
          'tier_name', st.name,
          'kind', 'guild_membership',
          'stripe_subscription_id', sts.stripe_subscription_id
        ) as entry
        from public.server_tier_subscriptions sts
        join public.servers s
          on s.id = sts.server_id
        left join public.subscription_tiers st
          on st.id = sts.tier_id
        where sts.user_id = current_user_id
          and sts.stripe_subscription_id is not null
          and sts.status in ('active', 'trialing', 'past_due')

        union all

        select jsonb_build_object(
          'server_id', s.id,
          'name', coalesce(s.display_name, s.handle, 'Untitled Server'),
          'tier_name', null,
          'kind', 'guild_plan',
          'stripe_subscription_id', s.stripe_subscription_id
        )
        from public.servers s
        where s.stripe_subscription_id is not null
          and s.billing_status in ('active', 'trialing', 'past_due')
          and public.is_server_owner(s.id, current_user_id)
      ) blocking
    ),
    '[]'::jsonb
  )
  into blocking_subscriptions;

  return jsonb_build_object(
    'blocking_servers', blocking_servers,
    'blocking_subscriptions', blocking_subscriptions,
    'transferable_servers', '[]'::jsonb
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

  stripe_targets := public.collect_user_stripe_cleanup_targets(current_user_id);
  perform public.queue_delete_account_stripe_cleanup(current_user_id, stripe_targets);
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

revoke all on function public.cleanup_user_storage_for_account_deletion(uuid) from public;
revoke all on function public.collect_user_stripe_cleanup_targets(uuid) from public;
revoke all on function public.queue_delete_account_stripe_cleanup(uuid, jsonb) from public;

grant execute on function public.get_my_account_deletion_status() to authenticated;
grant execute on function public.delete_my_account() to authenticated;
