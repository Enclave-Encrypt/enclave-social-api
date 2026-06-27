-- Service-role purge used by Enclave Account delete-enclave-account when token exchange fails.

create or replace function public.get_account_deletion_status_for_user(p_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  blocking_servers jsonb := '[]'::jsonb;
  blocking_subscriptions jsonb := '[]'::jsonb;
begin
  if p_user_id is null then
    raise exception 'Missing user id';
  end if;

  select coalesce(
    (
      select jsonb_agg(
        jsonb_build_object(
          'server_id', owned.id,
          'name', owned.name
        )
        order by owned.name
      )
      from (
        select distinct
          s.id,
          coalesce(s.display_name, s.handle, 'Untitled Server') as name
        from public.servers s
        where public.is_server_owner(s.id, p_user_id)
      ) owned
      where not exists (
        select 1
        from public.server_members sm
        where sm.server_id = owned.id
          and sm.user_id <> p_user_id
          and public.is_server_owner(owned.id, sm.user_id)
      )
    ),
    '[]'::jsonb
  )
  into blocking_servers;

  select coalesce(
    (
      select jsonb_agg(entry order by entry->>'name', entry->>'kind')
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
        where sts.user_id = p_user_id
          and sts.status in ('active', 'trialing', 'past_due', 'unpaid', 'pending', 'incomplete')

        union all

        select jsonb_build_object(
          'server_id', s.id,
          'name', coalesce(s.display_name, s.handle, 'Untitled Server'),
          'tier_name', null,
          'kind', 'guild_plan',
          'stripe_subscription_id', s.stripe_subscription_id
        )
        from public.servers s
        where public.is_server_owner(s.id, p_user_id)
          and s.billing_status in ('active', 'trialing', 'past_due', 'unpaid', 'pending')
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

create or replace function public.get_my_account_deletion_status()
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  current_user_id uuid := auth.uid();
begin
  if current_user_id is null then
    raise exception 'Not authenticated';
  end if;

  return public.get_account_deletion_status_for_user(current_user_id);
end;
$$;

create or replace function public.purge_social_account_for_account_deletion(p_account_user_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  status jsonb;
  blocking_server_count integer;
  blocking_subscription_count integer;
  stripe_targets jsonb;
  storage_targets jsonb;
begin
  if p_account_user_id is null then
    raise exception 'Missing account user id';
  end if;

  if not exists (
    select 1
    from public.users u
    where u.auth_id = p_account_user_id
  ) then
    return jsonb_build_object('deleted', false, 'skipped', true, 'reason', 'no_social_profile');
  end if;

  status := public.get_account_deletion_status_for_user(p_account_user_id);
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

  storage_targets := public.collect_user_storage_cleanup_targets(p_account_user_id);
  stripe_targets := public.collect_user_stripe_cleanup_targets(p_account_user_id);
  perform public.queue_delete_account_cleanup(p_account_user_id, stripe_targets, storage_targets);
  perform public.cleanup_user_storage_for_account_deletion(p_account_user_id);

  delete from public.server_nicknames
  where user_id = p_account_user_id;

  delete from public.server_members
  where user_id = p_account_user_id;

  delete from auth.users
  where id = p_account_user_id;

  return jsonb_build_object('deleted', true, 'skipped', false);
end;
$$;

revoke all on function public.get_account_deletion_status_for_user(uuid) from public;
revoke all on function public.purge_social_account_for_account_deletion(uuid) from public;

grant execute on function public.get_account_deletion_status_for_user(uuid) to service_role;
grant execute on function public.purge_social_account_for_account_deletion(uuid) to service_role;

comment on function public.purge_social_account_for_account_deletion(uuid) is
  'Deletes Social auth/profile data for an Enclave Account user id. Invoked by Account delete-enclave-account via service role.';
