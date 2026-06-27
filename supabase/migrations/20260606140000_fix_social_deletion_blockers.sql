-- Block Social data erasure for sole-owned servers and any active payment.

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
        where public.is_server_owner(s.id, current_user_id)
      ) owned
      where not exists (
        select 1
        from public.server_members sm
        where sm.server_id = owned.id
          and sm.user_id <> current_user_id
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
        where sts.user_id = current_user_id
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
        where public.is_server_owner(s.id, current_user_id)
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

comment on function public.get_my_account_deletion_status() is
  'Returns blockers for Social data erasure: sole-owned servers and any active payment (Stripe, tokens, or other billing).';
