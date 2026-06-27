create or replace function public.user_can_access_channel(
  p_channel_id bigint,
  p_user_id uuid
)
returns boolean
language sql
security definer
set search_path to public
as $$
  with channel_row as (
    select
      c.id,
      c.server_id,
      c.tier_id,
      st.role_id,
      coalesce(st.price, 0) as tier_price,
      coalesce(s.visibility, 'public') as visibility,
      s.owner_id
    from public.channels c
    join public.servers s
      on s.id = c.server_id
    left join public.subscription_tiers st
      on st.id = c.tier_id
    where c.id = p_channel_id
    limit 1
  ),
  member_row as (
    select sm.server_id, sm.role, sm.role_id
    from public.server_members sm
    join channel_row c
      on c.server_id = sm.server_id
    where sm.user_id = p_user_id
    limit 1
  )
  select exists (
    select 1
    from channel_row c
    left join member_row sm
      on sm.server_id = c.server_id
    where
      p_user_id is not null
      and (
        c.owner_id = p_user_id
        or sm.server_id is not null
        or c.visibility = 'public'
      )
      and (
        c.tier_id is null
        or c.tier_price <= 0
        or c.owner_id = p_user_id
        or lower(coalesce(sm.role, '')) in ('owner', 'admin')
        or (c.role_id is not null and public.user_has_server_role(c.server_id, p_user_id, c.role_id))
        or exists (
          select 1
          from public.server_tier_subscriptions sts
          where sts.server_id = c.server_id
            and sts.tier_id = c.tier_id
            and sts.user_id = p_user_id
            and sts.status in ('active', 'trialing')
        )
      )
  );
$$;

