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

drop policy if exists "Members can insert accessible channel messages" on public.messages;
create policy "Members can insert accessible channel messages"
on public.messages
for insert
to authenticated
with check (
  sender_id = auth.uid()
  and public.user_can_access_channel(channel_id, auth.uid())
);

drop policy if exists "Accessible users can create channel MLS groups" on public.mls_groups;
create policy "Accessible users can create channel MLS groups"
on public.mls_groups
for insert
to authenticated
with check (
  conversation_kind in ('channel', 'server_channel')
  and channel_id is not null
  and public.user_can_access_channel(channel_id, auth.uid())
  and (
    creator_device_id is null
    or exists (
      select 1
      from public.user_devices ud
      where ud.id = creator_device_id
        and ud.user_id = auth.uid()
        and ud.is_active = true
    )
  )
);

drop policy if exists "Accessible users can read channel MLS groups" on public.mls_groups;
create policy "Accessible users can read channel MLS groups"
on public.mls_groups
for select
to authenticated
using (
  conversation_kind in ('channel', 'server_channel')
  and channel_id is not null
  and public.user_can_access_channel(channel_id, auth.uid())
);

drop policy if exists "Accessible users can update channel MLS groups" on public.mls_groups;
create policy "Accessible users can update channel MLS groups"
on public.mls_groups
for update
to authenticated
using (
  conversation_kind in ('channel', 'server_channel')
  and channel_id is not null
  and public.user_can_access_channel(channel_id, auth.uid())
)
with check (
  conversation_kind in ('channel', 'server_channel')
  and channel_id is not null
  and public.user_can_access_channel(channel_id, auth.uid())
);

drop policy if exists "Accessible users can insert channel MLS snapshots" on public.mls_channel_state_snapshots;
create policy "Accessible users can insert channel MLS snapshots"
on public.mls_channel_state_snapshots
for insert
to authenticated
with check (
  public.user_can_access_channel(channel_id, auth.uid())
  and updated_by_user_id = auth.uid()
  and (
    updated_by_device_id is null
    or exists (
      select 1
      from public.user_devices ud
      where ud.id = updated_by_device_id
        and ud.user_id = auth.uid()
        and ud.is_active = true
    )
  )
  and exists (
    select 1
    from public.mls_groups g
    where g.id = mls_channel_state_snapshots.mls_group_id
      and g.channel_id = mls_channel_state_snapshots.channel_id
      and g.server_id = mls_channel_state_snapshots.server_id
      and g.group_identifier = mls_channel_state_snapshots.group_identifier
      and g.conversation_kind in ('channel', 'server_channel')
  )
);

drop policy if exists "Accessible users can read channel MLS snapshots" on public.mls_channel_state_snapshots;
create policy "Accessible users can read channel MLS snapshots"
on public.mls_channel_state_snapshots
for select
to authenticated
using (public.user_can_access_channel(channel_id, auth.uid()));

drop policy if exists "Accessible users can update channel MLS snapshots" on public.mls_channel_state_snapshots;
create policy "Accessible users can update channel MLS snapshots"
on public.mls_channel_state_snapshots
for update
to authenticated
using (public.user_can_access_channel(channel_id, auth.uid()))
with check (
  public.user_can_access_channel(channel_id, auth.uid())
  and updated_by_user_id = auth.uid()
  and (
    updated_by_device_id is null
    or exists (
      select 1
      from public.user_devices ud
      where ud.id = updated_by_device_id
        and ud.user_id = auth.uid()
        and ud.is_active = true
    )
  )
  and exists (
    select 1
    from public.mls_groups g
    where g.id = mls_channel_state_snapshots.mls_group_id
      and g.channel_id = mls_channel_state_snapshots.channel_id
      and g.server_id = mls_channel_state_snapshots.server_id
      and g.group_identifier = mls_channel_state_snapshots.group_identifier
      and g.conversation_kind in ('channel', 'server_channel')
  )
);
