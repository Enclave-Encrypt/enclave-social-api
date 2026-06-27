create or replace function public.user_can_view_channel(
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

create or replace function public.get_accessible_server_channels(p_server_id bigint)
returns table (
  id bigint,
  server_id bigint,
  name text,
  type text,
  "position" integer,
  created_at timestamptz,
  tier_id bigint,
  required_tier_name text,
  can_access boolean
)
language sql
stable
security definer
set search_path to public
as $$
  select
    c.id,
    c.server_id,
    c.name,
    c.type,
    c.position as "position",
    c.created_at,
    c.tier_id,
    st.name as required_tier_name,
    public.user_can_access_channel(c.id, auth.uid()) as can_access
  from public.channels c
  left join public.subscription_tiers st
    on st.id = c.tier_id
  where c.server_id = p_server_id
    and public.user_can_view_channel(c.id, auth.uid())
  order by c.position asc, c.created_at asc;
$$;

create or replace function public.get_channel_message_history(
  p_channel_id bigint,
  p_before timestamptz default null,
  p_limit integer default 50
)
returns setof public.messages
language sql
stable
security definer
set search_path to public
as $$
  select m.*
  from public.messages m
  where
    m.channel_id = p_channel_id
    and public.user_can_view_channel(m.channel_id, auth.uid())
    and (p_before is null or m.created_at < p_before)
  order by m.created_at desc
  limit least(greatest(coalesce(p_limit, 50), 1), 100);
$$;

drop policy if exists "Allow authenticated reads on messages" on public.messages;
drop policy if exists "Accessible users can read channel messages" on public.messages;
create policy "Accessible users can read channel messages"
on public.messages
for select
to authenticated
using (public.user_can_view_channel(channel_id, auth.uid()));

drop policy if exists "Accessible users can read channel MLS groups" on public.mls_groups;
create policy "Accessible users can read channel MLS groups"
on public.mls_groups
for select
to authenticated
using (
  conversation_kind in ('channel', 'server_channel')
  and channel_id is not null
  and public.user_can_view_channel(channel_id, auth.uid())
);

drop policy if exists "Accessible users can read channel MLS snapshots" on public.mls_channel_state_snapshots;
create policy "Accessible users can read channel MLS snapshots"
on public.mls_channel_state_snapshots
for select
to authenticated
using (public.user_can_view_channel(channel_id, auth.uid()));
