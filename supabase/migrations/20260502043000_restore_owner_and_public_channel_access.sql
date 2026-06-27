insert into public.server_members (server_id, user_id, role)
select s.id, s.owner_id, 'owner'
from public.servers s
where s.owner_id is not null
on conflict (server_id, user_id) do update set
  role = case
    when lower(coalesce(public.server_members.role, '')) in ('owner', 'admin')
      then public.server_members.role
    else 'owner'
  end;

create or replace function public.check_server_membership(
  p_server_id bigint,
  p_user_id uuid
)
returns boolean
language sql
security definer
set search_path to public
as $$
  select exists (
    select 1
    from public.servers s
    where s.id = p_server_id
      and s.owner_id = p_user_id
  )
  or exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = p_user_id
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
      s.visibility,
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
  join public.servers s
    on s.id = c.server_id
  left join public.subscription_tiers st
    on st.id = c.tier_id
  where c.server_id = p_server_id
    and (
      s.owner_id = auth.uid()
      or s.visibility = 'public'
      or exists (
        select 1
        from public.server_members sm
        where sm.server_id = p_server_id
          and sm.user_id = auth.uid()
      )
    )
    and public.user_can_access_channel(c.id, auth.uid())
  order by c.position asc, c.created_at asc;
$$;
