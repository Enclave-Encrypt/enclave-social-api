alter table public.subscription_tiers
  add column if not exists role_id bigint references public.server_roles(id) on delete set null,
  add column if not exists stripe_price_id text,
  add column if not exists stripe_product_id text;

create table if not exists public.server_tier_subscriptions (
  id bigint generated always as identity primary key,
  server_id bigint not null references public.servers(id) on delete cascade,
  tier_id bigint not null references public.subscription_tiers(id) on delete cascade,
  user_id uuid not null references public.users(auth_id) on delete cascade,
  status text not null default 'active',
  stripe_customer_id text,
  stripe_subscription_id text unique,
  current_period_end timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint server_tier_subscriptions_status_check
    check (status in ('active', 'trialing', 'past_due', 'canceled', 'incomplete', 'incomplete_expired', 'unpaid')),
  constraint server_tier_subscriptions_unique_user_tier unique (server_id, tier_id, user_id)
);

create table if not exists public.server_member_roles (
  id bigint generated always as identity primary key,
  server_id bigint not null references public.servers(id) on delete cascade,
  user_id uuid not null references public.users(auth_id) on delete cascade,
  role_id bigint not null references public.server_roles(id) on delete cascade,
  source text not null default 'manual',
  subscription_id bigint references public.server_tier_subscriptions(id) on delete cascade,
  created_at timestamptz not null default now(),
  constraint server_member_roles_source_check check (source in ('manual', 'subscription')),
  constraint server_member_roles_unique_role unique (server_id, user_id, role_id)
);

create index if not exists subscription_tiers_role_id_idx
  on public.subscription_tiers (role_id);
create index if not exists channels_tier_id_idx
  on public.channels (tier_id);
create index if not exists server_tier_subscriptions_user_server_idx
  on public.server_tier_subscriptions (user_id, server_id, status);
create index if not exists server_member_roles_user_server_idx
  on public.server_member_roles (user_id, server_id);

alter table public.server_tier_subscriptions enable row level security;
alter table public.server_member_roles enable row level security;

drop policy if exists "Users can read their server tier subscriptions" on public.server_tier_subscriptions;
create policy "Users can read their server tier subscriptions"
on public.server_tier_subscriptions
for select
to authenticated
using (
  user_id = auth.uid()
  or public.is_server_admin(server_id)
);

drop policy if exists "Server admins can read member roles" on public.server_member_roles;
create policy "Server admins can read member roles"
on public.server_member_roles
for select
to authenticated
using (
  user_id = auth.uid()
  or public.check_server_membership(server_id, auth.uid())
);

create or replace function public.user_has_server_role(
  p_server_id bigint,
  p_user_id uuid,
  p_role_id bigint
)
returns boolean
language sql
security definer
set search_path to public
as $$
  select exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = p_user_id
      and sm.role_id = p_role_id
  )
  or exists (
    select 1
    from public.server_member_roles smr
    where smr.server_id = p_server_id
      and smr.user_id = p_user_id
      and smr.role_id = p_role_id
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
    select c.id, c.server_id, c.tier_id, st.role_id
    from public.channels c
    left join public.subscription_tiers st
      on st.id = c.tier_id
    where c.id = p_channel_id
    limit 1
  )
  select exists (
    select 1
    from channel_row c
    join public.server_members sm
      on sm.server_id = c.server_id
     and sm.user_id = p_user_id
    where c.tier_id is null
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
    and public.check_server_membership(p_server_id, auth.uid())
    and public.user_can_access_channel(c.id, auth.uid())
  order by c.position asc, c.created_at asc;
$$;

create or replace function public.grant_server_tier_role(
  p_server_id bigint,
  p_tier_id bigint,
  p_user_id uuid,
  p_status text,
  p_stripe_customer_id text default null,
  p_stripe_subscription_id text default null,
  p_current_period_end timestamptz default null
)
returns void
language plpgsql
security definer
set search_path to public
as $$
declare
  tier_role_id bigint;
  subscription_row_id bigint;
begin
  select role_id
    into tier_role_id
  from public.subscription_tiers
  where id = p_tier_id
    and server_id = p_server_id;

  if tier_role_id is null then
    raise exception 'Tier has no linked role';
  end if;

  insert into public.server_members (server_id, user_id, role, role_id)
  values (p_server_id, p_user_id, 'member', (
    select id from public.server_roles
    where server_id = p_server_id and lower(name) = 'member'
    order by is_default desc, id asc
    limit 1
  ))
  on conflict (server_id, user_id) do nothing;

  insert into public.server_tier_subscriptions (
    server_id,
    tier_id,
    user_id,
    status,
    stripe_customer_id,
    stripe_subscription_id,
    current_period_end,
    updated_at
  )
  values (
    p_server_id,
    p_tier_id,
    p_user_id,
    p_status,
    p_stripe_customer_id,
    p_stripe_subscription_id,
    p_current_period_end,
    now()
  )
  on conflict (server_id, tier_id, user_id) do update set
    status = excluded.status,
    stripe_customer_id = coalesce(excluded.stripe_customer_id, server_tier_subscriptions.stripe_customer_id),
    stripe_subscription_id = coalesce(excluded.stripe_subscription_id, server_tier_subscriptions.stripe_subscription_id),
    current_period_end = excluded.current_period_end,
    updated_at = now()
  returning id into subscription_row_id;

  if p_status in ('active', 'trialing') then
    insert into public.server_member_roles (
      server_id,
      user_id,
      role_id,
      source,
      subscription_id
    )
    values (
      p_server_id,
      p_user_id,
      tier_role_id,
      'subscription',
      subscription_row_id
    )
    on conflict (server_id, user_id, role_id) do update set
      source = 'subscription',
      subscription_id = excluded.subscription_id;
  else
    delete from public.server_member_roles
    where server_id = p_server_id
      and user_id = p_user_id
      and role_id = tier_role_id
      and source = 'subscription';
  end if;
end;
$$;

create or replace function public.get_server_settings_members(p_server_id bigint)
returns table (
  id bigint,
  server_id bigint,
  user_id uuid,
  role text,
  roles text[],
  username text,
  display_name text,
  avatar_url text,
  email text
)
language sql
stable
security definer
set search_path to public
as $$
  with normalized as (
    select
      sm.id,
      sm.server_id,
      sm.user_id,
      case
        when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
        else lower(trim(coalesce(sm.role, 'member')))
      end as normalized_role
    from public.server_members sm
    where sm.server_id = p_server_id
  ),
  extra_roles as (
    select
      smr.user_id,
      array_agg(distinct lower(sr.name) order by lower(sr.name)) as role_names
    from public.server_member_roles smr
    join public.server_roles sr
      on sr.id = smr.role_id
    where smr.server_id = p_server_id
    group by smr.user_id
  )
  select
    n.id,
    n.server_id,
    n.user_id,
    n.normalized_role as role,
    array(
      select distinct value
      from unnest(array[n.normalized_role] || coalesce(er.role_names, array[]::text[])) as value
      where value is not null and value <> ''
    )::text[] as roles,
    u.username,
    u.display_name,
    u.avatar_url,
    u.email
  from normalized n
  join public.users u
    on u.auth_id = n.user_id
  left join extra_roles er
    on er.user_id = n.user_id
  order by
    case n.normalized_role
      when 'owner' then 4
      when 'admin' then 3
      when 'mod' then 2
      when 'member' then 1
      else 0
    end desc,
    coalesce(nullif(u.display_name, ''), nullif(u.username, ''), u.email, '') asc;
$$;

drop policy if exists "Allow authenticated reads" on public.channels;
drop policy if exists "Allow authenticated users to insert channels" on public.channels;
drop policy if exists "Allow authenticated users to reach channels" on public.channels;
drop policy if exists "Members can read accessible channels" on public.channels;

create policy "Members can read accessible channels"
on public.channels
for select
to authenticated
using (public.user_can_access_channel(id, auth.uid()));

drop policy if exists "Allow authenticated inserts on messages" on public.messages;
drop policy if exists "Allow authenticated reads on messages" on public.messages;
drop policy if exists "Members can insert accessible channel messages" on public.messages;
drop policy if exists "Members can read accessible channel messages" on public.messages;

create policy "Members can insert accessible channel messages"
on public.messages
for insert
to authenticated
with check (
  sender_id = auth.uid()
  and public.user_can_access_channel(channel_id, auth.uid())
);

create policy "Members can read accessible channel messages"
on public.messages
for select
to authenticated
using (public.user_can_access_channel(channel_id, auth.uid()));

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
  where m.channel_id = p_channel_id
    and public.user_can_access_channel(p_channel_id, auth.uid())
    and (
      p_before is null
      or m.created_at < p_before
    )
  order by m.created_at desc
  limit greatest(coalesce(p_limit, 50), 1);
$$;
