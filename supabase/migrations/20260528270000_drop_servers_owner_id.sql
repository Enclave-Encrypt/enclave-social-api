-- Remove servers.owner_id. Ownership is server_members.role = 'owner' only.

-- Final backfill before column drop.
insert into public.server_members (server_id, user_id, role)
select s.id, s.owner_id, 'owner'
from public.servers s
where s.owner_id is not null
  and not exists (
    select 1
    from public.server_members sm
    where sm.server_id = s.id
      and sm.user_id = s.owner_id
  )
on conflict (server_id, user_id) do update
  set role = 'owner';

create or replace function public.get_server_founding_owner_id(p_server_id bigint)
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select sm.user_id
  from public.server_members sm
  where sm.server_id = p_server_id
    and lower(coalesce(sm.role, '')) = 'owner'
  order by sm.created_at asc, sm.id asc
  limit 1;
$$;

grant execute on function public.get_server_founding_owner_id(bigint) to authenticated;

create or replace function public.create_default_server_roles_and_owner_membership()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  owner_role_id bigint;
  creator_id uuid := auth.uid();
begin
  if creator_id is null then
    raise exception 'Authentication required to create a server';
  end if;

  insert into public.server_roles (server_id, name, color, permissions, position, is_default)
  values
    (
      new.id,
      'Owner',
      '#F0B232',
      '{"manage_channels": true, "manage_roles": true, "manage_server": true, "kick_members": true, "ban_members": true, "manage_messages": true}',
      400,
      true
    ),
    (
      new.id,
      'Admin',
      '#FF6B00',
      '{"manage_channels": true, "manage_roles": true, "manage_server": true, "kick_members": true, "ban_members": true, "manage_messages": true}',
      300,
      true
    ),
    (
      new.id,
      'Mod',
      '#00CC66',
      '{"manage_channels": false, "manage_roles": false, "manage_server": false, "kick_members": true, "ban_members": false, "manage_messages": true}',
      200,
      true
    ),
    (
      new.id,
      'Member',
      '#999999',
      '{"manage_channels": false, "manage_roles": false, "manage_server": false, "kick_members": false, "ban_members": false, "manage_messages": false}',
      100,
      true
    );

  select sr.id
    into owner_role_id
  from public.server_roles sr
  where sr.server_id = new.id
    and lower(sr.name) = 'owner'
  order by sr.position desc, sr.id asc
  limit 1;

  insert into public.server_members (server_id, user_id, role, role_id)
  values (new.id, creator_id, 'owner', owner_role_id)
  on conflict (server_id, user_id)
  do update
    set role = 'owner',
        role_id = excluded.role_id;

  return new;
end;
$$;

create or replace function public.check_server_membership(p_server_id bigint, p_user_id uuid)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = p_user_id
  );
$$;

create or replace function public.get_my_channel_unread_context()
returns table (channel_id bigint, server_id bigint, unread_count bigint)
language sql
stable
set search_path = public
as $$
  select
    c.id as channel_id,
    c.server_id,
    count(m.id)::bigint as unread_count
  from public.channels c
  join public.server_members sm
    on sm.server_id = c.server_id
   and sm.user_id = auth.uid()
  left join public.channel_read_state crs
    on crs.channel_id = c.id
   and crs.user_id = auth.uid()
  left join public.messages m
    on m.channel_id = c.id
   and m.sender_id <> auth.uid()
   and (
     crs.last_read_at is null
     or m.created_at > crs.last_read_at
   )
  where auth.uid() is not null
  group by c.id, c.server_id, c.position
  order by c.server_id asc, c.position asc, c.id asc;
$$;

create or replace function public.get_server_feed_posts(p_server_id bigint, p_limit integer default 60)
returns table (
  id uuid,
  server_id bigint,
  author_id uuid,
  title text,
  content text,
  flair_id uuid,
  flair_name text,
  flair_color text,
  created_at timestamptz,
  author_username text,
  author_display_name text,
  author_avatar text,
  upvotes integer,
  downvotes integer,
  my_vote text,
  comment_count integer
)
language sql
stable
set search_path = public
as $$
  select
    p.id,
    p.server_id,
    p.author_id,
    p.title,
    p.content,
    p.flair_id,
    pf.name as flair_name,
    pf.color as flair_color,
    p.created_at,
    coalesce(u.username, 'unknown') as author_username,
    u.display_name as author_display_name,
    u.avatar_url as author_avatar,
    coalesce(votes.upvotes, 0)::integer as upvotes,
    coalesce(votes.downvotes, 0)::integer as downvotes,
    votes.my_vote,
    coalesce(comments.comment_count, 0)::integer as comment_count
  from public.posts p
  join public.servers s
    on s.id = p.server_id
  left join public.server_members sm
    on sm.server_id = s.id
   and sm.user_id = auth.uid()
  left join public.post_flairs pf
    on pf.id = p.flair_id
  left join public.users u
    on u.auth_id = p.author_id
  left join lateral (
    select
      count(*) filter (where pv.vote_type = 'up') as upvotes,
      count(*) filter (where pv.vote_type = 'down') as downvotes,
      max(pv.vote_type) filter (where pv.user_id = auth.uid()) as my_vote
    from public.post_votes pv
    where pv.post_id = p.id
  ) votes on true
  left join lateral (
    select count(*) as comment_count
    from public.post_comments pc
    where pc.post_id = p.id
  ) comments on true
  where
    p.server_id = p_server_id
    and (
      s.visibility = 'public'
      or sm.user_id is not null
    )
  order by p.created_at desc
  limit least(greatest(coalesce(p_limit, 60), 1), 100);
$$;

create or replace function public.user_can_manage_channels(
  p_server_id bigint,
  p_user_id uuid default auth.uid()
)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.server_members sm
    left join public.server_roles sr
      on sr.id = sm.role_id
    where sm.server_id = p_server_id
      and sm.user_id = p_user_id
      and (
        lower(coalesce(sm.role, '')) in ('owner', 'admin')
        or coalesce((sr.permissions ->> 'manage_channels')::boolean, false)
      )
  )
  or exists (
    select 1
    from public.server_member_roles smr
    join public.server_roles sr
      on sr.id = smr.role_id
    where smr.server_id = p_server_id
      and smr.user_id = p_user_id
      and coalesce((sr.permissions ->> 'manage_channels')::boolean, false)
  );
$$;

create or replace function public.user_can_manage_messages(
  p_server_id bigint,
  p_user_id uuid default auth.uid()
)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.server_members sm
    left join public.server_roles sr
      on sr.id = sm.role_id
    where sm.server_id = p_server_id
      and sm.user_id = p_user_id
      and (
        lower(coalesce(sm.role, '')) in ('owner', 'admin', 'mod', 'moderator')
        or coalesce((sr.permissions ->> 'manage_messages')::boolean, false)
      )
  )
  or exists (
    select 1
    from public.server_member_roles smr
    join public.server_roles sr
      on sr.id = smr.role_id
    where smr.server_id = p_server_id
      and smr.user_id = p_user_id
      and coalesce((sr.permissions ->> 'manage_messages')::boolean, false)
  );
$$;

create or replace function public.leave_server(p_server_id bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  current_user_id uuid := auth.uid();
  current_member public.server_members%rowtype;
  other_owner_count bigint;
begin
  if current_user_id is null then
    raise exception 'Authentication required';
  end if;

  select *
  into current_member
  from public.server_members
  where server_id = p_server_id
    and user_id = current_user_id;

  if not found then
    raise exception 'You are not a member of this server';
  end if;

  if lower(coalesce(current_member.role, '')) = 'owner' then
    select count(*)
    into other_owner_count
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id <> current_user_id
      and lower(coalesce(sm.role, '')) = 'owner';

    if other_owner_count = 0 then
      raise exception 'You cannot leave this server because you are the only owner. Add another owner first.';
    end if;
  end if;

  delete from public.server_nicknames
  where server_id = p_server_id
    and user_id = current_user_id;

  delete from public.server_members
  where server_id = p_server_id
    and user_id = current_user_id;
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
  blocking_count integer;
begin
  if current_user_id is null then
    raise exception 'Not authenticated';
  end if;

  status := public.get_my_account_deletion_status();
  blocking_count := coalesce(jsonb_array_length(status->'blocking_servers'), 0);

  if blocking_count > 0 then
    raise exception 'Delete blocked. Add another owner or delete these servers first: %',
      (
        select string_agg(value->>'name', ', ')
        from jsonb_array_elements(status->'blocking_servers')
      );
  end if;

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

create or replace function public.spend_tokens_for_guild_membership(p_tier_id bigint)
returns integer
language plpgsql
security definer
set search_path to public
as $$
declare
  tier_row record;
  guild_owner_id uuid;
  cost_tokens integer;
  platform_fee_tokens integer;
  creator_net_tokens integer;
begin
  select st.id, st.server_id, st.name, st.price_tokens, st.role_id
    into tier_row
  from public.subscription_tiers st
  where st.id = p_tier_id;

  if tier_row.id is null or tier_row.role_id is null then
    raise exception 'Guild membership is not available';
  end if;

  guild_owner_id := public.get_server_founding_owner_id(tier_row.server_id);
  if guild_owner_id is null then
    raise exception 'Guild has no owner to receive membership earnings';
  end if;

  cost_tokens := greatest(coalesce(tier_row.price_tokens, 0), 0);
  if cost_tokens <= 0 then
    raise exception 'Guild membership price is invalid';
  end if;

  platform_fee_tokens := ceil(cost_tokens * 0.10)::integer;
  creator_net_tokens := cost_tokens - platform_fee_tokens;

  perform public.spend_tokens(
    auth.uid(),
    cost_tokens,
    'guild_membership',
    tier_row.server_id,
    tier_row.id,
    jsonb_build_object(
      'membership_name', tier_row.name,
      'platform_fee_tokens', platform_fee_tokens,
      'creator_net_tokens', creator_net_tokens
    )
  );

  update public.users
     set creator_pending_tokens = creator_pending_tokens + creator_net_tokens
   where auth_id = guild_owner_id;

  insert into public.creator_earning_entries (
    creator_user_id,
    buyer_user_id,
    server_id,
    tier_id,
    gross_tokens,
    platform_fee_tokens,
    net_tokens,
    net_usd_cents,
    status
  )
  values (
    guild_owner_id,
    auth.uid(),
    tier_row.server_id,
    tier_row.id,
    cost_tokens,
    platform_fee_tokens,
    creator_net_tokens,
    creator_net_tokens,
    'pending'
  );

  perform public.grant_server_tier_role(
    tier_row.server_id,
    tier_row.id,
    auth.uid(),
    'active',
    null,
    null,
    now() + interval '1 month'
  );

  return (
    select token_balance
    from public.users
    where auth_id = auth.uid()
  );
end;
$$;

grant execute on function public.spend_tokens_for_guild_membership(bigint) to authenticated;

-- Legacy RLS policies reference servers.owner_id and block column drop.
drop policy if exists "Server owner can manage roles" on public.server_roles;
drop policy if exists "Server owner can manage tiers" on public.subscription_tiers;
drop policy if exists "Allow server owners to delete channels" on public.channels;
drop policy if exists "Allow owners to remove members" on public.server_members;
drop policy if exists "Servers visible based on visibility" on public.servers;
drop policy if exists "Allow owners to delete their servers" on public.servers;
drop policy if exists "Allow owners to update their servers" on public.servers;
drop policy if exists "Allow users to insert their own servers" on public.servers;

drop function if exists public.is_server_owner(bigint) cascade;
drop function if exists public.is_server_owner(bigint, uuid) cascade;

create or replace function public.is_server_owner(
  p_server_id bigint,
  p_user_id uuid default auth.uid()
)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = coalesce(p_user_id, auth.uid())
      and lower(coalesce(sm.role, '')) = 'owner'
  );
$$;

grant execute on function public.is_server_owner(bigint, uuid) to authenticated;

create or replace function public.is_server_admin(p_server_id bigint)
returns boolean
language sql
security definer
set search_path = public
as $$
  select public.is_server_owner(p_server_id, auth.uid())
  or exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = auth.uid()
      and lower(coalesce(sm.role, '')) = 'admin'
  );
$$;

drop policy if exists "Owners can manage roles via membership" on public.server_roles;
create policy "Owners can manage roles via membership"
on public.server_roles
to authenticated
using (public.is_server_owner(server_id, auth.uid()))
with check (public.is_server_owner(server_id, auth.uid()));

drop policy if exists "Owners can manage tiers via membership" on public.subscription_tiers;
create policy "Owners can manage tiers via membership"
on public.subscription_tiers
to authenticated
using (public.is_server_owner(server_id, auth.uid()))
with check (public.is_server_owner(server_id, auth.uid()));

drop policy if exists "Owners and admins can delete channels via membership" on public.channels;
create policy "Owners and admins can delete channels via membership"
on public.channels
for delete
to authenticated
using (
  public.is_server_owner(server_id, auth.uid())
  or public.is_server_admin(server_id)
);

drop policy if exists "Owners and admins can create channels via membership" on public.channels;
create policy "Owners and admins can create channels via membership"
on public.channels
for insert
to authenticated
with check (
  public.is_server_owner(server_id, auth.uid())
  or public.is_server_admin(server_id)
);

drop policy if exists "Owners and admins can update channels via membership" on public.channels;
create policy "Owners and admins can update channels via membership"
on public.channels
for update
to authenticated
using (
  public.is_server_owner(server_id, auth.uid())
  or public.is_server_admin(server_id)
)
with check (
  public.is_server_owner(server_id, auth.uid())
  or public.is_server_admin(server_id)
);

drop policy if exists "Owners and admins can remove members" on public.server_members;
create policy "Owners and admins can remove members"
on public.server_members
for delete
to authenticated
using (
  public.is_server_owner(server_id, auth.uid())
  or public.is_server_admin(server_id)
);

drop policy if exists "Owners can update member roles" on public.server_members;
create policy "Owners can update member roles"
on public.server_members
for update
to authenticated
using (public.is_server_owner(server_id, auth.uid()))
with check (public.is_server_owner(server_id, auth.uid()));

drop policy if exists "Owners can update servers via membership" on public.servers;
create policy "Owners can update servers via membership"
on public.servers
for update
to authenticated
using (public.is_server_owner(id, auth.uid()))
with check (public.is_server_owner(id, auth.uid()));

drop policy if exists "Owners can delete servers via membership" on public.servers;
create policy "Owners can delete servers via membership"
on public.servers
for delete
to authenticated
using (public.is_server_owner(id, auth.uid()));

drop policy if exists "Authenticated users can create servers" on public.servers;
create policy "Authenticated users can create servers"
on public.servers
for insert
to authenticated
with check (auth.uid() is not null);

create policy "Servers visible based on visibility"
on public.servers
for select
to authenticated
using (
  coalesce(visibility, 'public') = 'public'
  or exists (
    select 1
    from public.server_members sm
    where sm.server_id = servers.id
      and sm.user_id = auth.uid()
  )
);

-- Owner rows are created by the server bootstrap trigger or owner/admin RPCs.
drop policy if exists "Server owners can create their own owner membership" on public.server_members;

drop policy if exists "Server owners can upload their icons" on storage.objects;
drop policy if exists "Server owners can update their icons" on storage.objects;
drop policy if exists "Server owners can delete their icons" on storage.objects;

create policy "Server owners can upload their icons"
on storage.objects
for insert
to authenticated
with check (
  bucket_id = 'server-icons'
  and public.is_server_owner(((storage.foldername(name))[1])::bigint, auth.uid())
);

create policy "Server owners can update their icons"
on storage.objects
for update
to authenticated
using (
  bucket_id = 'server-icons'
  and public.is_server_owner(((storage.foldername(name))[1])::bigint, auth.uid())
)
with check (
  bucket_id = 'server-icons'
  and public.is_server_owner(((storage.foldername(name))[1])::bigint, auth.uid())
);

create policy "Server owners can delete their icons"
on storage.objects
for delete
to authenticated
using (
  bucket_id = 'server-icons'
  and public.is_server_owner(((storage.foldername(name))[1])::bigint, auth.uid())
);

alter table public.servers
  drop column if exists owner_id;
