alter table "public"."servers" alter column "server_type" set default 'free'::text;

set check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.apply_platform_server_subscription(p_user_id uuid, p_server_id bigint, p_status text, p_stripe_customer_id text, p_stripe_subscription_id text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if not exists (
    select 1
    from public.servers
    where id = p_server_id
      and owner_id = p_user_id
  ) then
    raise exception 'Only the server owner can apply server billing';
  end if;

  update public.servers
     set billing_status = case
         when p_status in ('active', 'trialing') then p_status
         when p_status in ('past_due', 'unpaid') then p_status
         else 'canceled'
       end,
       stripe_customer_id = p_stripe_customer_id,
       stripe_subscription_id = p_stripe_subscription_id
   where id = p_server_id;

  update public.users
     set platform_stripe_customer_id = p_stripe_customer_id
   where auth_id = p_user_id;

  insert into public.platform_billing_events (
    user_id,
    kind,
    server_id,
    stripe_customer_id,
    stripe_subscription_id,
    status
  )
  values (
    p_user_id,
    'platform_server',
    p_server_id,
    p_stripe_customer_id,
    p_stripe_subscription_id,
    p_status
  );
end;
$function$
;

CREATE OR REPLACE FUNCTION public.assign_server_member_role(p_member_id bigint, p_role_id bigint)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
  target_member public.server_members%rowtype;
  target_role public.server_roles%rowtype;
  actor_is_owner boolean;
  actor_is_admin boolean;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  select *
  into target_member
  from public.server_members
  where id = p_member_id;

  if not found then
    raise exception 'Member not found';
  end if;

  select *
  into target_role
  from public.server_roles
  where id = p_role_id
    and server_id = target_member.server_id;

  if not found then
    raise exception 'Role not found';
  end if;

  if target_member.user_id = auth.uid() then
    raise exception 'You cannot change your own role';
  end if;

  actor_is_owner := public.is_server_owner(target_member.server_id);
  actor_is_admin := public.is_server_admin(target_member.server_id);

  if lower(coalesce(target_role.name, '')) = 'owner' then
    if not actor_is_owner then
      raise exception 'Only owners can assign the owner role';
    end if;
  elsif lower(coalesce(target_member.role, '')) = 'owner' then
    if not actor_is_owner then
      raise exception 'Only owners can change another owner''s role';
    end if;
  elsif not (actor_is_owner or actor_is_admin) then
    raise exception 'Missing permission to assign roles';
  end if;

  update public.server_members
  set role = lower(target_role.name),
      role_id = target_role.id
  where id = target_member.id;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.check_server_membership(p_server_id bigint, p_user_id uuid)
 RETURNS boolean
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
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
$function$
;

CREATE OR REPLACE FUNCTION public.create_default_server_roles_and_owner_membership()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
declare
  owner_role_id bigint;
begin
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
  values (new.id, new.owner_id, 'owner', owner_role_id)
  on conflict (server_id, user_id)
  do update
    set role = 'owner',
        role_id = excluded.role_id;

  return new;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.delete_my_account()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'auth'
AS $function$
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

  update public.servers
  set owner_id = null
  where owner_id = current_user_id;

  delete from public.server_nicknames
  where user_id = current_user_id;

  delete from public.server_members
  where user_id = current_user_id;

  -- Storage objects must be removed through the Storage API, not SQL DML.
  -- Keep account deletion working here and handle avatar/blob cleanup separately.

  delete from auth.users
  where id = current_user_id;

  return jsonb_build_object(
    'deleted', true,
    'transferred_servers', 0
  );
end;
$function$
;

CREATE OR REPLACE FUNCTION public.enforce_auth_identity_metadata_terms()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if public.has_blocked_profile_term(new.identity_data ->> 'username', 'username') then
    raise exception 'Username contains a word that is not allowed';
  end if;

  if public.has_blocked_profile_term(new.identity_data ->> 'display_name', 'user_display_name') then
    raise exception 'Display name contains a word that is not allowed';
  end if;

  return new;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.enforce_auth_user_metadata_terms()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if public.has_blocked_profile_term(new.raw_user_meta_data ->> 'username', 'username') then
    raise exception 'Username contains a word that is not allowed';
  end if;

  if public.has_blocked_profile_term(new.raw_user_meta_data ->> 'display_name', 'user_display_name') then
    raise exception 'Display name contains a word that is not allowed';
  end if;

  return new;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.enforce_server_profile_terms()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if public.has_blocked_profile_term(new.handle, 'server_handle') then
    raise exception 'Server handle contains a word that is not allowed';
  end if;

  if public.has_blocked_profile_term(new.display_name, 'server_display_name') then
    raise exception 'Server name contains a word that is not allowed';
  end if;

  if public.has_blocked_profile_term(new.description, 'server_bio') then
    raise exception 'Server bio contains a word that is not allowed';
  end if;

  return new;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.enforce_user_profile_terms()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if public.has_blocked_profile_term(new.username, 'username') then
    raise exception 'Username contains a word that is not allowed';
  end if;

  if public.has_blocked_profile_term(new.display_name, 'user_display_name') then
    raise exception 'Display name contains a word that is not allowed';
  end if;

  if public.has_blocked_profile_term(new.bio, 'user_bio') then
    raise exception 'Bio contains a word that is not allowed';
  end if;

  return new;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.get_accessible_server_channels(p_server_id bigint)
 RETURNS TABLE(id bigint, server_id bigint, name text, type text, "position" integer, created_at timestamp with time zone, tier_id bigint, required_tier_name text, can_access boolean)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
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
$function$
;

CREATE OR REPLACE FUNCTION public.get_channel_message_history(p_channel_id bigint, p_before timestamp with time zone DEFAULT NULL::timestamp with time zone, p_limit integer DEFAULT 50)
 RETURNS SETOF public.messages
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  select m.*
  from public.messages m
  where
    m.channel_id = p_channel_id
    and public.user_can_view_channel(m.channel_id, auth.uid())
    and (p_before is null or m.created_at < p_before)
  order by m.created_at desc
  limit least(greatest(coalesce(p_limit, 50), 1), 100);
$function$
;

CREATE OR REPLACE FUNCTION public.get_dm_message_history(p_other_user_id uuid, p_before timestamp with time zone DEFAULT NULL::timestamp with time zone, p_limit integer DEFAULT 50)
 RETURNS SETOF public.direct_messages
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $function$
  select dm.*
  from public.direct_messages dm
  where
    least(dm.sender_id, dm.recipient_id) = least(auth.uid(), p_other_user_id)
    and greatest(dm.sender_id, dm.recipient_id) = greatest(auth.uid(), p_other_user_id)
    and (p_before is null or dm.created_at < p_before)
  order by dm.created_at desc
  limit least(greatest(coalesce(p_limit, 50), 1), 100);
$function$
;

CREATE OR REPLACE FUNCTION public.get_my_account_deletion_status()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'auth'
AS $function$
declare
  current_user_id uuid := auth.uid();
  blocking_servers jsonb := '[]'::jsonb;
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

  return jsonb_build_object(
    'blocking_servers', blocking_servers,
    'transferable_servers', '[]'::jsonb
  );
end;
$function$
;

CREATE OR REPLACE FUNCTION public.get_my_channel_unread_context()
 RETURNS TABLE(channel_id bigint, server_id bigint, unread_count bigint)
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $function$
  with my_servers as (
    select sm.server_id
    from public.server_members sm
    where sm.user_id = auth.uid()

    union

    select s.id as server_id
    from public.servers s
    where s.owner_id = auth.uid()
  )
  select
    c.id as channel_id,
    c.server_id,
    count(m.id)::bigint as unread_count
  from public.channels c
  join my_servers ms
    on ms.server_id = c.server_id
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
$function$
;

CREATE OR REPLACE FUNCTION public.get_my_dm_conversations()
 RETURNS TABLE(auth_id uuid, username text, display_name text, avatar_url text, email text, presence text, is_friend boolean, latest_message_at timestamp with time zone, unread_count bigint)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  with accepted_friend_ids as (
    select
      case
        when f.requester_id = auth.uid() then f.recipient_id
        else f.requester_id
      end as user_id
    from public.friendships f
    where
      f.status = 'accepted'
      and (f.requester_id = auth.uid() or f.recipient_id = auth.uid())
  ),
  dm_conversations as (
    select
      case
        when dm.sender_id = auth.uid() then dm.recipient_id
        else dm.sender_id
      end as user_id,
      max(dm.created_at) as latest_message_at
    from public.direct_messages dm
    where
      dm.sender_id = auth.uid()
      or dm.recipient_id = auth.uid()
    group by 1
  ),
  relevant_users as (
    select user_id from accepted_friend_ids
    union
    select user_id from dm_conversations
  ),
  unread_counts as (
    select
      dm.sender_id as user_id,
      count(*)::bigint as unread_count
    from public.direct_messages dm
    left join public.dm_read_state drs
      on drs.other_user_id = dm.sender_id
     and drs.user_id = auth.uid()
    where
      dm.recipient_id = auth.uid()
      and (drs.last_read_at is null or dm.created_at > drs.last_read_at)
    group by dm.sender_id
  )
  select
    u.auth_id,
    u.username,
    u.display_name,
    u.avatar_url,
    u.email,
    u.presence,
    (afi.user_id is not null) as is_friend,
    dc.latest_message_at,
    coalesce(uc.unread_count, 0)::bigint as unread_count
  from relevant_users ru
  join public.users u
    on u.auth_id = ru.user_id
  left join accepted_friend_ids afi
    on afi.user_id = ru.user_id
  left join dm_conversations dc
    on dc.user_id = ru.user_id
  left join unread_counts uc
    on uc.user_id = ru.user_id
  where
    auth.uid() is not null
    and ru.user_id is not null
  order by
    (afi.user_id is not null) desc,
    dc.latest_message_at desc nulls last,
    coalesce(u.display_name, u.username, u.email) asc;
$function$
;

CREATE OR REPLACE FUNCTION public.get_my_server_appearance_preference()
 RETURNS TABLE(user_id uuid, use_server_theme boolean)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
#variable_conflict use_column
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  insert into public.user_settings (user_id)
  values (auth.uid())
  on conflict on constraint user_settings_user_id_key do nothing;

  return query
  select
    us.user_id,
    us.use_server_theme
  from public.user_settings us
  where us.user_id = auth.uid()
  limit 1;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.get_my_servers()
 RETURNS SETOF public.servers
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $function$
  select distinct s.*
  from public.servers s
  left join public.server_members sm
    on sm.server_id = s.id
   and sm.user_id = auth.uid()
  where
    auth.uid() is not null
    and (
      s.owner_id = auth.uid()
      or sm.user_id is not null
    )
  order by s.created_at asc;
$function$
;

CREATE OR REPLACE FUNCTION public.get_my_user_settings()
 RETURNS TABLE(user_id uuid, dm_privacy text, presence text, app_theme text, nsfw_enabled boolean, created_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  insert into public.user_settings (user_id)
  values (auth.uid())
  on conflict (user_id) do nothing;

  return query
  select
    us.user_id,
    us.dm_privacy,
    us.presence,
    us.app_theme,
    us.nsfw_enabled,
    us.created_at
  from public.user_settings us
  where us.user_id = auth.uid()
  limit 1;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.get_post_comments_detailed(p_post_id uuid)
 RETURNS TABLE(id uuid, post_id uuid, author_id uuid, content text, created_at timestamp with time zone, upvotes integer, downvotes integer, my_vote text, author_username text, author_display_name text, author_avatar text)
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $function$
  select
    c.id,
    c.post_id,
    c.author_id,
    c.content,
    c.created_at,
    coalesce(votes.upvotes, 0)::integer as upvotes,
    coalesce(votes.downvotes, 0)::integer as downvotes,
    votes.my_vote,
    coalesce(u.username, 'unknown') as author_username,
    u.display_name as author_display_name,
    u.avatar_url as author_avatar
  from public.post_comments c
  left join public.users u
    on u.auth_id = c.author_id
  left join lateral (
    select
      count(*) filter (where pcv.vote_type = 'up') as upvotes,
      count(*) filter (where pcv.vote_type = 'down') as downvotes,
      max(pcv.vote_type) filter (where pcv.user_id = auth.uid()) as my_vote
    from public.post_comment_votes pcv
    where pcv.comment_id = c.id
  ) votes on true
  where c.post_id = p_post_id
  order by c.created_at asc;
$function$
;

CREATE OR REPLACE FUNCTION public.get_server_feed_posts(p_server_id bigint, p_limit integer DEFAULT 60)
 RETURNS TABLE(id uuid, server_id bigint, author_id uuid, title text, content text, flair_id uuid, flair_name text, flair_color text, created_at timestamp with time zone, author_username text, author_display_name text, author_avatar text, upvotes integer, downvotes integer, my_vote text, comment_count integer)
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $function$
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
      or s.owner_id = auth.uid()
      or sm.user_id is not null
    )
  order by p.created_at desc
  limit least(greatest(coalesce(p_limit, 60), 1), 100);
$function$
;

CREATE OR REPLACE FUNCTION public.get_server_settings_members(p_server_id bigint)
 RETURNS TABLE(id bigint, server_id bigint, user_id uuid, role text, roles text[], username text, display_name text, avatar_url text, email text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
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
$function$
;

CREATE OR REPLACE FUNCTION public.get_visible_feed_posts(p_limit integer DEFAULT 120)
 RETURNS TABLE(id uuid, server_id bigint, author_id uuid, title text, content text, flair_id uuid, flair_name text, flair_color text, created_at timestamp with time zone, server_name text, server_handle text, server_icon text, author_username text, author_display_name text, author_avatar text, feed_reason text, upvotes integer, downvotes integer, my_vote text, comment_count integer)
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $function$
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
    case
      when p.server_id is null then coalesce(u.display_name, u.username, 'Profile')
      else coalesce(s.display_name, s.handle, 'Unknown Server')
    end as server_name,
    case
      when p.server_id is null then null
      else s.handle
    end as server_handle,
    case
      when p.server_id is null then u.avatar_url
      else s.icon_url
    end as server_icon,
    coalesce(u.username, 'unknown') as author_username,
    u.display_name as author_display_name,
    u.avatar_url as author_avatar,
    case
      when p.server_id is null then 'Because you may have missed this profile post'
      when exists (
        select 1
        from public.server_members sm
        where sm.server_id = p.server_id
          and sm.user_id = auth.uid()
      ) then 'From a server you joined'
      else 'Because this server is public'
    end as feed_reason,
    coalesce(votes.upvotes, 0)::integer as upvotes,
    coalesce(votes.downvotes, 0)::integer as downvotes,
    votes.my_vote,
    coalesce(comments.comment_count, 0)::integer as comment_count
  from public.posts p
  left join public.servers s
    on s.id = p.server_id
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
    p.server_id is null
    or (
      s.visibility = 'public'
      and coalesce(s.show_posts_in_global_feed, true)
    )
  order by p.created_at desc
  limit least(greatest(coalesce(p_limit, 120), 1), 150);
$function$
;

CREATE OR REPLACE FUNCTION public.grant_server_tier_role(p_server_id bigint, p_tier_id bigint, p_user_id uuid, p_status text, p_stripe_customer_id text DEFAULT NULL::text, p_stripe_subscription_id text DEFAULT NULL::text, p_current_period_end timestamp with time zone DEFAULT NULL::timestamp with time zone)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
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
$function$
;

CREATE OR REPLACE FUNCTION public.guard_server_owner_membership()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
  owner_count bigint;
  server_exists boolean;
begin
  if tg_op = 'DELETE' then
    select exists (
      select 1
      from public.servers s
      where s.id = old.server_id
    )
    into server_exists;

    if not server_exists then
      return old;
    end if;

    if lower(coalesce(old.role, '')) = 'owner' then
      select count(*)
        into owner_count
      from public.server_members sm
      where sm.server_id = old.server_id
        and lower(coalesce(sm.role, '')) = 'owner';

      if owner_count <= 1 then
        raise exception 'Servers must have at least one owner';
      end if;
    end if;

    return old;
  end if;

  if tg_op = 'UPDATE' then
    if lower(coalesce(old.role, '')) = 'owner'
       and lower(coalesce(new.role, '')) <> 'owner' then
      select count(*)
        into owner_count
      from public.server_members sm
      where sm.server_id = old.server_id
        and lower(coalesce(sm.role, '')) = 'owner';

      if owner_count <= 1 then
        raise exception 'Servers must have at least one owner';
      end if;
    end if;

    return new;
  end if;

  return coalesce(new, old);
end;
$function$
;

CREATE OR REPLACE FUNCTION public.handle_new_user()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
BEGIN
  INSERT INTO public.users (
    auth_id,
    email,
    username,
    display_name,
    age_range,
    nsfw_enabled
  )
  VALUES (
    NEW.id,
    NEW.email,
    NEW.raw_user_meta_data ->> 'username',
    NEW.raw_user_meta_data ->> 'display_name',
    CASE
      WHEN (NEW.raw_user_meta_data ->> 'age_range') IN ('under_13', '13_17', '18_plus')
      THEN (NEW.raw_user_meta_data ->> 'age_range')::age_range_type
      ELSE NULL
    END,
    false
  )
  ON CONFLICT (auth_id) DO NOTHING;
  RETURN NEW;
END;
$function$
;

CREATE OR REPLACE FUNCTION public.has_blocked_profile_term(p_value text, p_context text)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  select exists (
    select 1
    from public.blocked_profile_terms bpt
    where bpt.active
      and p_context = any(bpt.contexts)
      and public.normalize_moderation_text(p_value) like '%' || public.normalize_moderation_text(bpt.term) || '%'
  );
$function$
;

CREATE OR REPLACE FUNCTION public.is_server_admin(p_server_id bigint)
 RETURNS boolean
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  select public.is_server_owner(p_server_id) or exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = auth.uid()
      and lower(coalesce(sm.role, '')) = 'admin'
  );
$function$
;

CREATE OR REPLACE FUNCTION public.is_server_owner(p_server_id bigint)
 RETURNS boolean
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  select exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = auth.uid()
      and lower(coalesce(sm.role, '')) = 'owner'
  );
$function$
;

CREATE OR REPLACE FUNCTION public.leave_server(p_server_id bigint)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
  current_user_id uuid := auth.uid();
  current_member public.server_members%rowtype;
  replacement_owner_id uuid;
  server_primary_owner_id uuid;
begin
  if current_user_id is null then
    raise exception 'Authentication required';
  end if;

  select owner_id
  into server_primary_owner_id
  from public.servers
  where id = p_server_id;

  select *
  into current_member
  from public.server_members
  where server_id = p_server_id
    and user_id = current_user_id;

  if not found and server_primary_owner_id is distinct from current_user_id then
    raise exception 'You are not a member of this server';
  end if;

  select sm.user_id
  into replacement_owner_id
  from public.server_members sm
  where sm.server_id = p_server_id
    and sm.user_id <> current_user_id
    and lower(coalesce(sm.role, '')) = 'owner'
  order by sm.created_at asc, sm.id asc
  limit 1;

  if (
    lower(coalesce(current_member.role, '')) = 'owner'
    or server_primary_owner_id = current_user_id
  ) and replacement_owner_id is null then
    raise exception 'You cannot leave this server because you are the only owner. Add another owner first.';
  end if;

  if server_primary_owner_id = current_user_id then
    update public.servers
    set owner_id = replacement_owner_id
    where id = p_server_id;
  end if;

  delete from public.server_nicknames
  where server_id = p_server_id
    and user_id = current_user_id;

  delete from public.server_members
  where server_id = p_server_id
    and user_id = current_user_id;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.manage_server_channel(p_server_id bigint, p_name text, p_type text DEFAULT 'text'::text, p_position integer DEFAULT NULL::integer, p_tier_id bigint DEFAULT NULL::bigint, p_channel_id bigint DEFAULT NULL::bigint)
 RETURNS public.channels
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
  channel_row public.channels;
  normalized_type text := coalesce(nullif(trim(p_type), ''), 'text');
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  if not public.user_can_manage_channels(p_server_id, auth.uid()) then
    raise exception 'You do not have permission to manage channels';
  end if;

  if p_tier_id is not null and not exists (
    select 1
    from public.subscription_tiers st
    where st.id = p_tier_id
      and st.server_id = p_server_id
  ) then
    raise exception 'Tier does not belong to this server';
  end if;

  if p_channel_id is null then
    insert into public.channels (
      server_id,
      name,
      type,
      position,
      tier_id
    )
    values (
      p_server_id,
      p_name,
      normalized_type,
      coalesce(p_position, 0),
      p_tier_id
    )
    returning * into channel_row;
  else
    update public.channels
    set
      name = p_name,
      type = normalized_type,
      position = coalesce(p_position, position),
      tier_id = p_tier_id
    where id = p_channel_id
      and server_id = p_server_id
    returning * into channel_row;

    if channel_row.id is null then
      raise exception 'Channel not found';
    end if;
  end if;

  return channel_row;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.normalize_moderation_text(p_value text)
 RETURNS text
 LANGUAGE sql
 IMMUTABLE
AS $function$
  select regexp_replace(
    translate(lower(coalesce(p_value, '')), '013457@$!', 'oieastasi'),
    '[^a-z0-9]+',
    '',
    'g'
  );
$function$
;

CREATE OR REPLACE FUNCTION public.protect_builtin_server_roles()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
  server_exists boolean;
begin
  if tg_op = 'DELETE' then
    select exists (
      select 1
      from public.servers s
      where s.id = old.server_id
    )
    into server_exists;

    if not server_exists then
      return old;
    end if;

    if lower(coalesce(old.name, '')) in ('owner', 'member') then
      raise exception 'The % role cannot be deleted', old.name;
    end if;

    return old;
  end if;

  if tg_op = 'UPDATE' then
    if lower(coalesce(old.name, '')) = 'owner' then
      new.name := 'Owner';
      new.permissions := '{"manage_channels": true, "manage_roles": true, "manage_server": true, "kick_members": true, "ban_members": true, "manage_messages": true}'::jsonb;
      new.position := 400;
      new.is_default := true;
    elsif lower(coalesce(old.name, '')) = 'member' then
      new.name := 'Member';
      new.position := 100;
      new.is_default := true;
    end if;

    return new;
  end if;

  return coalesce(new, old);
end;
$function$
;

CREATE OR REPLACE FUNCTION public.set_my_server_appearance_preference(p_use_server_theme boolean)
 RETURNS TABLE(user_id uuid, use_server_theme boolean)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
#variable_conflict use_column
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  insert into public.user_settings (
    user_id,
    use_server_theme
  )
  values (
    auth.uid(),
    coalesce(p_use_server_theme, true)
  )
  on conflict on constraint user_settings_user_id_key do update
    set use_server_theme = excluded.use_server_theme;

  return query
  select
    us.user_id,
    us.use_server_theme
  from public.user_settings us
  where us.user_id = auth.uid()
  limit 1;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.set_updated_at()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
begin
  new.updated_at = timezone('utc', now());
  return new;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.sync_auth_user_profile_metadata()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'auth'
AS $function$
begin
  if new.auth_id is null then
    return new;
  end if;

  update auth.users
  set raw_user_meta_data =
    coalesce(raw_user_meta_data, '{}'::jsonb)
    || jsonb_build_object(
      'username', new.username,
      'display_name', new.display_name
    )
  where id = new.auth_id;

  update auth.identities
  set identity_data =
    coalesce(identity_data, '{}'::jsonb)
    || jsonb_build_object(
      'username', new.username,
      'display_name', new.display_name
    )
  where user_id = new.auth_id;

  return new;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.upsert_my_user_settings(p_dm_privacy text DEFAULT NULL::text, p_presence text DEFAULT NULL::text, p_app_theme text DEFAULT NULL::text, p_nsfw_enabled boolean DEFAULT NULL::boolean)
 RETURNS TABLE(user_id uuid, dm_privacy text, presence text, app_theme text, nsfw_enabled boolean, created_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  insert into public.user_settings (
    user_id,
    dm_privacy,
    presence,
    app_theme,
    nsfw_enabled
  )
  values (
    auth.uid(),
    coalesce(p_dm_privacy, 'everyone'),
    coalesce(p_presence, 'online'),
    coalesce(p_app_theme, 'default'),
    coalesce(p_nsfw_enabled, false)
  )
  on conflict (user_id) do update
    set dm_privacy = coalesce(p_dm_privacy, public.user_settings.dm_privacy),
        presence = coalesce(p_presence, public.user_settings.presence),
        app_theme = coalesce(p_app_theme, public.user_settings.app_theme),
        nsfw_enabled = coalesce(p_nsfw_enabled, public.user_settings.nsfw_enabled);

  return query
  select
    us.user_id,
    us.dm_privacy,
    us.presence,
    us.app_theme,
    us.nsfw_enabled,
    us.created_at
  from public.user_settings us
  where us.user_id = auth.uid()
  limit 1;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.user_can_access_channel(p_channel_id bigint, p_user_id uuid)
 RETURNS boolean
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
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
$function$
;

CREATE OR REPLACE FUNCTION public.user_can_manage_channels(p_server_id bigint, p_user_id uuid DEFAULT auth.uid())
 RETURNS boolean
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  select exists (
    select 1
    from public.servers s
    where s.id = p_server_id
      and s.owner_id = p_user_id
  )
  or exists (
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
$function$
;

CREATE OR REPLACE FUNCTION public.user_can_manage_messages(p_server_id bigint, p_user_id uuid DEFAULT auth.uid())
 RETURNS boolean
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  select exists (
    select 1
    from public.servers s
    where s.id = p_server_id
      and s.owner_id = p_user_id
  )
  or exists (
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
$function$
;

CREATE OR REPLACE FUNCTION public.user_can_view_channel(p_channel_id bigint, p_user_id uuid)
 RETURNS boolean
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
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
$function$
;

CREATE OR REPLACE FUNCTION public.user_has_server_role(p_server_id bigint, p_user_id uuid, p_role_id bigint)
 RETURNS boolean
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
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
$function$
;


