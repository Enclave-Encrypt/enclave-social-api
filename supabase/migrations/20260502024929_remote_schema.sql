set check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.check_server_membership(p_server_id bigint, p_user_id uuid)
 RETURNS boolean
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
  select exists (
    select 1
    from public.server_members
    where server_id = p_server_id
      and user_id = p_user_id
  );
$function$
;

CREATE OR REPLACE FUNCTION public.claim_prekey_bundle(p_target_user_id uuid, p_target_device_id text DEFAULT NULL::text)
 RETURNS TABLE(user_device_pk bigint, device_id text, registration_id integer, identity_public_key text, signed_prekey_id integer, signed_prekey_public_key text, signed_prekey_signature text, kyber_prekey_id integer, kyber_prekey_public_key text, kyber_prekey_signature text, one_time_prekey_id integer, one_time_prekey_public_key text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  return query
  with target_device as (
    select
      ud.id as user_device_pk,
      ud.device_id,
      db.registration_id,
      db.identity_public_key,
      db.signed_prekey_id,
      db.signed_prekey_public_key,
      db.signed_prekey_signature,
      db.kyber_prekey_id,
      db.kyber_prekey_public_key,
      db.kyber_prekey_signature
    from public.user_devices ud
    join public.device_bundles db
      on db.user_device_id = ud.id
    where ud.user_id = p_target_user_id
      and ud.is_active = true
      and (p_target_device_id is null or ud.device_id = p_target_device_id)
    order by ud.created_at asc
    limit 1
  ),
  claimed_prekey as (
    update public.device_one_time_prekeys otp
    set
      is_consumed = true,
      consumed_at = timezone('utc', now()),
      claimed_by_user_id = auth.uid()
    where otp.id = (
      select otp2.id
      from public.device_one_time_prekeys otp2
      join target_device td
        on td.user_device_pk = otp2.user_device_id
      where otp2.is_consumed = false
      order by otp2.id asc
      limit 1
    )
    returning otp.user_device_id, otp.key_id, otp.public_key
  )
  select
    td.user_device_pk,
    td.device_id,
    td.registration_id,
    td.identity_public_key,
    td.signed_prekey_id,
    td.signed_prekey_public_key,
    td.signed_prekey_signature,
    td.kyber_prekey_id,
    td.kyber_prekey_public_key,
    td.kyber_prekey_signature,
    cp.key_id as one_time_prekey_id,
    cp.public_key as one_time_prekey_public_key
  from target_device td
  join claimed_prekey cp
    on cp.user_device_id = td.user_device_pk;
end;
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

CREATE OR REPLACE FUNCTION public.get_channel_message_history(p_channel_id bigint, p_before timestamp with time zone DEFAULT NULL::timestamp with time zone, p_limit integer DEFAULT 50)
 RETURNS SETOF public.messages
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $function$
  select m.*
  from public.messages m
  where
    m.channel_id = p_channel_id
    and (p_before is null or m.created_at < p_before)
  order by m.created_at desc
  limit greatest(coalesce(p_limit, 50), 1);
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
  limit greatest(coalesce(p_limit, 50), 1);
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
  limit greatest(coalesce(p_limit, 60), 1);
$function$
;

CREATE OR REPLACE FUNCTION public.get_server_settings_context(p_server_id bigint)
 RETURNS TABLE(id bigint, display_name text, description text, category text, visibility text, rules text, welcome_message text, banner_url text, icon_url text, invite_code text, my_role text, nickname text)
 LANGUAGE sql
 STABLE
 SET search_path TO 'public'
AS $function$
  select
    s.id,
    s.display_name,
    s.description,
    s.category,
    s.visibility,
    s.rules,
    s.welcome_message,
    s.banner_url,
    s.icon_url,
    s.invite_code,
    coalesce(
      case
        when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
        else lower(trim(coalesce(sm.role, 'member')))
      end,
      'member'
    ) as my_role,
    sn.nickname
  from public.servers s
  left join public.server_members sm
    on sm.server_id = s.id
   and sm.user_id = auth.uid()
  left join public.server_nicknames sn
    on sn.server_id = s.id
   and sn.user_id = auth.uid()
  where s.id = p_server_id
  limit 1;
$function$
;

CREATE OR REPLACE FUNCTION public.get_server_settings_members(p_server_id bigint)
 RETURNS TABLE(id bigint, server_id bigint, user_id uuid, role text, roles text[], username text, display_name text, avatar_url text, email text)
 LANGUAGE sql
 STABLE
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
  )
  select
    n.id,
    n.server_id,
    n.user_id,
    n.normalized_role as role,
    array[n.normalized_role]::text[] as roles,
    u.username,
    u.display_name,
    u.avatar_url,
    u.email
  from normalized n
  join public.users u
    on u.auth_id = n.user_id
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
 RETURNS TABLE(id uuid, server_id bigint, author_id uuid, title text, content text, flair_id uuid, flair_name text, flair_color text, created_at timestamp with time zone, server_name text, server_icon text, author_username text, author_display_name text, author_avatar text, upvotes integer, downvotes integer, my_vote text, comment_count integer)
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
    coalesce(s.display_name, s.handle, 'Unknown Server') as server_name,
    s.icon_url as server_icon,
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
    s.visibility = 'public'
    or s.owner_id = auth.uid()
    or sm.user_id is not null
  order by p.created_at desc
  limit greatest(coalesce(p_limit, 120), 1);
$function$
;

CREATE OR REPLACE FUNCTION public.guard_server_owner_membership()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
declare
  owner_count bigint;
begin
  if tg_op = 'DELETE' then
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

CREATE OR REPLACE FUNCTION public.protect_builtin_server_roles()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
AS $function$
begin
  if tg_op = 'DELETE' then
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

CREATE OR REPLACE FUNCTION public.upsert_my_user_settings(p_dm_privacy text DEFAULT NULL::text, p_presence text DEFAULT NULL::text, p_app_theme text DEFAULT NULL::text, p_theme_blur_strength integer DEFAULT NULL::integer, p_nsfw_enabled boolean DEFAULT NULL::boolean)
 RETURNS TABLE(user_id uuid, dm_privacy text, presence text, app_theme text, theme_blur_strength integer, nsfw_enabled boolean, created_at timestamp with time zone)
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
    theme_blur_strength,
    nsfw_enabled
  )
  values (
    auth.uid(),
    coalesce(p_dm_privacy, 'everyone'),
    coalesce(p_presence, 'online'),
    coalesce(p_app_theme, 'default'),
    coalesce(p_theme_blur_strength, 10),
    coalesce(p_nsfw_enabled, false)
  )
  on conflict (user_id) do update
    set dm_privacy = coalesce(p_dm_privacy, public.user_settings.dm_privacy),
        presence = coalesce(p_presence, public.user_settings.presence),
        app_theme = coalesce(p_app_theme, public.user_settings.app_theme),
        theme_blur_strength = coalesce(p_theme_blur_strength, public.user_settings.theme_blur_strength),
        nsfw_enabled = coalesce(p_nsfw_enabled, public.user_settings.nsfw_enabled);

  return query
  select
    us.user_id,
    us.dm_privacy,
    us.presence,
    us.app_theme,
    us.theme_blur_strength,
    us.nsfw_enabled,
    us.created_at
  from public.user_settings us
  where us.user_id = auth.uid()
  limit 1;
end;
$function$
;


