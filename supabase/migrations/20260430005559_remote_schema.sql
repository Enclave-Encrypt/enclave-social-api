alter table "public"."channel_read_state" add constraint "channel_read_state_user_id_channel_id_key" UNIQUE using index "channel_read_state_user_id_channel_id_key";

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

  delete from storage.objects
  where owner_id = current_user_id::text
    and bucket_id = 'avatars';

  delete from auth.users
  where id = current_user_id;

  return jsonb_build_object(
    'deleted', true,
    'transferred_servers', 0
  );
end;
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


