-- Relink legacy Social rows (public.users + server_members, etc.) when the same email
-- signs in through Enclave Account with a different auth.users id.

create or replace function public.rewrite_auth_user_references(p_old_id uuid, p_new_id uuid)
returns void
language plpgsql
security definer
set search_path = public, auth, storage
as $$
declare
  r record;
begin
  if p_old_id is null or p_new_id is null or p_old_id = p_new_id then
    return;
  end if;

  for r in
    select
      c.conrelid::regclass as table_name,
      a.attname as column_name
    from pg_constraint c
    join pg_attribute a
      on a.attrelid = c.conrelid
     and a.attnum = any (c.conkey)
     and not a.attisdropped
    join pg_class ref on ref.oid = c.confrelid
    join pg_namespace nref on nref.oid = ref.relnamespace
    where c.contype = 'f'
      and nref.nspname = 'auth'
      and ref.relname = 'users'
      and cardinality(c.conkey) = 1
  loop
    execute format(
      'update %s set %I = $1 where %I = $2',
      r.table_name,
      r.column_name,
      r.column_name
    )
    using p_new_id, p_old_id;
  end loop;

  for r in
    select
      c.conrelid::regclass as table_name,
      a.attname as column_name
    from pg_constraint c
    join pg_attribute a
      on a.attrelid = c.conrelid
     and a.attnum = any (c.conkey)
     and not a.attisdropped
    join pg_class ref on ref.oid = c.confrelid
    join pg_namespace nref on nref.oid = ref.relnamespace
    where c.contype = 'f'
      and nref.nspname = 'public'
      and ref.relname = 'users'
      and cardinality(c.conkey) = 1
      and c.conrelid::regclass::text <> 'public.users'
  loop
    execute format(
      'update %s set %I = $1 where %I = $2',
      r.table_name,
      r.column_name,
      r.column_name
    )
    using p_new_id, p_old_id;
  end loop;

  update storage.objects
  set owner_id = p_new_id::text
  where owner_id = p_old_id::text;
end;
$$;

create or replace function public.ensure_auth_users_row_for_relink(
  p_new_id uuid,
  p_old_id uuid,
  p_email text
)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  copied boolean := false;
begin
  if exists (select 1 from auth.users where id = p_new_id) then
    return;
  end if;

  insert into auth.users (
    id,
    instance_id,
    aud,
    role,
    email,
    encrypted_password,
    email_confirmed_at,
    raw_app_meta_data,
    raw_user_meta_data,
    created_at,
    updated_at,
    is_sso_user
  )
  select
    p_new_id,
    u.instance_id,
    u.aud,
    u.role,
    coalesce(nullif(trim(p_email), ''), u.email),
    null,
    coalesce(u.email_confirmed_at, now()),
    coalesce(u.raw_app_meta_data, '{}'::jsonb),
    coalesce(u.raw_user_meta_data, '{}'::jsonb),
    now(),
    now(),
    coalesce(u.is_sso_user, false)
  from auth.users u
  where u.id = p_old_id;

  get diagnostics copied = row_count;
  if copied > 0 then
    return;
  end if;

  insert into auth.users (
    instance_id,
    id,
    aud,
    role,
    email,
    email_confirmed_at,
    created_at,
    updated_at
  )
  values (
    '00000000-0000-0000-0000-000000000000',
    p_new_id,
    'authenticated',
    'authenticated',
    nullif(trim(p_email), ''),
    now(),
    now(),
    now()
  );
end;
$$;

create or replace function public.reconcile_account_auth_identity()
returns jsonb
language plpgsql
security definer
set search_path = public, auth, storage
as $$
declare
  new_id uuid := auth.uid();
  jwt_email text := nullif(trim(lower(coalesce(auth.jwt() ->> 'email', ''))), '');
  legacy public.users%rowtype;
  old_id uuid;
begin
  if new_id is null or jwt_email is null then
    return jsonb_build_object('ok', false, 'reason', 'not_authenticated');
  end if;

  select u.*
  into legacy
  from public.users u
  where lower(trim(coalesce(u.email, ''))) = jwt_email
    and u.auth_id is distinct from new_id
  order by u.created_at asc nulls last
  limit 1;

  if not found then
    return jsonb_build_object(
      'ok', true,
      'relinked', false,
      'auth_id', new_id::text
    );
  end if;

  old_id := legacy.auth_id;

  delete from public.users pu
  where pu.auth_id = new_id
    and not exists (
      select 1
      from public.server_members sm
      where sm.user_id = new_id
    );

  perform public.ensure_auth_users_row_for_relink(new_id, old_id, jwt_email);
  perform public.rewrite_auth_user_references(old_id, new_id);

  delete from auth.users where id = old_id;

  return jsonb_build_object(
    'ok', true,
    'relinked', true,
    'auth_id', new_id::text,
    'previous_auth_id', old_id::text,
    'username', legacy.username
  );
exception
  when others then
    return jsonb_build_object(
      'ok', false,
      'relinked', false,
      'reason', sqlerrm
    );
end;
$$;

revoke all on function public.rewrite_auth_user_references(uuid, uuid) from public;
revoke all on function public.ensure_auth_users_row_for_relink(uuid, uuid, text) from public;
revoke all on function public.reconcile_account_auth_identity() from public;

grant execute on function public.reconcile_account_auth_identity() to authenticated;
