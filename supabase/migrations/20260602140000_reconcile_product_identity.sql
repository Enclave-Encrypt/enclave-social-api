-- Cross-app identity: parameterized product slug + migrate from Account registry hint.

create or replace function public.migrate_product_identity(
  p_product text,
  p_legacy_user_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = public, auth, storage
as $$
declare
  new_id uuid := auth.uid();
  jwt_email text := nullif(trim(lower(coalesce(auth.jwt() ->> 'email', ''))), '');
  legacy public.users%rowtype;
begin
  if new_id is null or jwt_email is null or p_legacy_user_id is null then
    return jsonb_build_object('ok', false, 'reason', 'not_authenticated');
  end if;

  if p_legacy_user_id = new_id then
    return jsonb_build_object(
      'ok', true,
      'relinked', false,
      'auth_id', new_id::text,
      'product', p_product
    );
  end if;

  select u.*
  into legacy
  from public.users u
  where u.auth_id = p_legacy_user_id
    and lower(trim(coalesce(u.email, ''))) = jwt_email
  limit 1;

  if not found then
    return jsonb_build_object('ok', false, 'reason', 'legacy_profile_not_found_for_email');
  end if;

  delete from public.users pu
  where pu.auth_id = new_id
    and not exists (
      select 1
      from public.server_members sm
      where sm.user_id = new_id
    );

  perform public.ensure_auth_users_row_for_relink(new_id, p_legacy_user_id, jwt_email);
  perform public.rewrite_auth_user_references(p_legacy_user_id, new_id);
  delete from auth.users where id = p_legacy_user_id;

  return jsonb_build_object(
    'ok', true,
    'relinked', true,
    'product', p_product,
    'auth_id', new_id::text,
    'previous_auth_id', p_legacy_user_id::text,
    'username', legacy.username
  );
exception
  when others then
    return jsonb_build_object('ok', false, 'relinked', false, 'reason', sqlerrm);
end;
$$;

create or replace function public.reconcile_product_identity(p_product text)
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
      'auth_id', new_id::text,
      'product', p_product
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
    'product', p_product,
    'auth_id', new_id::text,
    'previous_auth_id', old_id::text,
    'username', legacy.username
  );
exception
  when others then
    return jsonb_build_object('ok', false, 'relinked', false, 'reason', sqlerrm);
end;
$$;

create or replace function public.reconcile_account_auth_identity()
returns jsonb
language sql
security definer
set search_path = public
as $$
  select public.reconcile_product_identity('social');
$$;

revoke all on function public.migrate_product_identity(text, uuid) from public;
revoke all on function public.reconcile_product_identity(text) from public;

grant execute on function public.migrate_product_identity(text, uuid) to authenticated;
grant execute on function public.reconcile_product_identity(text) to authenticated;
grant execute on function public.reconcile_account_auth_identity() to authenticated;
