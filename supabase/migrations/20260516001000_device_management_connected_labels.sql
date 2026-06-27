-- Follow-up for databases that already ran the initial device management migration.
-- Adds richer connected-client details to the listing RPC and allows cleanup of
-- already-revoked device rows.

alter table public.user_devices
  add column if not exists hidden_at timestamptz,
  add column if not exists blacklisted_at timestamptz;

drop table if exists public.user_device_revocations;

drop function if exists public.get_my_devices();

create or replace function public.get_my_devices()
returns table (
  id bigint,
  device_id text,
  label text,
  device_role text,
  parent_device_id bigint,
  storage_scope text,
  created_at timestamptz,
  last_seen_at timestamptz,
  last_user_agent text,
  is_active boolean,
  revoked_at timestamptz,
  blacklisted_at timestamptz,
  available_key_packages bigint,
  active_group_memberships bigint
)
language sql
security definer
set search_path = public
as $$
  select
    ud.id,
    ud.device_id,
    ud.label,
    ud.device_role,
    ud.parent_device_id,
    ud.storage_scope,
    ud.created_at,
    ud.last_seen_at,
    ud.last_user_agent,
    ud.is_active,
    ud.revoked_at,
    ud.blacklisted_at,
    (
      select count(*)
      from public.mls_key_packages mkp
      where mkp.user_device_id = ud.id
        and mkp.is_consumed = false
    ) as available_key_packages,
    (
      select count(*)
      from public.mls_group_members mgm
      where mgm.user_device_id = ud.id
        and mgm.membership_status = 'active'
    ) as active_group_memberships
  from public.user_devices ud
  where ud.user_id = auth.uid()
    and ud.hidden_at is null
  order by
    ud.is_active desc,
    ud.revoked_at desc nulls first,
    ud.last_seen_at desc nulls last,
    ud.created_at desc;
$$;

create or replace function public.delete_my_revoked_device(p_user_device_id bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  target_record public.user_devices%rowtype;
begin
  select *
    into target_record
  from public.user_devices ud
  where ud.id = p_user_device_id;

  if target_record.user_id is distinct from auth.uid() then
    raise exception 'Device not found';
  end if;

  if target_record.is_active = true and target_record.revoked_at is null then
    raise exception 'Only revoked devices can be deleted';
  end if;

  update public.user_devices
  set hidden_at = coalesce(hidden_at, timezone('utc', now()))
  where id = p_user_device_id
    and user_id = auth.uid();
end;
$$;

create or replace function public.revoke_my_device(p_user_device_id bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  target_record public.user_devices%rowtype;
begin
  select *
    into target_record
  from public.user_devices ud
  where ud.id = p_user_device_id;

  if target_record.user_id is distinct from auth.uid() then
    raise exception 'Device not found';
  end if;

  update public.user_devices
  set
    is_active = false,
    revoked_at = coalesce(revoked_at, timezone('utc', now()))
  where id = p_user_device_id
    and user_id = auth.uid();

  update public.mls_key_packages
  set
    is_consumed = true,
    consumed_at = coalesce(consumed_at, timezone('utc', now()))
  where user_device_id = p_user_device_id
    and is_consumed = false;

  update public.user_device_key_derivations
  set revoked_at = coalesce(revoked_at, timezone('utc', now()))
  where user_id = auth.uid()
    and (primary_device_id = p_user_device_id or secondary_device_id = p_user_device_id)
    and revoked_at is null;
end;
$$;

create or replace function public.reactivate_my_device(p_user_device_id bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  target_record public.user_devices%rowtype;
begin
  select *
    into target_record
  from public.user_devices ud
  where ud.id = p_user_device_id;

  if target_record.user_id is distinct from auth.uid() then
    raise exception 'Device not found';
  end if;

  update public.user_devices
  set
    is_active = true,
    revoked_at = null,
    blacklisted_at = null,
    hidden_at = null,
    last_seen_at = timezone('utc', now())
  where id = p_user_device_id
    and user_id = auth.uid();
end;
$$;

create or replace function public.blacklist_my_device(p_user_device_id bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  target_record public.user_devices%rowtype;
begin
  select *
    into target_record
  from public.user_devices ud
  where ud.id = p_user_device_id;

  if target_record.user_id is distinct from auth.uid() then
    raise exception 'Device not found';
  end if;

  update public.user_devices
  set
    is_active = false,
    revoked_at = coalesce(revoked_at, timezone('utc', now())),
    blacklisted_at = coalesce(blacklisted_at, timezone('utc', now()))
  where id = p_user_device_id
    and user_id = auth.uid();

  update public.mls_key_packages
  set
    is_consumed = true,
    consumed_at = coalesce(consumed_at, timezone('utc', now()))
  where user_device_id = p_user_device_id
    and is_consumed = false;

  update public.user_device_key_derivations
  set revoked_at = coalesce(revoked_at, timezone('utc', now()))
  where user_id = auth.uid()
    and (primary_device_id = p_user_device_id or secondary_device_id = p_user_device_id)
    and revoked_at is null;
end;
$$;

grant execute on function public.get_my_devices() to authenticated;
grant execute on function public.revoke_my_device(bigint) to authenticated;
grant execute on function public.reactivate_my_device(bigint) to authenticated;
grant execute on function public.blacklist_my_device(bigint) to authenticated;
grant execute on function public.delete_my_revoked_device(bigint) to authenticated;
