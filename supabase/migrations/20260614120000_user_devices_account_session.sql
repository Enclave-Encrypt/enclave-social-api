-- Link Social MLS devices to Enclave Account sessions for global device management.

alter table public.user_devices
  add column if not exists account_session_id uuid;

create index if not exists user_devices_account_session_id_idx
  on public.user_devices (account_session_id)
  where account_session_id is not null;

drop function if exists public.get_my_devices();

create or replace function public.get_my_devices()
returns table (
  id bigint,
  device_id text,
  label text,
  device_role text,
  parent_device_id bigint,
  storage_scope text,
  account_session_id uuid,
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
    ud.account_session_id,
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

create or replace function public.link_my_device_account_session(
  p_user_device_id bigint,
  p_account_session_id uuid
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_user_device_id is null then
    raise exception 'user_device_id is required';
  end if;

  if p_account_session_id is null then
    raise exception 'account_session_id is required';
  end if;

  update public.user_devices ud
  set account_session_id = p_account_session_id
  where ud.id = p_user_device_id
    and ud.user_id = auth.uid();
end;
$$;

revoke all on function public.link_my_device_account_session(bigint, uuid) from public;
grant execute on function public.link_my_device_account_session(bigint, uuid) to authenticated;
grant execute on function public.get_my_devices() to authenticated;
