-- Remove wrapped secondary-key history grants; devices receive MLS keys via standard membership sync.

drop function if exists public.get_my_device_key_derivation(bigint);
drop function if exists public.upsert_my_device_key_derivation(bigint, bigint, text);
drop function if exists public.publish_device_history_receiver_key(bigint, text);

drop table if exists public.user_device_key_derivations;

alter table public.user_devices
  drop column if exists history_receiver_public_key;

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
end;
$$;

grant execute on function public.revoke_my_device(bigint) to authenticated;
grant execute on function public.blacklist_my_device(bigint) to authenticated;
