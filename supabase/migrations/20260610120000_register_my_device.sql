-- Register or refresh the caller's MLS device row without relying on direct client INSERT RLS.

create or replace function public.register_my_device(
  p_device_id text,
  p_label text default null,
  p_device_role text default 'secondary',
  p_storage_scope text default 'browser_session',
  p_last_user_agent text default null
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  target_record public.user_devices%rowtype;
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if nullif(trim(p_device_id), '') is null then
    raise exception 'device_id is required';
  end if;

  select *
    into target_record
  from public.user_devices ud
  where ud.user_id = auth.uid()
    and ud.device_id = p_device_id;

  if target_record.id is not null then
    if target_record.blacklisted_at is not null then
      raise exception 'This device has been blacklisted.';
    end if;

    if target_record.revoked_at is not null then
      raise exception 'This device has been revoked. Clear local app data and sign in again to create a new device key.';
    end if;

    update public.user_devices ud
    set
      label = coalesce(nullif(trim(p_label), ''), ud.label),
      device_role = coalesce(nullif(trim(p_device_role), ''), ud.device_role),
      storage_scope = coalesce(nullif(trim(p_storage_scope), ''), ud.storage_scope),
      last_user_agent = coalesce(p_last_user_agent, ud.last_user_agent),
      last_seen_at = timezone('utc', now()),
      is_active = true
    where ud.id = target_record.id
      and ud.user_id = auth.uid();

    return target_record.id;
  end if;

  insert into public.user_devices (
    user_id,
    device_id,
    label,
    device_role,
    storage_scope,
    last_user_agent,
    last_seen_at,
    is_active
  )
  values (
    auth.uid(),
    p_device_id,
    nullif(trim(p_label), ''),
    coalesce(nullif(trim(p_device_role), ''), 'secondary'),
    coalesce(nullif(trim(p_storage_scope), ''), 'browser_session'),
    p_last_user_agent,
    timezone('utc', now()),
    true
  )
  returning id into target_record.id;

  return target_record.id;
end;
$$;

revoke all on function public.register_my_device(text, text, text, text, text) from public;
grant execute on function public.register_my_device(text, text, text, text, text) to authenticated;
