create or replace function public.claim_prekey_bundle(
  p_target_user_id uuid,
  p_target_device_id text default null
)
returns table (
  user_device_pk bigint,
  device_id text,
  registration_id integer,
  identity_public_key text,
  signed_prekey_id integer,
  signed_prekey_public_key text,
  signed_prekey_signature text,
  kyber_prekey_id integer,
  kyber_prekey_public_key text,
  kyber_prekey_signature text,
  one_time_prekey_id integer,
  one_time_prekey_public_key text
)
language plpgsql
security definer
set search_path = public
as $$
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
$$;

grant execute on function public.claim_prekey_bundle(uuid, text) to authenticated;
