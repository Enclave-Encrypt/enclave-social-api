-- Remove the unused pre-MLS E2EE Phase 1 schema only if it is empty.
-- Current app code uses the MLS tables instead. This migration deliberately
-- aborts before dropping anything if historical rows still exist.

do $$
declare
  device_bundle_count bigint;
  one_time_prekey_count bigint;
  device_envelope_count bigint;
begin
  select count(*) into device_bundle_count
  from public.device_bundles;

  select count(*) into one_time_prekey_count
  from public.device_one_time_prekeys;

  select count(*) into device_envelope_count
  from public.direct_message_device_envelopes;

  if device_bundle_count > 0
    or one_time_prekey_count > 0
    or device_envelope_count > 0
  then
    raise exception
      'Legacy E2EE Phase 1 tables are not empty: device_bundles=%, device_one_time_prekeys=%, direct_message_device_envelopes=%',
      device_bundle_count,
      one_time_prekey_count,
      device_envelope_count;
  end if;
end $$;

drop function if exists public.claim_prekey_bundle(uuid, text);

drop table if exists public.direct_message_device_envelopes;
drop table if exists public.device_one_time_prekeys;
drop table if exists public.device_bundles;
