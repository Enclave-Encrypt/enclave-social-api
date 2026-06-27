-- Remove the incomplete primary-device/history-key experiment.
-- The live app does not reference this table/function, and the function depends
-- on tables that are not present in the managed schema.

drop function if exists public.setup_primary_history_device(
  bigint,
  text,
  text
);

drop table if exists public.user_device_history_grants;
