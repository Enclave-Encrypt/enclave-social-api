-- Only rotate channel keys for genuinely new members on forward-encryption servers.
-- Re-running handle_server_join_key_access when an existing member opens a channel
-- on another device was rotating keys and raising their epoch floor, which made
-- messages sent from other devices unreadable.

create or replace function public.handle_server_join_key_access(
  p_server_id   bigint,
  p_new_user_id uuid
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_forward     boolean;
  v_channel     record;
  v_new_epoch   bigint;
  v_new_key     text;
  v_first_epoch bigint;
begin
  select coalesce(forward_encryption, false) into v_forward
  from public.servers where id = p_server_id;

  for v_channel in
    select id from public.channels where server_id = p_server_id
  loop
    if v_forward then
      if exists (
        select 1
        from public.member_channel_key_access mka
        where mka.user_id = p_new_user_id
          and mka.channel_id = v_channel.id
      ) then
        continue;
      end if;

      v_new_key := encode(gen_random_bytes(32), 'base64');

      insert into public.channel_key_epochs (channel_id, server_id, key_base64, created_by_user_id)
      values (v_channel.id, p_server_id, v_new_key, p_new_user_id)
      returning id into v_new_epoch;

      update public.mls_channel_state_snapshots
      set snapshot_payload = jsonb_set(
        jsonb_set(coalesce(snapshot_payload, '{}'), '{channel_key_base64}', to_jsonb(v_new_key)),
        '{current_key_epoch_id}', to_jsonb(v_new_epoch)
      )
      where channel_id = v_channel.id;

      insert into public.member_channel_key_access (user_id, channel_id, earliest_epoch_id)
      values (p_new_user_id, v_channel.id, v_new_epoch)
      on conflict (user_id, channel_id) do update
        set earliest_epoch_id = excluded.earliest_epoch_id;
    else
      select min(id) into v_first_epoch
      from public.channel_key_epochs
      where channel_id = v_channel.id;

      if v_first_epoch is not null then
        insert into public.member_channel_key_access (user_id, channel_id, earliest_epoch_id)
        values (p_new_user_id, v_channel.id, v_first_epoch)
        on conflict (user_id, channel_id) do nothing;
      end if;
    end if;
  end loop;
end;
$$;
