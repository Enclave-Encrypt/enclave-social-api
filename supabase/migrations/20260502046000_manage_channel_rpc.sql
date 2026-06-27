create or replace function public.manage_server_channel(
  p_server_id bigint,
  p_name text,
  p_type text default 'text',
  p_position integer default null,
  p_tier_id bigint default null,
  p_channel_id bigint default null
)
returns public.channels
language plpgsql
security definer
set search_path to public
as $$
declare
  channel_row public.channels;
  normalized_type text := coalesce(nullif(trim(p_type), ''), 'text');
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  if not public.user_can_manage_channels(p_server_id, auth.uid()) then
    raise exception 'You do not have permission to manage channels';
  end if;

  if p_tier_id is not null and not exists (
    select 1
    from public.subscription_tiers st
    where st.id = p_tier_id
      and st.server_id = p_server_id
  ) then
    raise exception 'Tier does not belong to this server';
  end if;

  if p_channel_id is null then
    insert into public.channels (
      server_id,
      name,
      type,
      position,
      tier_id
    )
    values (
      p_server_id,
      p_name,
      normalized_type,
      coalesce(p_position, 0),
      p_tier_id
    )
    returning * into channel_row;
  else
    update public.channels
    set
      name = p_name,
      type = normalized_type,
      position = coalesce(p_position, position),
      tier_id = p_tier_id
    where id = p_channel_id
      and server_id = p_server_id
    returning * into channel_row;

    if channel_row.id is null then
      raise exception 'Channel not found';
    end if;
  end if;

  return channel_row;
end;
$$;
