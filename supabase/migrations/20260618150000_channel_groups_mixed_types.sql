-- Channel groups are type-agnostic: any channel can belong to any group.

create or replace function public.manage_channel_category(
  p_server_id bigint,
  p_name text,
  p_channel_type text default 'text',
  p_position integer default null,
  p_category_id bigint default null,
  p_delete boolean default false
)
returns public.channel_categories
language plpgsql
security definer
set search_path to public
as $$
declare
  category_row public.channel_categories;
  fallback_category_id bigint;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  if not public.user_can_manage_channels(p_server_id, auth.uid()) then
    raise exception 'You do not have permission to manage channel groups';
  end if;

  perform public.ensure_default_channel_categories(p_server_id);

  if p_delete then
    if p_category_id is null then
      raise exception 'Category id required';
    end if;

    select cc.*
    into category_row
    from public.channel_categories cc
    where cc.id = p_category_id
      and cc.server_id = p_server_id;

    if category_row.id is null then
      raise exception 'Channel group not found';
    end if;

    select cc.id
    into fallback_category_id
    from public.channel_categories cc
    where cc.server_id = p_server_id
      and cc.id <> category_row.id
    order by cc.position asc, cc.id asc
    limit 1;

    if fallback_category_id is null then
      raise exception 'Cannot delete the last channel group';
    end if;

    update public.channels
    set category_id = fallback_category_id
    where category_id = category_row.id;

    delete from public.channel_categories
    where id = category_row.id;

    return category_row;
  end if;

  if p_category_id is null then
    insert into public.channel_categories (
      server_id,
      name,
      channel_type,
      position
    )
    values (
      p_server_id,
      trim(p_name),
      'text',
      coalesce(
        p_position,
        (
          select coalesce(max(cc.position), -1) + 1
          from public.channel_categories cc
          where cc.server_id = p_server_id
        )
      )
    )
    returning * into category_row;
  else
    update public.channel_categories
    set
      name = trim(p_name),
      position = coalesce(p_position, position)
    where id = p_category_id
      and server_id = p_server_id
    returning * into category_row;

    if category_row.id is null then
      raise exception 'Channel group not found';
    end if;
  end if;

  return category_row;
end;
$$;

drop function if exists public.manage_server_channel(
  bigint,
  text,
  text,
  integer,
  bigint,
  bigint
);

create or replace function public.manage_server_channel(
  p_server_id bigint,
  p_name text,
  p_type text default 'text',
  p_position integer default null,
  p_tier_id bigint default null,
  p_channel_id bigint default null,
  p_category_id bigint default null
)
returns public.channels
language plpgsql
security definer
set search_path to public
as $$
declare
  channel_row public.channels;
  normalized_type text := public.normalize_channel_type(p_type);
  resolved_category_id bigint;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  if not public.user_can_manage_channels(p_server_id, auth.uid()) then
    raise exception 'You do not have permission to manage channels';
  end if;

  perform public.ensure_default_channel_categories(p_server_id);

  if p_tier_id is not null and not exists (
    select 1
    from public.subscription_tiers st
    where st.id = p_tier_id
      and st.server_id = p_server_id
  ) then
    raise exception 'Tier does not belong to this server';
  end if;

  resolved_category_id := p_category_id;
  if resolved_category_id is not null and not exists (
    select 1
    from public.channel_categories cc
    where cc.id = resolved_category_id
      and cc.server_id = p_server_id
  ) then
    raise exception 'Channel group not found';
  end if;

  if resolved_category_id is null then
    resolved_category_id := public.default_channel_category_id(
      p_server_id,
      normalized_type
    );
  end if;

  if p_channel_id is null then
    insert into public.channels (
      server_id,
      name,
      type,
      position,
      tier_id,
      category_id
    )
    values (
      p_server_id,
      p_name,
      normalized_type,
      coalesce(p_position, 0),
      p_tier_id,
      resolved_category_id
    )
    returning * into channel_row;
  else
    update public.channels
    set
      name = p_name,
      type = normalized_type,
      position = coalesce(p_position, position),
      tier_id = p_tier_id,
      category_id = coalesce(resolved_category_id, category_id)
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
