-- Group chat packet encryption support, add-members RPC, and dm_group attachments.

create or replace function public.add_dm_group_chat_members(
  p_group_chat_id uuid,
  p_member_ids uuid[]
)
returns public.dm_group_chats
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_group public.dm_group_chats;
  v_member_id uuid;
  v_distinct_ids uuid[] := array[]::uuid[];
  v_current_count integer;
  v_add_count integer;
begin
  if v_user_id is null then
    raise exception 'Authentication required';
  end if;

  if not public.is_dm_group_member(p_group_chat_id, v_user_id) then
    raise exception 'You are not a member of this group chat';
  end if;

  if p_member_ids is null or coalesce(array_length(p_member_ids, 1), 0) < 1 then
    raise exception 'Select at least one friend to add';
  end if;

  foreach v_member_id in array p_member_ids loop
    if v_member_id is null or v_member_id = v_user_id then
      raise exception 'Invalid group member';
    end if;
    if exists (
      select 1
      from public.dm_group_chat_members m
      where m.group_chat_id = p_group_chat_id
        and m.user_id = v_member_id
    ) then
      raise exception 'One or more users are already in this group chat';
    end if;
    if not v_member_id = any (v_distinct_ids) then
      v_distinct_ids := array_append(v_distinct_ids, v_member_id);
    end if;
  end loop;

  v_add_count := coalesce(array_length(v_distinct_ids, 1), 0);
  if v_add_count < 1 then
    raise exception 'Select at least one friend to add';
  end if;

  select count(*)::integer
    into v_current_count
  from public.dm_group_chat_members m
  where m.group_chat_id = p_group_chat_id;

  if v_current_count + v_add_count > 8 then
    raise exception 'Group chats can include up to eight members total';
  end if;

  foreach v_member_id in array v_distinct_ids loop
    if not exists (
      select 1
      from public.friendships f
      where f.status = 'accepted'
        and (
          (f.requester_id = v_user_id and f.recipient_id = v_member_id)
          or (f.requester_id = v_member_id and f.recipient_id = v_user_id)
        )
    ) then
      raise exception 'You can only add friends to a group chat';
    end if;
  end loop;

  foreach v_member_id in array v_distinct_ids loop
    insert into public.dm_group_chat_members (group_chat_id, user_id)
    values (p_group_chat_id, v_member_id)
    on conflict do nothing;
  end loop;

  select *
    into v_group
  from public.dm_group_chats
  where id = p_group_chat_id;

  return v_group;
end;
$$;

grant execute on function public.add_dm_group_chat_members(uuid, uuid[]) to authenticated;

create or replace function public.get_dm_group_chat_member_ids(p_group_chat_id uuid)
returns uuid[]
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(array_agg(m.user_id order by m.joined_at), array[]::uuid[])
  from public.dm_group_chat_members m
  where m.group_chat_id = p_group_chat_id
    and public.is_dm_group_member(p_group_chat_id, auth.uid());
$$;

grant execute on function public.get_dm_group_chat_member_ids(uuid) to authenticated;

alter table public.message_attachments
  add column if not exists group_chat_id uuid references public.dm_group_chats (id) on delete cascade;

alter table public.message_attachments
  drop constraint if exists message_attachments_context_check;

alter table public.message_attachments
  add constraint message_attachments_context_check
  check (context in ('dm', 'channel', 'dm_group'));

create index if not exists message_attachments_group_chat_idx
  on public.message_attachments (group_chat_id)
  where group_chat_id is not null;

create or replace function public.reserve_message_attachment_upload(
  p_attachment_id text,
  p_context text,
  p_server_id bigint,
  p_channel_id bigint,
  p_recipient_id uuid,
  p_storage_path text,
  p_file_name text,
  p_mime_type text,
  p_size_bytes bigint,
  p_group_chat_id uuid default null
)
returns public.message_attachments
language plpgsql
security definer
set search_path = public, storage
as $$
declare
  current_user_id uuid := auth.uid();
  user_tier text;
  account_upload_limit bigint;
  server_upload_limit_cap bigint;
  server_base_upload_limit bigint := 25 * 1024 * 1024;
  effective_upload_limit bigint;
  account_quota bigint;
  server_quota bigint;
  current_usage bigint;
  channel_server_id bigint;
  server_type text;
  role_upload_limit bigint;
  reserved_row public.message_attachments;
begin
  if current_user_id is null then
    raise exception 'Authentication required.';
  end if;

  if p_size_bytes <= 0 then
    raise exception 'Attachment size is invalid.';
  end if;

  if p_storage_path is null or p_storage_path = '' or p_storage_path not like current_user_id::text || '/%' then
    raise exception 'Attachment storage path must be in your user folder.';
  end if;

  select tier into user_tier
  from public.users
  where auth_id = current_user_id
  limit 1;

  user_tier := public.effective_account_tier(user_tier);

  account_upload_limit := public.account_attachment_upload_limit_bytes(user_tier);

  if p_context = 'dm' then
    effective_upload_limit := account_upload_limit;
    account_quota := public.account_attachment_storage_quota_bytes(user_tier);

    select coalesce(sum(size_bytes), 0)
      into current_usage
    from public.message_attachments
    where owner_id = current_user_id
      and context in ('dm', 'dm_group')
      and status in ('pending', 'attached');

    if current_usage + p_size_bytes > account_quota then
      raise exception 'Attachment storage quota exceeded. Delete older DM attachments or upgrade your key.';
    end if;
  elsif p_context = 'dm_group' then
    if p_group_chat_id is null then
      raise exception 'Group chat is required for group attachments.';
    end if;

    if not public.is_dm_group_member(p_group_chat_id, current_user_id) then
      raise exception 'You cannot upload attachments to this group chat.';
    end if;

    effective_upload_limit := account_upload_limit;
    account_quota := public.account_attachment_storage_quota_bytes(user_tier);

    select coalesce(sum(size_bytes), 0)
      into current_usage
    from public.message_attachments
    where owner_id = current_user_id
      and context in ('dm', 'dm_group')
      and status in ('pending', 'attached');

    if current_usage + p_size_bytes > account_quota then
      raise exception 'Attachment storage quota exceeded. Delete older DM attachments or upgrade your key.';
    end if;
  elsif p_context = 'channel' then
    select c.server_id, s.server_type
      into channel_server_id, server_type
    from public.channels c
    join public.servers s on s.id = c.server_id
    where c.id = p_channel_id
    limit 1;

    if channel_server_id is null or channel_server_id <> p_server_id then
      raise exception 'Channel does not belong to this server.';
    end if;

    if not public.user_can_access_channel(p_channel_id, current_user_id) then
      raise exception 'You cannot upload attachments to this channel.';
    end if;

    server_upload_limit_cap := public.server_attachment_upload_limit_bytes(server_type);
    select greatest(
      coalesce((
        select max(sr.upload_limit_bytes)
        from public.server_roles sr
        where sr.server_id = p_server_id
          and sr.upload_limit_bytes is not null
          and public.user_has_server_role(p_server_id, current_user_id, sr.id)
      ), 0),
      coalesce((
        select max(st.upload_limit_bytes)
        from public.subscription_tiers st
        where st.server_id = p_server_id
          and st.upload_limit_bytes is not null
          and exists (
            select 1
            from public.server_tier_subscriptions sts
            where sts.server_id = st.server_id
              and sts.tier_id = st.id
              and sts.user_id = current_user_id
              and sts.status in ('active', 'trialing')
          )
      ), 0)
    ) into role_upload_limit;

    effective_upload_limit := greatest(
      account_upload_limit,
      server_base_upload_limit,
      least(coalesce(role_upload_limit, 0), server_upload_limit_cap)
    );
    server_quota := public.server_attachment_storage_quota_bytes(server_type);

    select coalesce(sum(size_bytes), 0)
      into current_usage
    from public.message_attachments
    where server_id = p_server_id
      and status in ('pending', 'attached');

    if current_usage + p_size_bytes > server_quota then
      raise exception 'Guild attachment storage quota exceeded. Delete older attachments or upgrade the guild.';
    end if;
  else
    raise exception 'Attachment context is invalid.';
  end if;

  if p_size_bytes > effective_upload_limit then
    raise exception 'Attachment is over the upload limit.';
  end if;

  insert into public.message_attachments (
    attachment_id,
    owner_id,
    context,
    server_id,
    channel_id,
    recipient_id,
    group_chat_id,
    storage_path,
    file_name,
    mime_type,
    size_bytes
  )
  values (
    p_attachment_id,
    current_user_id,
    p_context,
    case when p_context = 'channel' then p_server_id else null end,
    case when p_context = 'channel' then p_channel_id else null end,
    case when p_context = 'dm' then p_recipient_id else null end,
    case when p_context = 'dm_group' then p_group_chat_id else null end,
    p_storage_path,
    coalesce(nullif(p_file_name, ''), 'attachment'),
    coalesce(nullif(p_mime_type, ''), 'application/octet-stream'),
    p_size_bytes
  )
  returning * into reserved_row;

  return reserved_row;
end;
$$;

create or replace function public.finalize_message_attachments(
  p_attachment_ids text[],
  p_context text,
  p_message_id bigint
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  current_user_id uuid := auth.uid();
begin
  if current_user_id is null then
    raise exception 'Authentication required.';
  end if;

  if coalesce(array_length(p_attachment_ids, 1), 0) = 0 then
    return;
  end if;

  if p_context = 'channel' then
    if not exists (
      select 1
      from public.messages m
      where m.id = p_message_id
        and m.sender_id = current_user_id
    ) then
      raise exception 'Message not found.';
    end if;

    update public.message_attachments
       set status = 'attached',
           attached_at = coalesce(attached_at, now()),
           channel_message_id = p_message_id
     where owner_id = current_user_id
       and attachment_id = any(p_attachment_ids)
       and context = 'channel'
       and status = 'pending';
  elsif p_context in ('dm', 'dm_group') then
    if not exists (
      select 1
      from public.direct_messages dm
      where dm.id = p_message_id
        and dm.sender_id = current_user_id
    ) then
      raise exception 'Message not found.';
    end if;

    update public.message_attachments
       set status = 'attached',
           attached_at = coalesce(attached_at, now()),
           direct_message_id = p_message_id
     where owner_id = current_user_id
       and attachment_id = any(p_attachment_ids)
       and context = p_context
       and status = 'pending';
  else
    raise exception 'Attachment context is invalid.';
  end if;
end;
$$;

grant execute on function public.reserve_message_attachment_upload(text, text, bigint, bigint, uuid, text, text, text, bigint, uuid) to authenticated;
