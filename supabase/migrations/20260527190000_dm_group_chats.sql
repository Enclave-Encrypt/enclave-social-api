-- Group direct message chats (creator + up to 7 other members).

create table if not exists public.dm_group_chats (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  created_by uuid not null references auth.users (id) on delete cascade,
  name text not null,
  constraint dm_group_chats_name_not_blank check (char_length(trim(name)) > 0)
);

create table if not exists public.dm_group_chat_members (
  group_chat_id uuid not null references public.dm_group_chats (id) on delete cascade,
  user_id uuid not null references auth.users (id) on delete cascade,
  joined_at timestamptz not null default now(),
  primary key (group_chat_id, user_id)
);

create index if not exists dm_group_chat_members_user_idx
  on public.dm_group_chat_members (user_id, group_chat_id);

alter table public.direct_messages
  add column if not exists group_chat_id uuid references public.dm_group_chats (id) on delete cascade;

create index if not exists direct_messages_group_chat_created_at_idx
  on public.direct_messages (group_chat_id, created_at desc)
  where group_chat_id is not null;

create table if not exists public.dm_group_read_state (
  user_id uuid not null references auth.users (id) on delete cascade,
  group_chat_id uuid not null references public.dm_group_chats (id) on delete cascade,
  last_read_at timestamptz not null default now(),
  primary key (user_id, group_chat_id)
);

create or replace function public.is_dm_group_member(p_group_chat_id uuid, p_user_id uuid default auth.uid())
returns boolean
language sql
stable
security definer
set search_path to public
as $$
  select exists (
    select 1
    from public.dm_group_chat_members m
    where m.group_chat_id = p_group_chat_id
      and m.user_id = p_user_id
  );
$$;

create or replace function public.create_dm_group_chat(
  p_member_ids uuid[],
  p_name text default null
)
returns public.dm_group_chats
language plpgsql
security definer
set search_path to public
as $$
declare
  v_user_id uuid := auth.uid();
  v_group public.dm_group_chats;
  v_member_id uuid;
  v_distinct_ids uuid[] := array[]::uuid[];
  v_trimmed_name text;
  v_default_name text;
begin
  if v_user_id is null then
    raise exception 'Authentication required';
  end if;

  if p_member_ids is null or coalesce(array_length(p_member_ids, 1), 0) < 1 then
    raise exception 'Select at least one friend for a group chat';
  end if;

  if coalesce(array_length(p_member_ids, 1), 0) > 7 then
    raise exception 'Group chats can include up to seven other friends';
  end if;

  foreach v_member_id in array p_member_ids loop
    if v_member_id is null or v_member_id = v_user_id then
      raise exception 'Invalid group member';
    end if;
    if not v_member_id = any (v_distinct_ids) then
      v_distinct_ids := array_append(v_distinct_ids, v_member_id);
    end if;
  end loop;

  if coalesce(array_length(v_distinct_ids, 1), 0) < 1 then
    raise exception 'Select at least one friend for a group chat';
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
      raise exception 'All group members must be your friends';
    end if;
  end loop;

  v_trimmed_name := nullif(trim(coalesce(p_name, '')), '');
  if v_trimmed_name is null then
    select string_agg(coalesce(u.display_name, u.username, 'Friend'), ', ' order by coalesce(u.display_name, u.username))
    into v_default_name
    from public.users u
    where u.auth_id = any (v_distinct_ids);
    v_trimmed_name := left(coalesce(v_default_name, 'Group chat'), 80);
  else
    v_trimmed_name := left(v_trimmed_name, 80);
  end if;

  insert into public.dm_group_chats (created_by, name)
  values (v_user_id, v_trimmed_name)
  returning * into v_group;

  insert into public.dm_group_chat_members (group_chat_id, user_id)
  values (v_group.id, v_user_id)
  on conflict do nothing;

  foreach v_member_id in array v_distinct_ids loop
    insert into public.dm_group_chat_members (group_chat_id, user_id)
    values (v_group.id, v_member_id)
    on conflict do nothing;
  end loop;

  return v_group;
end;
$$;

create or replace function public.get_my_dm_group_chats()
returns table (
  group_chat_id uuid,
  name text,
  created_at timestamptz,
  member_count bigint,
  latest_message_at timestamptz,
  unread_count bigint
)
language sql
stable
security definer
set search_path to public
as $$
  with my_groups as (
    select m.group_chat_id
    from public.dm_group_chat_members m
    where m.user_id = auth.uid()
  ),
  unread as (
    select
      dm.group_chat_id,
      count(*)::bigint as unread_count
    from public.direct_messages dm
    left join public.dm_group_read_state rs
      on rs.group_chat_id = dm.group_chat_id
     and rs.user_id = auth.uid()
    where
      dm.group_chat_id is not null
      and dm.sender_id is distinct from auth.uid()
      and (rs.last_read_at is null or dm.created_at > rs.last_read_at)
    group by dm.group_chat_id
  ),
  latest as (
    select
      dm.group_chat_id,
      max(dm.created_at) as latest_message_at
    from public.direct_messages dm
    where dm.group_chat_id is not null
    group by dm.group_chat_id
  )
  select
    g.id as group_chat_id,
    g.name,
    g.created_at,
    (
      select count(*)::bigint
      from public.dm_group_chat_members gm
      where gm.group_chat_id = g.id
    ) as member_count,
    l.latest_message_at,
    coalesce(u.unread_count, 0)::bigint as unread_count
  from my_groups mg
  join public.dm_group_chats g on g.id = mg.group_chat_id
  left join latest l on l.group_chat_id = g.id
  left join unread u on u.group_chat_id = g.id
  where auth.uid() is not null
  order by l.latest_message_at desc nulls last, g.created_at desc;
$$;

create or replace function public.get_dm_group_message_history(
  p_group_chat_id uuid,
  p_before timestamptz default null,
  p_limit integer default 50
)
returns setof public.direct_messages
language sql
stable
security definer
set search_path to public
as $$
  select dm.*
  from public.direct_messages dm
  where
    dm.group_chat_id = p_group_chat_id
    and public.is_dm_group_member(p_group_chat_id, auth.uid())
    and (p_before is null or dm.created_at < p_before)
  order by dm.created_at desc
  limit greatest(coalesce(p_limit, 50), 1);
$$;

create or replace function public.send_dm_group_message(
  p_group_chat_id uuid,
  p_plaintext text
)
returns public.direct_messages
language plpgsql
security definer
set search_path to public
as $$
declare
  v_user_id uuid := auth.uid();
  v_row public.direct_messages;
  v_body text := trim(coalesce(p_plaintext, ''));
begin
  if v_user_id is null then
    raise exception 'Authentication required';
  end if;

  if not public.is_dm_group_member(p_group_chat_id, v_user_id) then
    raise exception 'You are not a member of this group chat';
  end if;

  if v_body = '' then
    raise exception 'Message cannot be empty';
  end if;

  insert into public.direct_messages (
    sender_id,
    recipient_id,
    group_chat_id,
    ciphertext,
    mls_message_type,
    mls_message
  )
  values (
    v_user_id,
    null,
    p_group_chat_id,
    '[group]',
    'group_plaintext',
    jsonb_build_object('plaintext', v_body)
  )
  returning * into v_row;

  return v_row;
end;
$$;

alter table public.dm_group_chats enable row level security;
alter table public.dm_group_chat_members enable row level security;
alter table public.dm_group_read_state enable row level security;

drop policy if exists "Members can view their group chats" on public.dm_group_chats;
create policy "Members can view their group chats"
on public.dm_group_chats
for select
to authenticated
using (public.is_dm_group_member(id, auth.uid()));

drop policy if exists "Members can view group chat members" on public.dm_group_chat_members;
create policy "Members can view group chat members"
on public.dm_group_chat_members
for select
to authenticated
using (public.is_dm_group_member(group_chat_id, auth.uid()));

drop policy if exists "Users manage their group read state" on public.dm_group_read_state;
create policy "Users manage their group read state"
on public.dm_group_read_state
for all
to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());

drop policy if exists "Members can read group chat messages" on public.direct_messages;
create policy "Members can read group chat messages"
on public.direct_messages
for select
to authenticated
using (
  group_chat_id is not null
  and public.is_dm_group_member(group_chat_id, auth.uid())
);

drop policy if exists "Members can send group chat messages" on public.direct_messages;
create policy "Members can send group chat messages"
on public.direct_messages
for insert
to authenticated
with check (
  auth.uid() = sender_id
  and group_chat_id is not null
  and recipient_id is null
  and public.is_dm_group_member(group_chat_id, auth.uid())
);

grant execute on function public.create_dm_group_chat(uuid[], text) to authenticated;
grant execute on function public.get_my_dm_group_chats() to authenticated;
grant execute on function public.get_dm_group_message_history(uuid, timestamptz, integer) to authenticated;
grant execute on function public.send_dm_group_message(uuid, text) to authenticated;
grant execute on function public.is_dm_group_member(uuid, uuid) to authenticated;
