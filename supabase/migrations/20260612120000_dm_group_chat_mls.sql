-- Option A: friend group chats backed by MLS groups (multi-member E2EE DMs).

alter table public.dm_group_chats
  add column if not exists mls_group_id bigint references public.mls_groups (id) on delete set null;

alter table public.mls_groups
  add column if not exists group_chat_id uuid references public.dm_group_chats (id) on delete set null;

alter table public.mls_groups
  drop constraint if exists mls_groups_conversation_kind_check;

alter table public.mls_groups
  add constraint mls_groups_conversation_kind_check
  check (conversation_kind in ('dm', 'dm_group', 'channel', 'server_channel'));

alter table public.mls_groups
  drop constraint if exists mls_groups_target_check;

alter table public.mls_groups
  add constraint mls_groups_target_check
  check (
    (conversation_kind in ('channel', 'server_channel') and channel_id is not null)
    or (conversation_kind = 'dm' and dm_user_a is not null and dm_user_b is not null)
    or (conversation_kind = 'dm_group' and group_chat_id is not null)
  );

create index if not exists mls_groups_group_chat_id_idx
  on public.mls_groups (group_chat_id)
  where group_chat_id is not null;

create or replace function public.is_dm_group_chat_mls_member(
  p_group_chat_id uuid,
  p_user_id uuid default auth.uid()
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    public.is_dm_group_member(p_group_chat_id, p_user_id)
    and exists (
      select 1
      from public.mls_groups g
      where g.group_chat_id = p_group_chat_id
        and g.conversation_kind = 'dm_group'
        and g.is_active = true
        and public.check_mls_group_membership(g.id, p_user_id)
    );
$$;

grant execute on function public.is_dm_group_chat_mls_member(uuid, uuid) to authenticated;

create or replace function public.attach_dm_group_chat_mls_group(
  p_group_chat_id uuid,
  p_mls_group_id bigint
)
returns public.dm_group_chats
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_group public.dm_group_chats;
begin
  if v_user_id is null then
    raise exception 'Authentication required';
  end if;

  if not public.is_dm_group_member(p_group_chat_id, v_user_id) then
    raise exception 'You are not a member of this group chat';
  end if;

  if not exists (
    select 1
    from public.mls_groups g
    where g.id = p_mls_group_id
      and g.conversation_kind = 'dm_group'
      and g.group_chat_id = p_group_chat_id
      and public.check_mls_group_membership(g.id, v_user_id)
  ) then
    raise exception 'MLS group is not linked to this chat or you are not a member';
  end if;

  update public.dm_group_chats
  set mls_group_id = p_mls_group_id
  where id = p_group_chat_id
  returning * into v_group;

  return v_group;
end;
$$;

grant execute on function public.attach_dm_group_chat_mls_group(uuid, bigint) to authenticated;

drop policy if exists "Users can read MLS groups they belong to" on public.mls_groups;
create policy "Users can read MLS groups they belong to"
on public.mls_groups
for select
to authenticated
using (
  (conversation_kind = 'dm' and (dm_user_a = auth.uid() or dm_user_b = auth.uid()))
  or (
    conversation_kind = 'dm_group'
    and group_chat_id is not null
    and public.is_dm_group_member(group_chat_id, auth.uid())
  )
  or public.check_mls_group_membership(id, auth.uid())
);
