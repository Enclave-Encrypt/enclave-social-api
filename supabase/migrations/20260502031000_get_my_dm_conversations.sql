create or replace function public.get_my_dm_conversations()
returns table (
  auth_id uuid,
  username text,
  display_name text,
  avatar_url text,
  email text,
  presence text,
  is_friend boolean,
  latest_message_at timestamptz,
  unread_count bigint
)
language sql
stable
security definer
set search_path to public
as $$
  with accepted_friend_ids as (
    select
      case
        when f.requester_id = auth.uid() then f.recipient_id
        else f.requester_id
      end as user_id
    from public.friendships f
    where
      f.status = 'accepted'
      and (f.requester_id = auth.uid() or f.recipient_id = auth.uid())
  ),
  dm_conversations as (
    select
      case
        when dm.sender_id = auth.uid() then dm.recipient_id
        else dm.sender_id
      end as user_id,
      max(dm.created_at) as latest_message_at
    from public.direct_messages dm
    where
      dm.sender_id = auth.uid()
      or dm.recipient_id = auth.uid()
    group by 1
  ),
  relevant_users as (
    select user_id from accepted_friend_ids
    union
    select user_id from dm_conversations
  ),
  unread_counts as (
    select
      dm.sender_id as user_id,
      count(*)::bigint as unread_count
    from public.direct_messages dm
    left join public.dm_read_state drs
      on drs.other_user_id = dm.sender_id
     and drs.user_id = auth.uid()
    where
      dm.recipient_id = auth.uid()
      and (drs.last_read_at is null or dm.created_at > drs.last_read_at)
    group by dm.sender_id
  )
  select
    u.auth_id,
    u.username,
    u.display_name,
    u.avatar_url,
    u.email,
    u.presence,
    (afi.user_id is not null) as is_friend,
    dc.latest_message_at,
    coalesce(uc.unread_count, 0)::bigint as unread_count
  from relevant_users ru
  join public.users u
    on u.auth_id = ru.user_id
  left join accepted_friend_ids afi
    on afi.user_id = ru.user_id
  left join dm_conversations dc
    on dc.user_id = ru.user_id
  left join unread_counts uc
    on uc.user_id = ru.user_id
  where
    auth.uid() is not null
    and ru.user_id is not null
  order by
    (afi.user_id is not null) desc,
    dc.latest_message_at desc nulls last,
    coalesce(u.display_name, u.username, u.email) asc;
$$;

grant execute on function public.get_my_dm_conversations() to authenticated;
