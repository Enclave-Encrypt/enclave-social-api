-- RLS for public.public_user_profiles.
-- Postgres cannot enable RLS on views, so replace the view with a table kept in sync from public.users.

drop function if exists public.search_public_profiles(text, integer);
drop function if exists public.get_my_dm_conversations();

drop view if exists public.public_user_profiles;

create table public.public_user_profiles (
  auth_id uuid primary key references public.users (auth_id) on delete cascade,
  username text,
  display_name text,
  avatar_url text,
  banner_url text,
  bio text,
  presence text,
  status_message text,
  tier text,
  created_at timestamptz,
  last_seen timestamptz
);

comment on table public.public_user_profiles is
  'Client-safe profile fields. No email, billing, push tokens, or private preferences. Synced from public.users.';

insert into public.public_user_profiles (
  auth_id,
  username,
  display_name,
  avatar_url,
  banner_url,
  bio,
  presence,
  status_message,
  tier,
  created_at,
  last_seen
)
select
  u.auth_id,
  u.username,
  u.display_name,
  u.avatar_url,
  u.banner_url,
  u.bio,
  u.presence,
  u.status_message,
  u.tier,
  u.created_at,
  u.last_seen
from public.users u
where u.auth_id is not null;

create or replace function public.sync_public_user_profile_row()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if tg_op = 'DELETE' then
    if old.auth_id is not null then
      delete from public.public_user_profiles where auth_id = old.auth_id;
    end if;
    return old;
  end if;

  if new.auth_id is null then
    return new;
  end if;

  insert into public.public_user_profiles (
    auth_id,
    username,
    display_name,
    avatar_url,
    banner_url,
    bio,
    presence,
    status_message,
    tier,
    created_at,
    last_seen
  )
  values (
    new.auth_id,
    new.username,
    new.display_name,
    new.avatar_url,
    new.banner_url,
    new.bio,
    new.presence,
    new.status_message,
    new.tier,
    new.created_at,
    new.last_seen
  )
  on conflict (auth_id) do update set
    username = excluded.username,
    display_name = excluded.display_name,
    avatar_url = excluded.avatar_url,
    banner_url = excluded.banner_url,
    bio = excluded.bio,
    presence = excluded.presence,
    status_message = excluded.status_message,
    tier = excluded.tier,
    created_at = excluded.created_at,
    last_seen = excluded.last_seen;

  return new;
end;
$$;

drop trigger if exists sync_public_user_profile_row on public.users;
create trigger sync_public_user_profile_row
after insert or update or delete on public.users
for each row
execute function public.sync_public_user_profile_row();

revoke all on public.public_user_profiles from anon;
revoke all on public.public_user_profiles from public;
grant select on public.public_user_profiles to authenticated;

alter table public.public_user_profiles enable row level security;

create policy "Public profiles are viewable by authenticated users"
on public.public_user_profiles
for select
to authenticated
using (true);

create policy "Users can update own profile"
on public.public_user_profiles
for update
to authenticated
using (auth.uid() = auth_id)
with check (auth.uid() = auth_id);

create policy "Users can insert own profile"
on public.public_user_profiles
for insert
to authenticated
with check (auth.uid() = auth_id);

create policy "Users can delete own profile"
on public.public_user_profiles
for delete
to authenticated
using (auth.uid() = auth_id);

create policy "Anon users cannot read profiles"
on public.public_user_profiles
for select
to anon
using (false);

create or replace function public.search_public_profiles(
  p_query text,
  p_limit integer default 20
)
returns setof public.public_user_profiles
language sql
stable
security definer
set search_path = public
as $$
  select v.*
  from public.public_user_profiles v
  where v.auth_id is distinct from auth.uid()
    and (
      v.username ilike '%' || lower(regexp_replace(coalesce(p_query, ''), '[^a-z0-9_]', '', 'g')) || '%'
      or v.display_name ilike '%' || coalesce(p_query, '') || '%'
    )
  order by v.username asc nulls last
  limit greatest(1, least(coalesce(p_limit, 20), 50));
$$;

revoke all on function public.search_public_profiles(text, integer) from public;
grant execute on function public.search_public_profiles(text, integer) to authenticated;

create or replace function public.get_my_dm_conversations()
returns table (
  auth_id uuid,
  username text,
  display_name text,
  avatar_url text,
  presence text,
  is_friend boolean,
  latest_message_at timestamptz,
  unread_count bigint
)
language sql
stable
security definer
set search_path = public
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
    p.auth_id,
    p.username,
    p.display_name,
    p.avatar_url,
    p.presence,
    (afi.user_id is not null) as is_friend,
    dc.latest_message_at,
    coalesce(uc.unread_count, 0)::bigint as unread_count
  from relevant_users ru
  join public.public_user_profiles p
    on p.auth_id = ru.user_id
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
    coalesce(p.display_name, p.username) asc;
$$;

revoke all on function public.get_my_dm_conversations() from public;
grant execute on function public.get_my_dm_conversations() to authenticated;
