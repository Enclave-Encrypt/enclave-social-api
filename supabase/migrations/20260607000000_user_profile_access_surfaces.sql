-- Phase 1a: Safe read surfaces for public profiles and own-account data.
-- Writes continue on public.users; cross-user reads use the view or RPCs below.

create or replace view public.public_user_profiles
with (security_invoker = false) as
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
from public.users u;

comment on view public.public_user_profiles is
  'Client-safe profile fields. No email, billing, push tokens, or private preferences.';

grant select on public.public_user_profiles to authenticated;

create or replace function public.get_my_account()
returns table (
  id bigint,
  auth_id uuid,
  email text,
  username text,
  display_name text,
  avatar_url text,
  banner_url text,
  bio text,
  username_updated_at timestamptz,
  created_at timestamptz,
  last_seen timestamptz,
  presence text,
  status_message text,
  age_range public.age_range_type,
  nsfw_enabled boolean,
  app_theme text,
  tier text,
  token_balance integer,
  key_credit_balance integer,
  platform_stripe_customer_id text,
  stripe_customer_id text,
  creator_pending_tokens integer,
  creator_available_tokens integer,
  creator_stripe_account_id text,
  marketing_emails_enabled boolean,
  marketing_emails_opted_in_at timestamptz,
  marketing_emails_opted_in_source text,
  marketing_emails_unsubscribed_at timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
  select
    u.id,
    u.auth_id,
    u.email,
    u.username,
    u.display_name,
    u.avatar_url,
    u.banner_url,
    u.bio,
    u.username_updated_at,
    u.created_at,
    u.last_seen,
    u.presence,
    u.status_message,
    u.age_range,
    u.nsfw_enabled,
    u.app_theme,
    u.tier,
    u.token_balance,
    u.key_credit_balance,
    u.platform_stripe_customer_id,
    u.stripe_customer_id,
    u.creator_pending_tokens,
    u.creator_available_tokens,
    u.creator_stripe_account_id,
    u.marketing_emails_enabled,
    u.marketing_emails_opted_in_at,
    u.marketing_emails_opted_in_source,
    u.marketing_emails_unsubscribed_at
  from public.users u
  where u.auth_id = auth.uid();
$$;

revoke all on function public.get_my_account() from public;
grant execute on function public.get_my_account() to authenticated;

create or replace function public.is_username_available(p_username text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select not exists (
    select 1
    from public.users u
    where u.username = lower(regexp_replace(coalesce(p_username, ''), '[^a-z0-9_]', '', 'g'))
      and u.auth_id is distinct from auth.uid()
  );
$$;

revoke all on function public.is_username_available(text) from public;
grant execute on function public.is_username_available(text) to authenticated;

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

drop function if exists public.get_my_dm_conversations();

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

revoke execute on function public.lookup_login_email_by_username(text) from anon;

create policy "Users can read their own account row"
  on public.users
  for select
  to authenticated
  using (auth_id = auth.uid());
