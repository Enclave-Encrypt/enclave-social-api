alter table public.messages
  alter column sender_id drop default;

alter table public.server_members
  alter column user_id drop default;

alter table public.servers
  alter column owner_id drop default;

drop function if exists public.upsert_my_user_settings(
  text,
  text,
  text,
  integer,
  boolean
);

alter table public.server_members
  drop constraint if exists server_members_server_user_uidx;

alter table public.mls_channel_state_snapshots
  drop constraint if exists mls_channel_state_snapshots_channel_unique;

drop index if exists public.server_members_server_user_uidx;
drop index if exists public.mls_channel_state_snapshots_channel_unique;

create or replace function public.get_channel_message_history(
  p_channel_id bigint,
  p_before timestamptz default null,
  p_limit integer default 50
)
returns setof public.messages
language sql
stable
set search_path to public
as $$
  select m.*
  from public.messages m
  where
    m.channel_id = p_channel_id
    and (p_before is null or m.created_at < p_before)
  order by m.created_at desc
  limit least(greatest(coalesce(p_limit, 50), 1), 100);
$$;

create or replace function public.get_dm_message_history(
  p_other_user_id uuid,
  p_before timestamptz default null,
  p_limit integer default 50
)
returns setof public.direct_messages
language sql
stable
set search_path to public
as $$
  select dm.*
  from public.direct_messages dm
  where
    least(dm.sender_id, dm.recipient_id) = least(auth.uid(), p_other_user_id)
    and greatest(dm.sender_id, dm.recipient_id) = greatest(auth.uid(), p_other_user_id)
    and (p_before is null or dm.created_at < p_before)
  order by dm.created_at desc
  limit least(greatest(coalesce(p_limit, 50), 1), 100);
$$;

create or replace function public.get_visible_feed_posts(p_limit integer default 120)
returns table (
  id uuid,
  server_id bigint,
  author_id uuid,
  title text,
  content text,
  flair_id uuid,
  flair_name text,
  flair_color text,
  created_at timestamptz,
  server_name text,
  server_icon text,
  author_username text,
  author_display_name text,
  author_avatar text,
  upvotes integer,
  downvotes integer,
  my_vote text,
  comment_count integer
)
language sql
stable
set search_path to public
as $$
  select
    p.id,
    p.server_id,
    p.author_id,
    p.title,
    p.content,
    p.flair_id,
    pf.name as flair_name,
    pf.color as flair_color,
    p.created_at,
    coalesce(s.display_name, s.handle, 'Unknown Server') as server_name,
    s.icon_url as server_icon,
    coalesce(u.username, 'unknown') as author_username,
    u.display_name as author_display_name,
    u.avatar_url as author_avatar,
    coalesce(votes.upvotes, 0)::integer as upvotes,
    coalesce(votes.downvotes, 0)::integer as downvotes,
    votes.my_vote,
    coalesce(comments.comment_count, 0)::integer as comment_count
  from public.posts p
  join public.servers s
    on s.id = p.server_id
  left join public.server_members sm
    on sm.server_id = s.id
   and sm.user_id = auth.uid()
  left join public.post_flairs pf
    on pf.id = p.flair_id
  left join public.users u
    on u.auth_id = p.author_id
  left join lateral (
    select
      count(*) filter (where pv.vote_type = 'up') as upvotes,
      count(*) filter (where pv.vote_type = 'down') as downvotes,
      max(pv.vote_type) filter (where pv.user_id = auth.uid()) as my_vote
    from public.post_votes pv
    where pv.post_id = p.id
  ) votes on true
  left join lateral (
    select count(*) as comment_count
    from public.post_comments pc
    where pc.post_id = p.id
  ) comments on true
  where
    s.visibility = 'public'
    or s.owner_id = auth.uid()
    or sm.user_id is not null
  order by p.created_at desc
  limit least(greatest(coalesce(p_limit, 120), 1), 150);
$$;

create or replace function public.get_server_feed_posts(
  p_server_id bigint,
  p_limit integer default 60
)
returns table (
  id uuid,
  server_id bigint,
  author_id uuid,
  title text,
  content text,
  flair_id uuid,
  flair_name text,
  flair_color text,
  created_at timestamptz,
  author_username text,
  author_display_name text,
  author_avatar text,
  upvotes integer,
  downvotes integer,
  my_vote text,
  comment_count integer
)
language sql
stable
set search_path to public
as $$
  select
    p.id,
    p.server_id,
    p.author_id,
    p.title,
    p.content,
    p.flair_id,
    pf.name as flair_name,
    pf.color as flair_color,
    p.created_at,
    coalesce(u.username, 'unknown') as author_username,
    u.display_name as author_display_name,
    u.avatar_url as author_avatar,
    coalesce(votes.upvotes, 0)::integer as upvotes,
    coalesce(votes.downvotes, 0)::integer as downvotes,
    votes.my_vote,
    coalesce(comments.comment_count, 0)::integer as comment_count
  from public.posts p
  join public.servers s
    on s.id = p.server_id
  left join public.server_members sm
    on sm.server_id = s.id
   and sm.user_id = auth.uid()
  left join public.post_flairs pf
    on pf.id = p.flair_id
  left join public.users u
    on u.auth_id = p.author_id
  left join lateral (
    select
      count(*) filter (where pv.vote_type = 'up') as upvotes,
      count(*) filter (where pv.vote_type = 'down') as downvotes,
      max(pv.vote_type) filter (where pv.user_id = auth.uid()) as my_vote
    from public.post_votes pv
    where pv.post_id = p.id
  ) votes on true
  left join lateral (
    select count(*) as comment_count
    from public.post_comments pc
    where pc.post_id = p.id
  ) comments on true
  where
    p.server_id = p_server_id
    and (
      s.visibility = 'public'
      or s.owner_id = auth.uid()
      or sm.user_id is not null
    )
  order by p.created_at desc
  limit least(greatest(coalesce(p_limit, 60), 1), 100);
$$;
