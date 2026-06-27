-- Append-only feed post edits using sidechain packets.

create extension if not exists pgcrypto;

alter table public.posts
  add column if not exists msg_packet jsonb;

alter table public.post_comments
  add column if not exists parent_comment_id uuid references public.post_comments(id) on delete cascade,
  add column if not exists msg_packet jsonb;

update public.posts
set msg_packet = jsonb_build_object(
  'unencrypted',
  jsonb_build_object(
    'packet_type', 'feed_root_post',
    'version', 1
  ),
  'encrypted',
  jsonb_build_object(
    'body',
    jsonb_build_object(
      'title', coalesce(title, ''),
      'content', coalesce(content, '')
    ),
    'sidechain_key', encode(extensions.gen_random_bytes(32), 'base64'),
    'sidechain_version', 1
  )
)
where msg_packet is null;

create table if not exists public.post_sidechain_events (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  actor_id uuid not null references auth.users(id) on delete cascade,
  event_type text not null check (
    event_type in (
      'feed_post_edit',
      'feed_comment_add',
      'feed_post_vote',
      'feed_comment_vote'
    )
  ),
  msg_packet jsonb not null,
  authenticated_data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists post_sidechain_events_post_id_idx
  on public.post_sidechain_events (post_id, created_at desc, id desc);

create index if not exists post_comments_parent_comment_id_idx
  on public.post_comments (parent_comment_id, created_at asc);

alter table public.post_sidechain_events enable row level security;

drop policy if exists "post_sidechain_events_select" on public.post_sidechain_events;
create policy "post_sidechain_events_select"
on public.post_sidechain_events
for select
using (
  exists (
    select 1
    from public.posts p
    left join public.servers s on s.id = p.server_id
    where p.id = post_sidechain_events.post_id
      and (
        p.server_id is null
        or s.visibility = 'public'
        or exists (
          select 1
          from public.server_members sm
          where sm.server_id = p.server_id
            and sm.user_id = auth.uid()
        )
      )
  )
);

drop policy if exists "post_sidechain_events_insert" on public.post_sidechain_events;
create policy "post_sidechain_events_insert"
on public.post_sidechain_events
for insert
with check (
  actor_id = auth.uid()
  and exists (
    select 1
    from public.posts p
    where p.id = post_sidechain_events.post_id
      and p.author_id = auth.uid()
  )
);

alter publication supabase_realtime add table public.post_sidechain_events;

drop function if exists public.get_server_feed_posts(bigint, integer);
create or replace function public.get_server_feed_posts(p_server_id bigint, p_limit integer default 60)
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
  edited_at timestamptz,
  msg_packet jsonb,
  latest_edit_packet jsonb,
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
set search_path = public
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
    latest_edit.created_at as edited_at,
    p.msg_packet,
    latest_edit.msg_packet as latest_edit_packet,
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
  left join public.public_user_profiles u
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
  left join lateral (
    select pse.msg_packet, pse.created_at
    from public.post_sidechain_events pse
    where pse.post_id = p.id
      and pse.event_type = 'feed_post_edit'
    order by pse.created_at desc, pse.id desc
    limit 1
  ) latest_edit on true
  where
    p.server_id = p_server_id
    and (
      s.visibility = 'public'
      or sm.user_id is not null
    )
  order by p.created_at desc
  limit least(greatest(coalesce(p_limit, 60), 1), 100);
$$;

drop function if exists public.get_visible_feed_posts(integer);
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
  edited_at timestamptz,
  msg_packet jsonb,
  latest_edit_packet jsonb,
  server_name text,
  server_handle text,
  server_icon text,
  author_username text,
  author_display_name text,
  author_avatar text,
  feed_reason text,
  upvotes integer,
  downvotes integer,
  my_vote text,
  comment_count integer
)
language sql
stable
set search_path = public
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
    latest_edit.created_at as edited_at,
    p.msg_packet,
    latest_edit.msg_packet as latest_edit_packet,
    case
      when p.server_id is null then coalesce(u.display_name, u.username, 'Profile')
      else coalesce(s.display_name, s.handle, 'Unknown Server')
    end as server_name,
    case
      when p.server_id is null then null
      else coalesce(s.handle, s.display_name)
    end as server_handle,
    case
      when p.server_id is null then u.avatar_url
      else s.icon_url
    end as server_icon,
    coalesce(u.username, 'unknown') as author_username,
    u.display_name as author_display_name,
    u.avatar_url as author_avatar,
    case
      when p.server_id is null then 'Because you may have missed this profile post'
      when exists (
        select 1
        from public.server_members sm
        where sm.server_id = p.server_id
          and sm.user_id = auth.uid()
      ) then 'From a server you joined'
      else 'Because this server is public'
    end as feed_reason,
    coalesce(votes.upvotes, 0)::integer as upvotes,
    coalesce(votes.downvotes, 0)::integer as downvotes,
    votes.my_vote,
    coalesce(comments.comment_count, 0)::integer as comment_count
  from public.posts p
  left join public.servers s
    on s.id = p.server_id
  left join public.post_flairs pf
    on pf.id = p.flair_id
  left join public.public_user_profiles u
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
  left join lateral (
    select pse.msg_packet, pse.created_at
    from public.post_sidechain_events pse
    where pse.post_id = p.id
      and pse.event_type = 'feed_post_edit'
    order by pse.created_at desc, pse.id desc
    limit 1
  ) latest_edit on true
  where
    p.server_id is null
    or (
      s.visibility = 'public'
      and coalesce(s.show_posts_in_global_feed, true)
    )
  order by p.created_at desc
  limit least(greatest(coalesce(p_limit, 120), 1), 150);
$$;

drop function if exists public.get_post_comments_detailed(uuid);
create or replace function public.get_post_comments_detailed(p_post_id uuid)
returns table (
  id uuid,
  post_id uuid,
  author_id uuid,
  content text,
  parent_comment_id uuid,
  msg_packet jsonb,
  created_at timestamptz,
  upvotes integer,
  downvotes integer,
  my_vote text,
  author_username text,
  author_display_name text,
  author_avatar text
)
language sql
stable
set search_path = public
as $$
  select
    c.id,
    c.post_id,
    c.author_id,
    c.content,
    c.parent_comment_id,
    c.msg_packet,
    c.created_at,
    coalesce(votes.upvotes, 0)::integer as upvotes,
    coalesce(votes.downvotes, 0)::integer as downvotes,
    votes.my_vote,
    coalesce(u.username, 'unknown') as author_username,
    u.display_name as author_display_name,
    u.avatar_url as author_avatar
  from public.post_comments c
  left join public.public_user_profiles u
    on u.auth_id = c.author_id
  left join lateral (
    select
      count(*) filter (where pcv.vote_type = 'up') as upvotes,
      count(*) filter (where pcv.vote_type = 'down') as downvotes,
      max(pcv.vote_type) filter (where pcv.user_id = auth.uid()) as my_vote
    from public.post_comment_votes pcv
    where pcv.comment_id = c.id
  ) votes on true
  where c.post_id = p_post_id
  order by c.created_at asc;
$$;
