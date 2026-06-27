-- Feed/comment RPCs joined public.users under invoker rights; users SELECT RLS blocks other authors.
-- Join public_user_profiles instead (authenticated read policy allows all rows).

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
  where
    p.server_id = p_server_id
    and (
      s.visibility = 'public'
      or sm.user_id is not null
    )
  order by p.created_at desc
  limit least(greatest(coalesce(p_limit, 60), 1), 100);
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
  where
    p.server_id is null
    or (
      s.visibility = 'public'
      and coalesce(s.show_posts_in_global_feed, true)
    )
  order by p.created_at desc
  limit least(greatest(coalesce(p_limit, 120), 1), 150);
$$;

create or replace function public.get_post_comments_detailed(p_post_id uuid)
returns table (
  id uuid,
  post_id uuid,
  author_id uuid,
  content text,
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
