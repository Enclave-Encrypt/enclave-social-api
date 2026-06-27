alter table public.posts
  alter column server_id drop not null;

alter table public.servers
  add column if not exists show_posts_in_global_feed boolean not null default true;

create index if not exists posts_author_profile_created_at_idx
  on public.posts (author_id, created_at desc)
  where server_id is null;

drop policy if exists "posts_select" on public.posts;
create policy "posts_select" on public.posts for select using (
  server_id is null
  or exists (
    select 1
    from public.servers s
    where s.id = posts.server_id
      and (
        s.visibility = 'public'
        or exists (
          select 1
          from public.server_members sm
          where sm.server_id = s.id
            and sm.user_id = auth.uid()
        )
      )
  )
);

drop policy if exists "posts_insert" on public.posts;
create policy "posts_insert" on public.posts for insert with check (
  author_id = auth.uid()
  and (
    server_id is null
    or exists (
      select 1
      from public.server_members sm
      where sm.server_id = posts.server_id
        and sm.user_id = auth.uid()
    )
    or exists (
      select 1
      from public.servers s
      where s.id = posts.server_id
        and s.visibility = 'public'
    )
  )
);

drop policy if exists "post_comments_select" on public.post_comments;
create policy "post_comments_select" on public.post_comments for select using (
  exists (
    select 1
    from public.posts p
    left join public.servers s
      on s.id = p.server_id
    where p.id = post_comments.post_id
      and (
        p.server_id is null
        or s.visibility = 'public'
        or exists (
          select 1
          from public.server_members sm
          where sm.server_id = s.id
            and sm.user_id = auth.uid()
        )
      )
  )
);

drop policy if exists "post_comments_insert" on public.post_comments;
create policy "post_comments_insert" on public.post_comments for insert with check (
  author_id = auth.uid()
  and exists (
    select 1
    from public.posts p
    where p.id = post_comments.post_id
      and (
        p.server_id is null
        or exists (
          select 1
          from public.server_members sm
          where sm.server_id = p.server_id
            and sm.user_id = auth.uid()
        )
        or exists (
          select 1
          from public.servers s
          where s.id = p.server_id
            and s.visibility = 'public'
        )
      )
  )
);

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
    case
      when p.server_id is null then coalesce(u.display_name, u.username, 'Profile')
      else coalesce(s.display_name, s.handle, 'Unknown Server')
    end as server_name,
    case
      when p.server_id is null then u.avatar_url
      else s.icon_url
    end as server_icon,
    coalesce(u.username, 'unknown') as author_username,
    u.display_name as author_display_name,
    u.avatar_url as author_avatar,
    coalesce(votes.upvotes, 0)::integer as upvotes,
    coalesce(votes.downvotes, 0)::integer as downvotes,
    votes.my_vote,
    coalesce(comments.comment_count, 0)::integer as comment_count
  from public.posts p
  left join public.servers s
    on s.id = p.server_id
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
    p.server_id is null
    or (
      s.visibility = 'public'
      and coalesce(s.show_posts_in_global_feed, true)
    )
  order by p.created_at desc
  limit least(greatest(coalesce(p_limit, 120), 1), 150);
$$;

drop function if exists public.get_server_settings_context(bigint);

create or replace function public.get_server_settings_context(p_server_id bigint)
returns table (
  id bigint,
  display_name text,
  description text,
  category text,
  visibility text,
  rules text,
  welcome_message text,
  banner_url text,
  icon_url text,
  invite_code text,
  show_posts_in_global_feed boolean,
  my_role text,
  nickname text
)
language sql
stable
set search_path to public
as $$
  select
    s.id,
    s.display_name,
    s.description,
    s.category,
    s.visibility,
    s.rules,
    s.welcome_message,
    s.banner_url,
    s.icon_url,
    s.invite_code,
    coalesce(s.show_posts_in_global_feed, true) as show_posts_in_global_feed,
    coalesce(
      case
        when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
        else lower(trim(coalesce(sm.role, 'member')))
      end,
      'member'
    ) as my_role,
    sn.nickname
  from public.servers s
  left join public.server_members sm
    on sm.server_id = s.id
   and sm.user_id = auth.uid()
  left join public.server_nicknames sn
    on sn.server_id = s.id
   and sn.user_id = auth.uid()
  where s.id = p_server_id
  limit 1;
$$;
