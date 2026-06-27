-- ─── Posts Feed Tables ────────────────────────────────────────────────────────

create table if not exists posts (
  id          uuid primary key default gen_random_uuid(),
  server_id   bigint not null references servers(id) on delete cascade,
  author_id   uuid   not null references auth.users(id) on delete cascade,
  content     text   not null,
  upvotes     int    not null default 0,
  downvotes   int    not null default 0,
  created_at  timestamptz not null default now()
);

create table if not exists post_votes (
  id          uuid primary key default gen_random_uuid(),
  post_id     uuid not null references posts(id) on delete cascade,
  user_id     uuid not null references auth.users(id) on delete cascade,
  vote_type   text not null check (vote_type in ('up', 'down')),
  created_at  timestamptz not null default now(),
  unique (post_id, user_id)
);

create table if not exists post_comments (
  id          uuid primary key default gen_random_uuid(),
  post_id     uuid not null references posts(id) on delete cascade,
  author_id   uuid not null references auth.users(id) on delete cascade,
  content     text not null,
  created_at  timestamptz not null default now()
);

-- ─── Indexes ──────────────────────────────────────────────────────────────────

create index if not exists posts_server_id_idx     on posts(server_id, created_at desc);
create index if not exists post_votes_post_id_idx  on post_votes(post_id);
create index if not exists post_comments_post_id_idx on post_comments(post_id, created_at asc);

-- ─── RLS ──────────────────────────────────────────────────────────────────────

alter table posts         enable row level security;
alter table post_votes    enable row level security;
alter table post_comments enable row level security;

-- Posts: visible to members of the server or anyone if server is public
create policy "posts_select" on posts for select using (
  exists (
    select 1 from servers s
    where s.id = posts.server_id
      and (
        s.visibility = 'public'
        or exists (
          select 1 from server_members sm
          where sm.server_id = s.id
            and sm.user_id = auth.uid()
        )
      )
  )
);

-- Posts: members can insert
create policy "posts_insert" on posts for insert with check (
  author_id = auth.uid()
  and exists (
    select 1 from server_members sm
    where sm.server_id = posts.server_id
      and sm.user_id = auth.uid()
  )
);

-- Posts: only author can delete
create policy "posts_delete" on posts for delete using (author_id = auth.uid());

-- Post votes: authenticated users can see all votes on visible posts
create policy "post_votes_select" on post_votes for select using (true);

-- Post votes: user can insert their own vote
create policy "post_votes_insert" on post_votes for insert with check (user_id = auth.uid());

-- Post votes: user can update their own vote
create policy "post_votes_update" on post_votes for update using (user_id = auth.uid());

-- Post votes: user can delete their own vote
create policy "post_votes_delete" on post_votes for delete using (user_id = auth.uid());

-- Post comments: same visibility as posts
create policy "post_comments_select" on post_comments for select using (
  exists (
    select 1 from posts p
    join servers s on s.id = p.server_id
    where p.id = post_comments.post_id
      and (
        s.visibility = 'public'
        or exists (
          select 1 from server_members sm
          where sm.server_id = s.id
            and sm.user_id = auth.uid()
        )
      )
  )
);

-- Post comments: authenticated members can insert
create policy "post_comments_insert" on post_comments for insert with check (
  author_id = auth.uid()
  and exists (
    select 1 from posts p
    join server_members sm on sm.server_id = p.server_id
    where p.id = post_comments.post_id
      and sm.user_id = auth.uid()
  )
);

-- Post comments: only author can delete
create policy "post_comments_delete" on post_comments for delete using (author_id = auth.uid());

-- ─── Realtime ─────────────────────────────────────────────────────────────────

alter publication supabase_realtime add table posts;
alter publication supabase_realtime add table post_votes;
