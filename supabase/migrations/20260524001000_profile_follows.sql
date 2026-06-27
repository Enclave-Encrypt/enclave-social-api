create table if not exists public.profile_follows (
  id bigint generated always as identity primary key,
  follower_id uuid not null references auth.users(id) on delete cascade,
  followed_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  constraint profile_follows_follower_followed_key unique (follower_id, followed_id),
  constraint profile_follows_no_self_follow check (follower_id <> followed_id)
);

create index if not exists profile_follows_followed_idx
  on public.profile_follows(followed_id, created_at desc);

alter table public.profile_follows enable row level security;

drop policy if exists "Users can read profile follows" on public.profile_follows;
create policy "Users can read profile follows"
on public.profile_follows
for select
to authenticated
using (follower_id = auth.uid() or followed_id = auth.uid());

drop policy if exists "Users can follow profiles" on public.profile_follows;
create policy "Users can follow profiles"
on public.profile_follows
for insert
to authenticated
with check (follower_id = auth.uid() and followed_id <> auth.uid());

drop policy if exists "Users can unfollow profiles" on public.profile_follows;
create policy "Users can unfollow profiles"
on public.profile_follows
for delete
to authenticated
using (follower_id = auth.uid());
