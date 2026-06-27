-- Fix feed RLS gaps introduced with profile posts and sidechain events.
-- 1. post_votes_select: profile posts (server_id IS NULL) were invisible to vote aggregations.
-- 2. post_sidechain_events_insert: only post authors could insert; voters/commenters were blocked.
-- 3. post_comment_votes_select: tighten from permissive true to post visibility rules.

drop policy if exists "post_votes_select" on public.post_votes;
create policy "post_votes_select"
on public.post_votes
for select
using (
  exists (
    select 1
    from public.posts p
    left join public.servers s
      on s.id = p.server_id
    where p.id = post_votes.post_id
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

drop policy if exists "post_comment_votes_select" on public.post_comment_votes;
create policy "post_comment_votes_select"
on public.post_comment_votes
for select
using (
  exists (
    select 1
    from public.post_comments c
    join public.posts p
      on p.id = c.post_id
    left join public.servers s
      on s.id = p.server_id
    where c.id = post_comment_votes.comment_id
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

drop policy if exists "post_sidechain_events_insert" on public.post_sidechain_events;
create policy "post_sidechain_events_insert"
on public.post_sidechain_events
for insert
with check (
  actor_id = auth.uid()
  and (
    (
      event_type = 'feed_post_edit'
      and exists (
        select 1
        from public.posts p
        where p.id = post_sidechain_events.post_id
          and p.author_id = auth.uid()
      )
    )
    or (
      event_type = 'feed_comment_add'
      and exists (
        select 1
        from public.posts p
        where p.id = post_sidechain_events.post_id
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
    )
    or (
      event_type in ('feed_post_vote', 'feed_comment_vote')
      and exists (
        select 1
        from public.posts p
        left join public.servers s
          on s.id = p.server_id
        where p.id = post_sidechain_events.post_id
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
    )
  )
);
