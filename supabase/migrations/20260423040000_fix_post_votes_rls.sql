-- Drop the overly-permissive SELECT policy that exposed all vote records to
-- every authenticated user regardless of server membership or visibility.
drop policy if exists "post_votes_select" on post_votes;

-- Replace with the same visibility check used by post_comments_select:
-- a vote is readable only when the associated post's server is public,
-- or the querying user is a member of that server.
create policy "post_votes_select" on post_votes for select using (
  exists (
    select 1 from posts p
    join servers s on s.id = p.server_id
    where p.id = post_votes.post_id
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
