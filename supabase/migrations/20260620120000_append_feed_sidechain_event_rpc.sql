-- Reliable feed sidechain writes for comments/votes/edits.
-- Client-side inserts were blocked when post_sidechain_events_insert only allowed authors.

create or replace function public.can_access_feed_post(p_post_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.posts p
    left join public.servers s
      on s.id = p.server_id
    where p.id = p_post_id
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
  );
$$;

create or replace function public.append_feed_post_sidechain_event(
  p_id uuid,
  p_post_id uuid,
  p_event_type text,
  p_msg_packet jsonb,
  p_authenticated_data jsonb default '{}'::jsonb
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'Not authenticated';
  end if;

  if p_event_type = 'feed_post_edit' then
    if not exists (
      select 1
      from public.posts p
      where p.id = p_post_id
        and p.author_id = auth.uid()
    ) then
      raise exception 'Only the post author can edit this post';
    end if;
  elsif p_event_type = 'feed_comment_add' then
    if not public.can_access_feed_post(p_post_id) then
      raise exception 'Cannot comment on this post';
    end if;
  elsif p_event_type in ('feed_post_vote', 'feed_comment_vote') then
    if not public.can_access_feed_post(p_post_id) then
      raise exception 'Cannot vote on this post';
    end if;
  else
    raise exception 'Unsupported feed sidechain event type';
  end if;

  insert into public.post_sidechain_events (
    id,
    post_id,
    actor_id,
    event_type,
    msg_packet,
    authenticated_data
  )
  values (
    p_id,
    p_post_id,
    auth.uid(),
    p_event_type,
    p_msg_packet,
    p_authenticated_data
  );
end;
$$;

revoke all on function public.append_feed_post_sidechain_event(uuid, uuid, text, jsonb, jsonb) from public;
grant execute on function public.append_feed_post_sidechain_event(uuid, uuid, text, jsonb, jsonb) to authenticated;

-- Keep direct inserts aligned for environments that already applied the earlier policy fix.
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
      and public.can_access_feed_post(post_sidechain_events.post_id)
    )
    or (
      event_type in ('feed_post_vote', 'feed_comment_vote')
      and public.can_access_feed_post(post_sidechain_events.post_id)
    )
  )
);
