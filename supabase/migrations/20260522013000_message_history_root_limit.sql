-- Keep reaction/edit/thread sidechain rows from consuming the visible message page.
-- The client filters sidechain rows out after applying them to their root message,
-- so p_limit should mean root chat messages, not total transport rows.

create or replace function public.get_channel_message_history(
  p_channel_id bigint,
  p_before timestamptz default null,
  p_limit integer default 50
)
returns setof public.messages
language sql
stable
security definer
set search_path to public
as $$
  with root_messages as (
    select m.*
    from public.messages m
    where
      m.channel_id = p_channel_id
      and public.user_can_view_channel(m.channel_id, auth.uid())
      and (p_before is null or m.created_at < p_before)
      and coalesce(m.mls_message_type, '') <> 'sidechain_event'
      and coalesce(m.mls_content_type, '') <> 'sidechain_event'
    order by m.created_at desc, m.id desc
    limit least(greatest(coalesce(p_limit, 50), 1), 100)
  ),
  sidechain_events as (
    select m.*
    from public.messages m
    where
      m.channel_id = p_channel_id
      and public.user_can_view_channel(m.channel_id, auth.uid())
      and (
        m.mls_message_type = 'sidechain_event'
        or m.mls_content_type = 'sidechain_event'
      )
      and m.mls_authenticated_data ->> 'root_message_id' in (
        select rm.id::text
        from root_messages rm
      )
  )
  select *
  from (
    select * from root_messages
    union all
    select * from sidechain_events
  ) history
  order by history.created_at desc, history.id desc;
$$;
