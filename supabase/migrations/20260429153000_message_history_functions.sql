create index if not exists direct_messages_pair_created_at_idx
  on public.direct_messages (
    least(sender_id, recipient_id),
    greatest(sender_id, recipient_id),
    created_at desc
  )
  where sender_id is not null and recipient_id is not null;

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
  limit greatest(coalesce(p_limit, 50), 1);
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
  limit greatest(coalesce(p_limit, 50), 1);
$$;
