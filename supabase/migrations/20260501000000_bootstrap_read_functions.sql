create or replace function public.get_my_servers()
returns setof public.servers
language sql
stable
set search_path to public
as $$
  select distinct s.*
  from public.servers s
  left join public.server_members sm
    on sm.server_id = s.id
   and sm.user_id = auth.uid()
  where
    auth.uid() is not null
    and (
      s.owner_id = auth.uid()
      or sm.user_id is not null
    )
  order by s.created_at asc;
$$;

create or replace function public.get_my_channel_unread_context()
returns table (
  channel_id bigint,
  server_id bigint,
  unread_count bigint
)
language sql
stable
set search_path to public
as $$
  with my_servers as (
    select sm.server_id
    from public.server_members sm
    where sm.user_id = auth.uid()

    union

    select s.id as server_id
    from public.servers s
    where s.owner_id = auth.uid()
  )
  select
    c.id as channel_id,
    c.server_id,
    count(m.id)::bigint as unread_count
  from public.channels c
  join my_servers ms
    on ms.server_id = c.server_id
  left join public.channel_read_state crs
    on crs.channel_id = c.id
   and crs.user_id = auth.uid()
  left join public.messages m
    on m.channel_id = c.id
   and m.sender_id <> auth.uid()
   and (
     crs.last_read_at is null
     or m.created_at > crs.last_read_at
   )
  where auth.uid() is not null
  group by c.id, c.server_id, c.position
  order by c.server_id asc, c.position asc, c.id asc;
$$;
