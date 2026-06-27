create or replace function public.user_can_manage_messages(
  p_server_id bigint,
  p_user_id uuid default auth.uid()
)
returns boolean
language sql
security definer
set search_path to public
as $$
  select exists (
    select 1
    from public.servers s
    where s.id = p_server_id
      and s.owner_id = p_user_id
  )
  or exists (
    select 1
    from public.server_members sm
    left join public.server_roles sr
      on sr.id = sm.role_id
    where sm.server_id = p_server_id
      and sm.user_id = p_user_id
      and (
        lower(coalesce(sm.role, '')) in ('owner', 'admin', 'mod', 'moderator')
        or coalesce((sr.permissions ->> 'manage_messages')::boolean, false)
      )
  )
  or exists (
    select 1
    from public.server_member_roles smr
    join public.server_roles sr
      on sr.id = smr.role_id
    where smr.server_id = p_server_id
      and smr.user_id = p_user_id
      and coalesce((sr.permissions ->> 'manage_messages')::boolean, false)
  );
$$;

drop policy if exists "Server message managers can delete messages" on public.messages;
create policy "Server message managers can delete messages"
on public.messages
for delete
to authenticated
using (
  sender_id = auth.uid()
  or exists (
    select 1
    from public.channels c
    where c.id = messages.channel_id
      and public.user_can_manage_messages(c.server_id, auth.uid())
  )
);
