create or replace function public.user_can_manage_channels(
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
        lower(coalesce(sm.role, '')) in ('owner', 'admin')
        or coalesce((sr.permissions ->> 'manage_channels')::boolean, false)
      )
  )
  or exists (
    select 1
    from public.server_member_roles smr
    join public.server_roles sr
      on sr.id = smr.role_id
    where smr.server_id = p_server_id
      and smr.user_id = p_user_id
      and coalesce((sr.permissions ->> 'manage_channels')::boolean, false)
  );
$$;

drop policy if exists "Server managers can create channels" on public.channels;
create policy "Server managers can create channels"
on public.channels
for insert
to authenticated
with check (public.user_can_manage_channels(server_id, auth.uid()));

drop policy if exists "Server managers can update channels" on public.channels;
create policy "Server managers can update channels"
on public.channels
for update
to authenticated
using (public.user_can_manage_channels(server_id, auth.uid()))
with check (public.user_can_manage_channels(server_id, auth.uid()));

drop policy if exists "Server managers can delete channels" on public.channels;
create policy "Server managers can delete channels"
on public.channels
for delete
to authenticated
using (public.user_can_manage_channels(server_id, auth.uid()));
