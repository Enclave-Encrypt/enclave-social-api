create or replace function public.is_server_owner(p_server_id bigint)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.servers s
    where s.id = p_server_id
      and s.owner_id = auth.uid()
  ) or exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = auth.uid()
      and lower(coalesce(sm.role, '')) = 'owner'
  );
$$;

create or replace function public.is_server_admin(p_server_id bigint)
returns boolean
language sql
security definer
set search_path = public
as $$
  select public.is_server_owner(p_server_id) or exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = auth.uid()
      and lower(coalesce(sm.role, '')) = 'admin'
  );
$$;

drop policy if exists "Owners can update servers via membership" on public.servers;
create policy "Owners can update servers via membership"
on public.servers
for update
to authenticated
using (public.is_server_owner(id))
with check (public.is_server_owner(id));

drop policy if exists "Owners can delete servers via membership" on public.servers;
create policy "Owners can delete servers via membership"
on public.servers
for delete
to authenticated
using (public.is_server_owner(id));

drop policy if exists "Owners can manage roles via membership" on public.server_roles;
create policy "Owners can manage roles via membership"
on public.server_roles
to authenticated
using (public.is_server_owner(server_id))
with check (public.is_server_owner(server_id));

drop policy if exists "Owners can manage tiers via membership" on public.subscription_tiers;
create policy "Owners can manage tiers via membership"
on public.subscription_tiers
to authenticated
using (public.is_server_owner(server_id))
with check (public.is_server_owner(server_id));

drop policy if exists "Owners and admins can create channels via membership" on public.channels;
create policy "Owners and admins can create channels via membership"
on public.channels
for insert
to authenticated
with check (public.is_server_owner(server_id) or public.is_server_admin(server_id));

drop policy if exists "Owners and admins can update channels via membership" on public.channels;
create policy "Owners and admins can update channels via membership"
on public.channels
for update
to authenticated
using (public.is_server_owner(server_id) or public.is_server_admin(server_id))
with check (public.is_server_owner(server_id) or public.is_server_admin(server_id));

drop policy if exists "Owners and admins can delete channels via membership" on public.channels;
create policy "Owners and admins can delete channels via membership"
on public.channels
for delete
to authenticated
using (public.is_server_owner(server_id) or public.is_server_admin(server_id));
