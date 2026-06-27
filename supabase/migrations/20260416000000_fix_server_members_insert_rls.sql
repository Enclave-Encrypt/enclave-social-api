-- Allow authenticated users to join servers as themselves without exposing
-- broader write access on server membership rows.

create policy "Authenticated users can join servers as themselves"
on public.server_members
for insert
to authenticated
with check (
  user_id = auth.uid()
  and role = 'member'
);

-- Allow a server creator to create their own owner membership row during
-- server creation while preventing arbitrary owner escalation.
create policy "Server owners can create their own owner membership"
on public.server_members
for insert
to authenticated
with check (
  user_id = auth.uid()
  and role = 'owner'
  and exists (
    select 1
    from public.servers
    where servers.id = server_members.server_id
      and servers.owner_id = auth.uid()
  )
);
