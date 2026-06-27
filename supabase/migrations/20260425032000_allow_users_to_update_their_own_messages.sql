create policy "Allow users to update their own messages"
on public.messages
for update
to authenticated
using (sender_id = auth.uid())
with check (sender_id = auth.uid());

create policy "Allow users to update their own direct messages"
on public.direct_messages
for update
to authenticated
using (sender_id = auth.uid())
with check (sender_id = auth.uid());
