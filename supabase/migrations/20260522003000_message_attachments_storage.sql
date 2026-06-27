insert into storage.buckets (id, name, public)
values ('message-attachments', 'message-attachments', false)
on conflict (id) do nothing;

drop policy if exists "Authenticated users can upload encrypted message attachments" on storage.objects;
create policy "Authenticated users can upload encrypted message attachments"
on storage.objects for insert
to authenticated
with check (
  bucket_id = 'message-attachments'
  and owner = auth.uid()
);

drop policy if exists "Authenticated users can read encrypted message attachments" on storage.objects;
create policy "Authenticated users can read encrypted message attachments"
on storage.objects for select
to authenticated
using (bucket_id = 'message-attachments');

drop policy if exists "Attachment owners can delete encrypted message attachments" on storage.objects;
create policy "Attachment owners can delete encrypted message attachments"
on storage.objects for delete
to authenticated
using (
  bucket_id = 'message-attachments'
  and owner = auth.uid()
);
