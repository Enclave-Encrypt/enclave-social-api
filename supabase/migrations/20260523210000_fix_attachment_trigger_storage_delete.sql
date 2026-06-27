-- Supabase blocks direct DELETE on storage.objects from PL/pgSQL triggers even with
-- security definer. Remove that step from both trigger functions — storage file cleanup
-- is now handled client-side via the Storage API before the message row is deleted.

create or replace function public.cleanup_message_attachment_refs_on_channel_delete()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.message_attachments
     set status = 'deleted',
         deleted_at = now()
   where channel_message_id = old.id
     and status <> 'deleted';

  return old;
end;
$$;

create or replace function public.cleanup_message_attachment_refs_on_dm_delete()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.message_attachments
     set status = 'deleted',
         deleted_at = now()
   where direct_message_id = old.id
     and status <> 'deleted';

  return old;
end;
$$;
