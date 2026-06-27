alter table public.messages
  add column if not exists edited_at timestamp with time zone;

alter table public.direct_messages
  add column if not exists edited_at timestamp with time zone;
