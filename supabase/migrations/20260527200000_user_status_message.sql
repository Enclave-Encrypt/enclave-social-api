alter table public.users
  add column if not exists status_message text;

alter table public.users
  drop constraint if exists users_status_message_length_check;

alter table public.users
  add constraint users_status_message_length_check
  check (status_message is null or char_length(status_message) <= 128);
