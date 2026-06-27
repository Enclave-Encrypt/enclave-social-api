create extension if not exists pg_trgm;

create index if not exists direct_messages_conversation_created_at_idx
  on public.direct_messages (sender_id, recipient_id, created_at desc);

create index if not exists users_username_trgm_idx
  on public.users
  using gin (username gin_trgm_ops);

create index if not exists users_email_trgm_idx
  on public.users
  using gin (email gin_trgm_ops);

create index if not exists servers_display_name_trgm_idx
  on public.servers
  using gin (display_name gin_trgm_ops);

create index if not exists servers_handle_trgm_idx
  on public.servers
  using gin (handle gin_trgm_ops);

create index if not exists servers_description_trgm_idx
  on public.servers
  using gin (description gin_trgm_ops);
