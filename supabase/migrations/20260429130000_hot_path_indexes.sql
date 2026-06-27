create index if not exists friendships_status_requester_idx
  on public.friendships (status, requester_id);

create index if not exists friendships_status_recipient_idx
  on public.friendships (status, recipient_id);

create index if not exists server_members_user_id_idx
  on public.server_members (user_id);

create index if not exists channels_server_id_position_idx
  on public.channels (server_id, position);

create index if not exists messages_channel_id_created_at_idx
  on public.messages (channel_id, created_at desc);

create index if not exists direct_messages_sender_created_at_idx
  on public.direct_messages (sender_id, created_at desc);

create index if not exists direct_messages_recipient_created_at_idx
  on public.direct_messages (recipient_id, created_at desc);
