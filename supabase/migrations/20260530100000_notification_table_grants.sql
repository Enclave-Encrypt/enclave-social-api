-- Ensure client table access works without RPC schema reload (remote may lag on new functions).
grant select, insert, update, delete on public.conversation_mutes to authenticated;
grant select, insert, update, delete on public.server_notification_settings to authenticated;
