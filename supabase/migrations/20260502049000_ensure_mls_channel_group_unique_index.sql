create unique index if not exists mls_groups_channel_id_uidx
  on public.mls_groups (channel_id)
  where channel_id is not null;

