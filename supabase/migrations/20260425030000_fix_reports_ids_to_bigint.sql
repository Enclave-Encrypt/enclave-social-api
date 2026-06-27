alter table public.reports
  alter column message_id type bigint
  using nullif(message_id::text, '')::bigint;

alter table public.reports
  alter column server_id type bigint
  using nullif(server_id::text, '')::bigint;
