alter table public.server_nicknames
  alter column nickname drop not null,
  add column if not exists enabled boolean not null default true;
