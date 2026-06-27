alter table public.messages
  add column if not exists mention_user_ids uuid[] not null default '{}',
  add column if not exists mention_role_ids bigint[] not null default '{}',
  add column if not exists mention_everyone boolean not null default false,
  add column if not exists mention_here boolean not null default false;

alter table public.direct_messages
  add column if not exists mention_user_ids uuid[] not null default '{}',
  add column if not exists mention_role_ids bigint[] not null default '{}',
  add column if not exists mention_everyone boolean not null default false,
  add column if not exists mention_here boolean not null default false;
