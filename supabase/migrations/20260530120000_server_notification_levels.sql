alter table public.server_notification_settings
  add column if not exists notification_level text not null default 'all',
  add column if not exists suppress_everyone_here boolean not null default false,
  add column if not exists suppress_role_mentions boolean not null default false;

alter table public.server_notification_settings
  drop constraint if exists server_notification_settings_notification_level_check;

alter table public.server_notification_settings
  add constraint server_notification_settings_notification_level_check
  check (notification_level in ('all', 'mentions', 'nothing'));

update public.server_notification_settings
set notification_level = case
  when notify_messages = false then 'nothing'
  else 'all'
end
where notification_level = 'all'
  and notify_messages = false;
