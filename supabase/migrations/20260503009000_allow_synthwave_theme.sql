alter table public.user_settings
  drop constraint if exists user_settings_app_theme_check;

alter table public.user_settings
  add constraint user_settings_app_theme_check
  check (app_theme in ('default', 'dark', 'light', 'synthwave', 'native_frosted', 'clear', 'hakerman', 'custom'));

alter table public.servers
  drop constraint if exists servers_theme_id_check;

alter table public.servers
  add constraint servers_theme_id_check
  check (theme_id in ('default', 'dark', 'light', 'synthwave', 'native_frosted', 'clear', 'hakerman', 'custom'));
