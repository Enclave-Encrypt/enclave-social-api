alter table public.users
  drop constraint if exists users_app_theme_check;

alter table public.users
  add constraint users_app_theme_check
  check (app_theme in ('default', 'dark', 'light', 'native_frosted', 'clear', 'hakerman', 'custom'));

alter table public.user_settings
  drop constraint if exists user_settings_app_theme_check;

alter table public.user_settings
  add constraint user_settings_app_theme_check
  check (app_theme in ('default', 'dark', 'light', 'native_frosted', 'clear', 'hakerman', 'custom'));
