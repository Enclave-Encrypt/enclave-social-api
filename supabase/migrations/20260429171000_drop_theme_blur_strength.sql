alter table public.users
  drop constraint if exists users_theme_blur_strength_check;

alter table public.users
  drop column if exists theme_blur_strength;

alter table public.user_settings
  drop constraint if exists user_settings_theme_blur_strength_check;

alter table public.user_settings
  drop column if exists theme_blur_strength;

drop function if exists public.get_my_user_settings();

drop function if exists public.upsert_my_user_settings(
  text,
  text,
  text,
  boolean
);

create or replace function public.get_my_user_settings()
returns table (
  user_id uuid,
  dm_privacy text,
  presence text,
  app_theme text,
  nsfw_enabled boolean,
  created_at timestamptz
)
language plpgsql
security definer
set search_path to public
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  insert into public.user_settings (user_id)
  values (auth.uid())
  on conflict (user_id) do nothing;

  return query
  select
    us.user_id,
    us.dm_privacy,
    us.presence,
    us.app_theme,
    us.nsfw_enabled,
    us.created_at
  from public.user_settings us
  where us.user_id = auth.uid()
  limit 1;
end;
$$;

create or replace function public.upsert_my_user_settings(
  p_dm_privacy text default null,
  p_presence text default null,
  p_app_theme text default null,
  p_nsfw_enabled boolean default null
)
returns table (
  user_id uuid,
  dm_privacy text,
  presence text,
  app_theme text,
  nsfw_enabled boolean,
  created_at timestamptz
)
language plpgsql
security definer
set search_path to public
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  insert into public.user_settings (
    user_id,
    dm_privacy,
    presence,
    app_theme,
    nsfw_enabled
  )
  values (
    auth.uid(),
    coalesce(p_dm_privacy, 'everyone'),
    coalesce(p_presence, 'online'),
    coalesce(p_app_theme, 'default'),
    coalesce(p_nsfw_enabled, false)
  )
  on conflict (user_id) do update
    set dm_privacy = coalesce(p_dm_privacy, public.user_settings.dm_privacy),
        presence = coalesce(p_presence, public.user_settings.presence),
        app_theme = coalesce(p_app_theme, public.user_settings.app_theme),
        nsfw_enabled = coalesce(p_nsfw_enabled, public.user_settings.nsfw_enabled);

  return query
  select
    us.user_id,
    us.dm_privacy,
    us.presence,
    us.app_theme,
    us.nsfw_enabled,
    us.created_at
  from public.user_settings us
  where us.user_id = auth.uid()
  limit 1;
end;
$$;
