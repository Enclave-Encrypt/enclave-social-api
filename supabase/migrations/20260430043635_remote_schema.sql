set check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.upsert_my_user_settings(p_dm_privacy text DEFAULT NULL::text, p_presence text DEFAULT NULL::text, p_app_theme text DEFAULT NULL::text, p_theme_blur_strength integer DEFAULT NULL::integer, p_nsfw_enabled boolean DEFAULT NULL::boolean)
 RETURNS TABLE(user_id uuid, dm_privacy text, presence text, app_theme text, theme_blur_strength integer, nsfw_enabled boolean, created_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  insert into public.user_settings (
    user_id,
    dm_privacy,
    presence,
    app_theme,
    theme_blur_strength,
    nsfw_enabled
  )
  values (
    auth.uid(),
    coalesce(p_dm_privacy, 'everyone'),
    coalesce(p_presence, 'online'),
    coalesce(p_app_theme, 'default'),
    coalesce(p_theme_blur_strength, 10),
    coalesce(p_nsfw_enabled, false)
  )
  on conflict (user_id) do update
    set dm_privacy = coalesce(p_dm_privacy, public.user_settings.dm_privacy),
        presence = coalesce(p_presence, public.user_settings.presence),
        app_theme = coalesce(p_app_theme, public.user_settings.app_theme),
        theme_blur_strength = coalesce(p_theme_blur_strength, public.user_settings.theme_blur_strength),
        nsfw_enabled = coalesce(p_nsfw_enabled, public.user_settings.nsfw_enabled);

  return query
  select
    us.user_id,
    us.dm_privacy,
    us.presence,
    us.app_theme,
    us.theme_blur_strength,
    us.nsfw_enabled,
    us.created_at
  from public.user_settings us
  where us.user_id = auth.uid()
  limit 1;
end;
$function$
;


