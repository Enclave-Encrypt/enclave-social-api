drop function if exists public.get_server_settings_context(bigint);

create or replace function public.get_server_settings_context(p_server_id bigint)
returns table (
  id bigint,
  display_name text,
  description text,
  category text,
  visibility text,
  rules text,
  welcome_message text,
  banner_url text,
  icon_url text,
  invite_code text,
  show_posts_in_global_feed boolean,
  monetization_enabled boolean,
  my_role text,
  nickname text
)
language sql
stable
set search_path to public
as $$
  select
    s.id,
    s.display_name,
    s.description,
    s.category,
    s.visibility,
    s.rules,
    s.welcome_message,
    s.banner_url,
    s.icon_url,
    s.invite_code,
    coalesce(s.show_posts_in_global_feed, true) as show_posts_in_global_feed,
    coalesce(s.monetization_enabled, false) as monetization_enabled,
    coalesce(
      case
        when s.owner_id = auth.uid() then 'owner'
        when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
        else lower(trim(coalesce(sm.role, 'member')))
      end,
      'member'
    ) as my_role,
    sn.nickname
  from public.servers s
  left join public.server_members sm
    on sm.server_id = s.id
   and sm.user_id = auth.uid()
  left join public.server_nicknames sn
    on sn.server_id = s.id
   and sn.user_id = auth.uid()
  where s.id = p_server_id
  limit 1;
$$;
