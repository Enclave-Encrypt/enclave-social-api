create index if not exists server_roles_server_id_position_idx
  on public.server_roles (server_id, position desc);

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
    coalesce(
      case
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

create or replace function public.get_server_settings_members(p_server_id bigint)
returns table (
  id bigint,
  server_id bigint,
  user_id uuid,
  role text,
  roles text[],
  username text,
  display_name text,
  avatar_url text,
  email text
)
language sql
stable
set search_path to public
as $$
  with normalized as (
    select
      sm.id,
      sm.server_id,
      sm.user_id,
      case
        when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
        else lower(trim(coalesce(sm.role, 'member')))
      end as normalized_role
    from public.server_members sm
    where sm.server_id = p_server_id
  )
  select
    n.id,
    n.server_id,
    n.user_id,
    n.normalized_role as role,
    array[n.normalized_role]::text[] as roles,
    u.username,
    u.display_name,
    u.avatar_url,
    u.email
  from normalized n
  join public.users u
    on u.auth_id = n.user_id
  order by
    case n.normalized_role
      when 'owner' then 4
      when 'admin' then 3
      when 'mod' then 2
      when 'member' then 1
      else 0
    end desc,
    coalesce(nullif(u.display_name, ''), nullif(u.username, ''), u.email, '') asc;
$$;
