alter table public.servers
  add column if not exists theme_enabled boolean not null default false,
  add column if not exists theme_id text not null default 'default',
  add column if not exists appearance_preferences jsonb not null default '{}'::jsonb;

alter table public.servers
  drop constraint if exists servers_theme_id_check;

alter table public.servers
  add constraint servers_theme_id_check
  check (theme_id in ('default', 'dark', 'light', 'native_frosted', 'clear', 'hakerman', 'custom'));

create table if not exists public.server_theme_preferences (
  id bigint generated always as identity primary key,
  server_id bigint not null references public.servers(id) on delete cascade,
  user_id uuid not null references public.users(auth_id) on delete cascade,
  use_server_theme boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint server_theme_preferences_unique_user_server unique (server_id, user_id)
);

alter table public.server_theme_preferences enable row level security;

drop policy if exists "Users can manage their server theme preference" on public.server_theme_preferences;
create policy "Users can manage their server theme preference"
on public.server_theme_preferences
for all
to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());

create or replace function public.get_my_server_theme_preference(p_server_id bigint)
returns table (
  server_id bigint,
  user_id uuid,
  use_server_theme boolean
)
language plpgsql
security definer
set search_path to public
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  insert into public.server_theme_preferences (server_id, user_id)
  values (p_server_id, auth.uid())
  on conflict (server_id, user_id) do nothing;

  return query
  select
    stp.server_id,
    stp.user_id,
    stp.use_server_theme
  from public.server_theme_preferences stp
  where stp.server_id = p_server_id
    and stp.user_id = auth.uid()
  limit 1;
end;
$$;

create or replace function public.set_my_server_theme_preference(
  p_server_id bigint,
  p_use_server_theme boolean
)
returns table (
  server_id bigint,
  user_id uuid,
  use_server_theme boolean
)
language plpgsql
security definer
set search_path to public
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  insert into public.server_theme_preferences (
    server_id,
    user_id,
    use_server_theme,
    updated_at
  )
  values (
    p_server_id,
    auth.uid(),
    coalesce(p_use_server_theme, true),
    now()
  )
  on conflict (server_id, user_id) do update
    set use_server_theme = excluded.use_server_theme,
        updated_at = now();

  return query
  select
    stp.server_id,
    stp.user_id,
    stp.use_server_theme
  from public.server_theme_preferences stp
  where stp.server_id = p_server_id
    and stp.user_id = auth.uid()
  limit 1;
end;
$$;

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
  theme_enabled boolean,
  theme_id text,
  appearance_preferences jsonb,
  use_server_theme boolean,
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
    coalesce(s.theme_enabled, false) as theme_enabled,
    coalesce(s.theme_id, 'default') as theme_id,
    coalesce(s.appearance_preferences, '{}'::jsonb) as appearance_preferences,
    coalesce(stp.use_server_theme, true) as use_server_theme,
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
  left join public.server_theme_preferences stp
    on stp.server_id = s.id
   and stp.user_id = auth.uid()
  where s.id = p_server_id
  limit 1;
$$;
