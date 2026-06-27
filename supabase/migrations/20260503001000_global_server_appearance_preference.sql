alter table public.user_settings
  add column if not exists use_server_theme boolean not null default true;

create or replace function public.get_my_server_appearance_preference()
returns table (
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

  insert into public.user_settings (user_id)
  values (auth.uid())
  on conflict (user_id) do nothing;

  return query
  select
    us.user_id,
    us.use_server_theme
  from public.user_settings us
  where us.user_id = auth.uid()
  limit 1;
end;
$$;

create or replace function public.set_my_server_appearance_preference(
  p_use_server_theme boolean
)
returns table (
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

  insert into public.user_settings (
    user_id,
    use_server_theme
  )
  values (
    auth.uid(),
    coalesce(p_use_server_theme, true)
  )
  on conflict (user_id) do update
    set use_server_theme = excluded.use_server_theme;

  return query
  select
    us.user_id,
    us.use_server_theme
  from public.user_settings us
  where us.user_id = auth.uid()
  limit 1;
end;
$$;

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

  return query
  select
    p_server_id as server_id,
    us.user_id,
    us.use_server_theme
  from public.user_settings us
  where us.user_id = auth.uid()
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
  return query
  select
    p_server_id as server_id,
    pref.user_id,
    pref.use_server_theme
  from public.set_my_server_appearance_preference(p_use_server_theme) pref;
end;
$$;
