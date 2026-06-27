-- Global notification prefs on user_settings
alter table public.user_settings
  add column if not exists notify_push_enabled boolean not null default true,
  add column if not exists notify_dm_messages boolean not null default true,
  add column if not exists notify_server_messages boolean not null default true;

-- Per-conversation mutes (DM or group)
create table if not exists public.conversation_mutes (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  peer_user_id uuid references auth.users (id) on delete cascade,
  group_chat_id uuid references public.dm_group_chats (id) on delete cascade,
  muted_until timestamptz,
  created_at timestamptz not null default now(),
  constraint conversation_mutes_target_check check (
    (peer_user_id is not null and group_chat_id is null)
    or (peer_user_id is null and group_chat_id is not null)
  )
);

create unique index if not exists conversation_mutes_user_peer_idx
  on public.conversation_mutes (user_id, peer_user_id)
  where peer_user_id is not null;

create unique index if not exists conversation_mutes_user_group_idx
  on public.conversation_mutes (user_id, group_chat_id)
  where group_chat_id is not null;

alter table public.conversation_mutes enable row level security;

drop policy if exists "Users manage own conversation mutes" on public.conversation_mutes;
create policy "Users manage own conversation mutes"
  on public.conversation_mutes
  for all
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

-- Per-server notification overrides
create table if not exists public.server_notification_settings (
  user_id uuid not null references auth.users (id) on delete cascade,
  server_id bigint not null references public.servers (id) on delete cascade,
  notify_messages boolean not null default true,
  muted_until timestamptz,
  updated_at timestamptz not null default now(),
  primary key (user_id, server_id)
);

alter table public.server_notification_settings enable row level security;

drop policy if exists "Users manage own server notification settings" on public.server_notification_settings;
create policy "Users manage own server notification settings"
  on public.server_notification_settings
  for all
  to authenticated
  using (user_id = auth.uid())
  with check (user_id = auth.uid());

grant select, insert, update, delete on public.conversation_mutes to authenticated;
grant select, insert, update, delete on public.server_notification_settings to authenticated;

-- Extend user settings RPCs
drop function if exists public.get_my_user_settings();
drop function if exists public.upsert_my_user_settings(text, text, text, jsonb, boolean);

create or replace function public.get_my_user_settings()
returns table (
  user_id uuid,
  dm_privacy text,
  presence text,
  app_theme text,
  appearance_preferences jsonb,
  nsfw_enabled boolean,
  notify_push_enabled boolean,
  notify_dm_messages boolean,
  notify_server_messages boolean,
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
    us.appearance_preferences,
    us.nsfw_enabled,
    us.notify_push_enabled,
    us.notify_dm_messages,
    us.notify_server_messages,
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
  p_appearance_preferences jsonb default null,
  p_nsfw_enabled boolean default null,
  p_notify_push_enabled boolean default null,
  p_notify_dm_messages boolean default null,
  p_notify_server_messages boolean default null
)
returns table (
  user_id uuid,
  dm_privacy text,
  presence text,
  app_theme text,
  appearance_preferences jsonb,
  nsfw_enabled boolean,
  notify_push_enabled boolean,
  notify_dm_messages boolean,
  notify_server_messages boolean,
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
    appearance_preferences,
    nsfw_enabled,
    notify_push_enabled,
    notify_dm_messages,
    notify_server_messages
  )
  values (
    auth.uid(),
    coalesce(p_dm_privacy, 'everyone'),
    coalesce(p_presence, 'online'),
    coalesce(p_app_theme, 'default'),
    coalesce(p_appearance_preferences, '{}'::jsonb),
    coalesce(p_nsfw_enabled, false),
    coalesce(p_notify_push_enabled, true),
    coalesce(p_notify_dm_messages, true),
    coalesce(p_notify_server_messages, true)
  )
  on conflict (user_id) do update
    set dm_privacy = coalesce(p_dm_privacy, public.user_settings.dm_privacy),
        presence = coalesce(p_presence, public.user_settings.presence),
        app_theme = coalesce(p_app_theme, public.user_settings.app_theme),
        appearance_preferences = coalesce(
          p_appearance_preferences,
          public.user_settings.appearance_preferences
        ),
        nsfw_enabled = coalesce(p_nsfw_enabled, public.user_settings.nsfw_enabled),
        notify_push_enabled = coalesce(
          p_notify_push_enabled,
          public.user_settings.notify_push_enabled
        ),
        notify_dm_messages = coalesce(
          p_notify_dm_messages,
          public.user_settings.notify_dm_messages
        ),
        notify_server_messages = coalesce(
          p_notify_server_messages,
          public.user_settings.notify_server_messages
        );

  return query
  select
    us.user_id,
    us.dm_privacy,
    us.presence,
    us.app_theme,
    us.appearance_preferences,
    us.nsfw_enabled,
    us.notify_push_enabled,
    us.notify_dm_messages,
    us.notify_server_messages,
    us.created_at
  from public.user_settings us
  where us.user_id = auth.uid()
  limit 1;
end;
$$;

grant execute on function public.get_my_user_settings() to authenticated;
grant execute on function public.upsert_my_user_settings(
  text, text, text, jsonb, boolean, boolean, boolean, boolean
) to authenticated;

create or replace function public.get_my_conversation_mutes()
returns table (
  peer_user_id uuid,
  group_chat_id uuid,
  muted_until timestamptz
)
language sql
security definer
set search_path to public
stable
as $$
  select cm.peer_user_id, cm.group_chat_id, cm.muted_until
  from public.conversation_mutes cm
  where cm.user_id = auth.uid()
    and (cm.muted_until is null or cm.muted_until > now());
$$;

grant execute on function public.get_my_conversation_mutes() to authenticated;

create or replace function public.upsert_conversation_mute(
  p_peer_user_id uuid default null,
  p_group_chat_id uuid default null,
  p_muted_until timestamptz default null
)
returns void
language plpgsql
security definer
set search_path to public
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  if (p_peer_user_id is null) = (p_group_chat_id is null) then
    raise exception 'Specify exactly one of peer_user_id or group_chat_id';
  end if;

  if p_peer_user_id is not null then
    delete from public.conversation_mutes cm
    where cm.user_id = auth.uid()
      and cm.peer_user_id = p_peer_user_id;

    insert into public.conversation_mutes (user_id, peer_user_id, muted_until)
    values (auth.uid(), p_peer_user_id, p_muted_until);
  else
    delete from public.conversation_mutes cm
    where cm.user_id = auth.uid()
      and cm.group_chat_id = p_group_chat_id;

    insert into public.conversation_mutes (user_id, group_chat_id, muted_until)
    values (auth.uid(), p_group_chat_id, p_muted_until);
  end if;
end;
$$;

grant execute on function public.upsert_conversation_mute(uuid, uuid, timestamptz) to authenticated;

create or replace function public.clear_conversation_mute(
  p_peer_user_id uuid default null,
  p_group_chat_id uuid default null
)
returns void
language plpgsql
security definer
set search_path to public
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  delete from public.conversation_mutes cm
  where cm.user_id = auth.uid()
    and (
      (p_peer_user_id is not null and cm.peer_user_id = p_peer_user_id)
      or (p_group_chat_id is not null and cm.group_chat_id = p_group_chat_id)
    );
end;
$$;

grant execute on function public.clear_conversation_mute(uuid, uuid) to authenticated;

create or replace function public.get_server_notification_settings(p_server_id bigint)
returns table (
  notify_messages boolean,
  muted_until timestamptz
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
    coalesce(sns.notify_messages, true),
    sns.muted_until
  from public.server_notification_settings sns
  where sns.user_id = auth.uid()
    and sns.server_id = p_server_id
  limit 1;

  if not found then
    return query select true::boolean, null::timestamptz;
  end if;
end;
$$;

grant execute on function public.get_server_notification_settings(bigint) to authenticated;

create or replace function public.upsert_server_notification_settings(
  p_server_id bigint,
  p_notify_messages boolean default null,
  p_muted_until timestamptz default null,
  p_clear_mute boolean default false
)
returns table (
  notify_messages boolean,
  muted_until timestamptz
)
language plpgsql
security definer
set search_path to public
as $$
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  insert into public.server_notification_settings (
    user_id,
    server_id,
    notify_messages,
    muted_until,
    updated_at
  )
  values (
    auth.uid(),
    p_server_id,
    coalesce(p_notify_messages, true),
    p_muted_until,
    now()
  )
  on conflict (user_id, server_id) do update
    set notify_messages = coalesce(
          p_notify_messages,
          public.server_notification_settings.notify_messages
        ),
        muted_until = case
          when p_clear_mute then null
          when p_muted_until is not null then p_muted_until
          else public.server_notification_settings.muted_until
        end,
        updated_at = now();

  return query
  select sns.notify_messages, sns.muted_until
  from public.server_notification_settings sns
  where sns.user_id = auth.uid()
    and sns.server_id = p_server_id;
end;
$$;

grant execute on function public.upsert_server_notification_settings(
  bigint, boolean, timestamptz, boolean
) to authenticated;
