alter table public.servers
  add column if not exists require_approval boolean not null default false;

create table if not exists public.server_join_requests (
  id bigint generated always as identity primary key,
  server_id bigint not null references public.servers(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  status text not null default 'pending',
  message text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by uuid references auth.users(id) on delete set null,
  constraint server_join_requests_server_user_key unique (server_id, user_id),
  constraint server_join_requests_status_check check (status in ('pending', 'approved', 'denied'))
);

create index if not exists server_join_requests_server_status_idx
  on public.server_join_requests(server_id, status, created_at);

alter table public.server_join_requests enable row level security;

drop policy if exists "Users can read their own join requests" on public.server_join_requests;
create policy "Users can read their own join requests"
on public.server_join_requests
for select
to authenticated
using (user_id = auth.uid());

drop policy if exists "Server admins can read join requests" on public.server_join_requests;
create policy "Server admins can read join requests"
on public.server_join_requests
for select
to authenticated
using (public.is_server_admin(server_id));

drop policy if exists "Server admins can update join requests" on public.server_join_requests;
create policy "Server admins can update join requests"
on public.server_join_requests
for update
to authenticated
using (public.is_server_admin(server_id))
with check (public.is_server_admin(server_id));

drop function if exists public.update_server_privacy_settings(bigint, text, boolean, boolean);
drop function if exists public.update_server_privacy_settings(bigint, text, boolean, boolean, boolean);

create or replace function public.update_server_privacy_settings(
  p_server_id bigint,
  p_visibility text,
  p_forward_encryption boolean,
  p_require_approval boolean,
  p_show_posts_in_global_feed boolean
)
returns table (
  id bigint,
  visibility text,
  forward_encryption boolean,
  require_approval boolean,
  show_posts_in_global_feed boolean
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_visibility text := lower(trim(coalesce(p_visibility, 'public')));
begin
  if auth.uid() is null then
    raise exception 'Sign in required.';
  end if;

  if v_visibility not in ('public', 'private') then
    raise exception 'Server visibility must be public or private.';
  end if;

  if not public.is_server_admin(p_server_id) then
    raise exception 'Only server owners and admins can update privacy settings.';
  end if;

  return query
    update public.servers s
    set
      visibility = v_visibility,
      forward_encryption = coalesce(p_forward_encryption, false),
      require_approval = coalesce(p_require_approval, false),
      show_posts_in_global_feed = coalesce(p_show_posts_in_global_feed, true)
    where s.id = p_server_id
    returning
      s.id,
      s.visibility,
      coalesce(s.forward_encryption, false),
      coalesce(s.require_approval, false),
      coalesce(s.show_posts_in_global_feed, true);

  if not found then
    raise exception 'Server not found.';
  end if;
end;
$$;

grant execute on function public.update_server_privacy_settings(bigint, text, boolean, boolean, boolean) to authenticated;

drop function if exists public.get_server_settings_context(bigint);

create or replace function public.get_server_settings_context(p_server_id bigint)
returns table (
  id                       bigint,
  display_name             text,
  description              text,
  category                 text,
  visibility               text,
  rules                    text,
  welcome_message          text,
  banner_url               text,
  icon_url                 text,
  invite_code              text,
  show_posts_in_global_feed boolean,
  monetization_enabled     boolean,
  theme_enabled            boolean,
  theme_id                 text,
  appearance_preferences   jsonb,
  use_server_theme         boolean,
  forward_encryption       boolean,
  require_approval         boolean,
  my_role                  text,
  nickname                 text
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
    coalesce(s.show_posts_in_global_feed, true),
    coalesce(s.monetization_enabled, false),
    coalesce(s.theme_enabled, false),
    coalesce(s.theme_id, 'default'),
    coalesce(s.appearance_preferences, '{}'::jsonb),
    coalesce(stp.use_server_theme, true),
    coalesce(s.forward_encryption, false),
    coalesce(s.require_approval, false),
    coalesce(
      case
        when s.owner_id = auth.uid() then 'owner'
        when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
        else lower(trim(coalesce(sm.role, 'member')))
      end,
      'member'
    ),
    sn.nickname
  from public.servers s
  left join public.server_members sm
    on sm.server_id = s.id and sm.user_id = auth.uid()
  left join public.server_nicknames sn
    on sn.server_id = s.id and sn.user_id = auth.uid()
  left join public.server_theme_preferences stp
    on stp.server_id = s.id and stp.user_id = auth.uid()
  where s.id = p_server_id
  limit 1;
$$;

drop function if exists public.join_server_by_invite(text);
drop function if exists public.get_server_invite_preview(text);

create or replace function public.get_server_invite_preview(p_invite_code text)
returns table (
  id bigint,
  display_name text,
  description text,
  handle text,
  icon_url text,
  banner_url text,
  category text,
  visibility text,
  member_count integer,
  already_member boolean,
  require_approval boolean,
  pending_join_request boolean,
  join_request_status text
)
language sql
stable
security definer
set search_path = public
as $$
  select
    s.id,
    s.display_name,
    s.description,
    s.handle,
    s.icon_url,
    s.banner_url,
    s.category,
    s.visibility,
    (
      select count(*)::integer
      from public.server_members sm_count
      where sm_count.server_id = s.id
    ) as member_count,
    exists (
      select 1
      from public.server_members sm
      where sm.server_id = s.id
        and sm.user_id = auth.uid()
    ) as already_member,
    coalesce(s.require_approval, false) as require_approval,
    exists (
      select 1
      from public.server_join_requests sjr
      where sjr.server_id = s.id
        and sjr.user_id = auth.uid()
        and sjr.status = 'pending'
    ) as pending_join_request,
    (
      select sjr.status
      from public.server_join_requests sjr
      where sjr.server_id = s.id
        and sjr.user_id = auth.uid()
      order by sjr.updated_at desc
      limit 1
    ) as join_request_status
  from public.servers s
  where lower(s.invite_code) = lower(trim(p_invite_code))
  limit 1;
$$;

create or replace function public.join_server_by_invite(p_invite_code text)
returns table (
  id bigint,
  display_name text,
  description text,
  handle text,
  icon_url text,
  banner_url text,
  category text,
  visibility text,
  member_count integer,
  already_member boolean,
  require_approval boolean,
  pending_join_request boolean,
  join_request_status text
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_server_id bigint;
  v_require_approval boolean;
  v_inserted integer := 0;
begin
  if v_user_id is null then
    raise exception 'Sign in required to join this server.';
  end if;

  select s.id, coalesce(s.require_approval, false)
    into v_server_id, v_require_approval
  from public.servers s
  where lower(s.invite_code) = lower(trim(p_invite_code))
  limit 1;

  if v_server_id is null then
    raise exception 'This invite link is invalid or expired.';
  end if;

  if exists (
    select 1 from public.server_members sm
    where sm.server_id = v_server_id and sm.user_id = v_user_id
  ) then
    return query select * from public.get_server_invite_preview(p_invite_code);
    return;
  end if;

  if v_require_approval then
    insert into public.server_join_requests (server_id, user_id, status)
    values (v_server_id, v_user_id, 'pending')
    on conflict (server_id, user_id) do update
      set status = 'pending',
          reviewed_at = null,
          reviewed_by = null,
          updated_at = now()
      where public.server_join_requests.status <> 'pending';

    return query select * from public.get_server_invite_preview(p_invite_code);
    return;
  end if;

  insert into public.server_members (server_id, user_id, role)
  values (v_server_id, v_user_id, 'member')
  on conflict (server_id, user_id) do nothing;

  get diagnostics v_inserted = row_count;

  if v_inserted > 0 then
    perform public.handle_server_join_key_access(v_server_id, v_user_id);
  end if;

  return query select * from public.get_server_invite_preview(p_invite_code);
end;
$$;

grant execute on function public.get_server_invite_preview(text) to anon, authenticated;
grant execute on function public.join_server_by_invite(text) to authenticated;
