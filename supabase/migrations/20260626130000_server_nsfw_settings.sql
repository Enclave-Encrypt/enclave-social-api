-- NSFW server flag: discovery visibility and join access require 18+ with NSFW enabled.

alter table public.servers
  add column if not exists nsfw_enabled boolean not null default false;

create or replace function public.viewer_can_access_nsfw()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.users u
    where u.auth_id = auth.uid()
      and u.age_range = '18_plus'
      and coalesce(u.nsfw_enabled, false) = true
  );
$$;

grant execute on function public.viewer_can_access_nsfw() to authenticated;

create or replace function public.enforce_server_nsfw_setting()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.nsfw_enabled is distinct from old.nsfw_enabled then
    if new.nsfw_enabled = true and not public.viewer_can_access_nsfw() then
      raise exception 'You must be 18+ with NSFW content enabled in your account settings to mark a server as NSFW.';
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists enforce_server_nsfw_setting on public.servers;
create trigger enforce_server_nsfw_setting
before update of nsfw_enabled on public.servers
for each row
execute function public.enforce_server_nsfw_setting();

create or replace function public.enforce_nsfw_server_join()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_nsfw boolean;
begin
  if lower(coalesce(new.role, '')) <> 'member' then
    return new;
  end if;

  select coalesce(s.nsfw_enabled, false)
    into v_nsfw
  from public.servers s
  where s.id = new.server_id;

  if v_nsfw and not public.viewer_can_access_nsfw() then
    raise exception 'This server is marked as NSFW. Enable NSFW content in your account settings (18+ required) to join.';
  end if;

  return new;
end;
$$;

drop trigger if exists enforce_nsfw_server_join on public.server_members;
create trigger enforce_nsfw_server_join
before insert on public.server_members
for each row
execute function public.enforce_nsfw_server_join();

create or replace function public.enforce_nsfw_server_join_request()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_nsfw boolean;
begin
  select coalesce(s.nsfw_enabled, false)
    into v_nsfw
  from public.servers s
  where s.id = new.server_id;

  if v_nsfw and not public.viewer_can_access_nsfw() then
    raise exception 'This server is marked as NSFW. Enable NSFW content in your account settings (18+ required) to request access.';
  end if;

  return new;
end;
$$;

drop trigger if exists enforce_nsfw_server_join_request on public.server_join_requests;
create trigger enforce_nsfw_server_join_request
before insert on public.server_join_requests
for each row
execute function public.enforce_nsfw_server_join_request();

drop policy if exists "Servers visible based on visibility" on public.servers;
create policy "Servers visible based on visibility"
on public.servers
for select
to authenticated
using (
  exists (
    select 1
    from public.server_members sm
    where sm.server_id = servers.id
      and sm.user_id = auth.uid()
  )
  or (
    coalesce(visibility, 'public') = 'public'
    and (
      coalesce(nsfw_enabled, false) = false
      or public.viewer_can_access_nsfw()
    )
  )
);

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
  forward_encryption boolean,
  require_approval boolean,
  server_type text,
  billing_status text,
  nsfw_enabled boolean,
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
    coalesce(s.show_posts_in_global_feed, true),
    coalesce(s.monetization_enabled, false),
    coalesce(s.theme_enabled, false),
    coalesce(s.theme_id, 'default'),
    coalesce(s.appearance_preferences, '{}'::jsonb),
    coalesce(stp.use_server_theme, true),
    coalesce(s.forward_encryption, false),
    coalesce(s.require_approval, false),
    lower(trim(coalesce(s.server_type, 'stone'))),
    coalesce(s.billing_status, 'free'),
    coalesce(s.nsfw_enabled, false),
    coalesce(
      case
        when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
        else lower(trim(coalesce(sm.role, 'member')))
      end,
      'member'
    ),
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

grant execute on function public.get_server_settings_context(bigint) to authenticated;

drop function if exists public.get_server_invite_preview(text);
drop function if exists public.join_server_by_invite(text);

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
    and (
      coalesce(s.nsfw_enabled, false) = false
      or public.viewer_can_access_nsfw()
      or exists (
        select 1
        from public.server_members sm
        where sm.server_id = s.id
          and sm.user_id = auth.uid()
      )
    )
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
  v_nsfw boolean;
  v_inserted integer := 0;
begin
  if v_user_id is null then
    raise exception 'Sign in required to join this server.';
  end if;

  select
    s.id,
    coalesce(s.require_approval, false),
    coalesce(s.nsfw_enabled, false)
    into v_server_id, v_require_approval, v_nsfw
  from public.servers s
  where lower(s.invite_code) = lower(trim(p_invite_code))
  limit 1;

  if v_server_id is null then
    raise exception 'This invite link is invalid or expired.';
  end if;

  if v_nsfw and not public.viewer_can_access_nsfw() then
    raise exception 'This server is marked as NSFW. Enable NSFW content in your account settings (18+ required) to join.';
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
