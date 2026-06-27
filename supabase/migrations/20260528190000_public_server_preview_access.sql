-- Public server preview: non-members can see member list and related directory data.
-- server_members SELECT is limited to shared-server membership via RLS.

create or replace function public.user_can_view_server(p_server_id bigint)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.servers s
    where s.id = p_server_id
      and (
        coalesce(s.visibility, 'public') = 'public'
        or (
          auth.uid() is not null
          and (
            s.owner_id = auth.uid()
            or exists (
              select 1
              from public.server_members sm
              where sm.server_id = s.id
                and sm.user_id = auth.uid()
            )
          )
        )
      )
  );
$$;

revoke all on function public.user_can_view_server(bigint) from public;
grant execute on function public.user_can_view_server(bigint) to authenticated;
grant execute on function public.user_can_view_server(bigint) to anon;

create or replace function public.get_server_member_list(p_server_id bigint)
returns table (
  auth_id uuid,
  username text,
  display_name text,
  avatar_url text,
  presence text,
  tier text,
  status_message text,
  last_seen timestamptz,
  role text
)
language sql
stable
security definer
set search_path = public
as $$
  select
    u.auth_id,
    u.username,
    u.display_name,
    u.avatar_url,
    u.presence,
    u.tier,
    u.status_message,
    u.last_seen,
    case
      when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
      else lower(trim(coalesce(sm.role, 'member')))
    end as role
  from public.server_members sm
  join public.users u on u.auth_id = sm.user_id
  where sm.server_id = p_server_id
    and public.user_can_view_server(p_server_id)
  order by sm.created_at asc;
$$;

revoke all on function public.get_server_member_list(bigint) from public;
grant execute on function public.get_server_member_list(bigint) to authenticated;
grant execute on function public.get_server_member_list(bigint) to anon;

-- Align member counts with the same visibility gate.
create or replace function public.get_server_member_counts(p_server_ids bigint[])
returns table (server_id bigint, member_count integer)
language sql
stable
security definer
set search_path = public
as $$
  select
    s.id as server_id,
    count(sm.user_id)::integer as member_count
  from public.servers s
  left join public.server_members sm on sm.server_id = s.id
  where s.id = any(coalesce(p_server_ids, array[]::bigint[]))
    and public.user_can_view_server(s.id)
  group by s.id;
$$;

-- Settings member picker: same visibility gate (no email leak to previewers).
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
security definer
set search_path = public
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
      and public.user_can_view_server(p_server_id)
  ),
  extra_roles as (
    select
      smr.user_id,
      array_agg(distinct lower(sr.name) order by lower(sr.name)) as role_names
    from public.server_member_roles smr
    join public.server_roles sr
      on sr.id = smr.role_id
    where smr.server_id = p_server_id
    group by smr.user_id
  ),
  viewer as (
    select
      public.is_server_owner(p_server_id) as is_owner,
      public.is_server_admin(p_server_id) as is_admin
  )
  select
    n.id,
    n.server_id,
    n.user_id,
    n.normalized_role as role,
    array(
      select distinct value
      from unnest(array[n.normalized_role] || coalesce(er.role_names, array[]::text[])) as value
      where value is not null and value <> ''
    )::text[] as roles,
    u.username,
    u.display_name,
    u.avatar_url,
    case
      when (select is_owner or is_admin from viewer) then u.email
      else null
    end as email
  from normalized n
  join public.users u
    on u.auth_id = n.user_id
  left join extra_roles er
    on er.user_id = n.user_id
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
