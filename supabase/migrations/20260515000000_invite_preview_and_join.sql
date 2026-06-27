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
  already_member boolean
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
    ) as already_member
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
  already_member boolean
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_server_id bigint;
  v_inserted integer := 0;
begin
  if v_user_id is null then
    raise exception 'Sign in required to join this server.';
  end if;

  select s.id into v_server_id
  from public.servers s
  where lower(s.invite_code) = lower(trim(p_invite_code))
  limit 1;

  if v_server_id is null then
    raise exception 'This invite link is invalid or expired.';
  end if;

  insert into public.server_members (server_id, user_id, role)
  values (v_server_id, v_user_id, 'member')
  on conflict (server_id, user_id) do nothing;

  get diagnostics v_inserted = row_count;

  if v_inserted > 0 then
    perform public.handle_server_join_key_access(v_server_id, v_user_id);
  end if;

  return query
    select *
    from public.get_server_invite_preview(p_invite_code);
end;
$$;

grant execute on function public.get_server_invite_preview(text) to anon, authenticated;
grant execute on function public.join_server_by_invite(text) to authenticated;
