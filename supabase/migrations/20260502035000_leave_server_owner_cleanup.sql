create or replace function public.leave_server(p_server_id bigint)
returns void
language plpgsql
security definer
set search_path to public
as $$
declare
  current_user_id uuid := auth.uid();
  current_member public.server_members%rowtype;
  replacement_owner_id uuid;
  server_primary_owner_id uuid;
begin
  if current_user_id is null then
    raise exception 'Authentication required';
  end if;

  select owner_id
  into server_primary_owner_id
  from public.servers
  where id = p_server_id;

  select *
  into current_member
  from public.server_members
  where server_id = p_server_id
    and user_id = current_user_id;

  if not found and server_primary_owner_id is distinct from current_user_id then
    raise exception 'You are not a member of this server';
  end if;

  select sm.user_id
  into replacement_owner_id
  from public.server_members sm
  where sm.server_id = p_server_id
    and sm.user_id <> current_user_id
    and lower(coalesce(sm.role, '')) = 'owner'
  order by sm.created_at asc, sm.id asc
  limit 1;

  if (
    lower(coalesce(current_member.role, '')) = 'owner'
    or server_primary_owner_id = current_user_id
  ) and replacement_owner_id is null then
    raise exception 'You cannot leave this server because you are the only owner. Add another owner first.';
  end if;

  if server_primary_owner_id = current_user_id then
    update public.servers
    set owner_id = replacement_owner_id
    where id = p_server_id;
  end if;

  delete from public.server_nicknames
  where server_id = p_server_id
    and user_id = current_user_id;

  delete from public.server_members
  where server_id = p_server_id
    and user_id = current_user_id;
end;
$$;

grant execute on function public.leave_server(bigint) to authenticated;
