create or replace function public.assign_server_member_role(
  p_member_id bigint,
  p_role_id bigint
)
returns void
language plpgsql
security definer
set search_path to public
as $$
declare
  target_member public.server_members%rowtype;
  target_role public.server_roles%rowtype;
  actor_is_owner boolean;
  actor_is_admin boolean;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;

  select *
  into target_member
  from public.server_members
  where id = p_member_id;

  if not found then
    raise exception 'Member not found';
  end if;

  select *
  into target_role
  from public.server_roles
  where id = p_role_id
    and server_id = target_member.server_id;

  if not found then
    raise exception 'Role not found';
  end if;

  if target_member.user_id = auth.uid() then
    raise exception 'You cannot change your own role';
  end if;

  actor_is_owner := public.is_server_owner(target_member.server_id);
  actor_is_admin := public.is_server_admin(target_member.server_id);

  if lower(coalesce(target_role.name, '')) = 'owner' then
    if not actor_is_owner then
      raise exception 'Only owners can assign the owner role';
    end if;
  elsif lower(coalesce(target_member.role, '')) = 'owner' then
    if not actor_is_owner then
      raise exception 'Only owners can change another owner''s role';
    end if;
  elsif not (actor_is_owner or actor_is_admin) then
    raise exception 'Missing permission to assign roles';
  end if;

  update public.server_members
  set role = lower(target_role.name),
      role_id = target_role.id
  where id = target_member.id;
end;
$$;

grant execute on function public.assign_server_member_role(bigint, bigint) to authenticated;

alter table public.server_members replica identity full;
alter table public.server_roles replica identity full;

do $$
begin
  alter publication supabase_realtime add table public.server_members;
exception
  when duplicate_object then null;
end $$;

do $$
begin
  alter publication supabase_realtime add table public.server_roles;
exception
  when duplicate_object then null;
end $$;
