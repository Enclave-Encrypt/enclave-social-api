-- Admin role removal must clear subscription roles and paid memberships, not only primary role.

create or replace function public.revoke_server_member_role(
  p_member_id bigint,
  p_role_id bigint
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  target_member public.server_members%rowtype;
  target_role public.server_roles%rowtype;
  tier_row record;
  default_member_role_id bigint;
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

  if lower(coalesce(target_role.name, '')) = 'owner' then
    raise exception 'Cannot revoke the owner role directly';
  end if;

  if lower(coalesce(target_member.role, '')) = 'owner'
     and not public.is_server_owner(target_member.server_id) then
    raise exception 'Only owners can change another owner''s roles';
  end if;

  if not (
    public.is_server_owner(target_member.server_id)
    or public.is_server_admin(target_member.server_id)
  ) then
    raise exception 'Missing permission to revoke roles';
  end if;

  for tier_row in
    select st.id as tier_id
    from public.subscription_tiers st
    where st.server_id = target_member.server_id
      and st.role_id = p_role_id
  loop
    perform public.grant_server_tier_role(
      target_member.server_id,
      tier_row.tier_id,
      target_member.user_id,
      'canceled'
    );
  end loop;

  delete from public.server_member_roles
  where server_id = target_member.server_id
    and user_id = target_member.user_id
    and role_id = p_role_id;

  if target_member.role_id = p_role_id
     or lower(trim(coalesce(target_member.role, ''))) = lower(trim(coalesce(target_role.name, ''))) then
    select sr.id
    into default_member_role_id
    from public.server_roles sr
    where sr.server_id = target_member.server_id
      and lower(trim(coalesce(sr.name, ''))) = 'member'
    order by sr.is_default desc, sr.id asc
    limit 1;

    update public.server_members
    set role = 'member',
        role_id = coalesce(default_member_role_id, target_member.role_id)
    where id = target_member.id;
  end if;
end;
$$;

create or replace function public.assign_server_member_role(
  p_member_id bigint,
  p_role_id bigint
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  target_member public.server_members%rowtype;
  target_role public.server_roles%rowtype;
  tier_row record;
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

  if lower(coalesce(target_role.name, '')) = 'owner' then
    if not public.is_server_owner(target_member.server_id) then
      raise exception 'Only owners can assign the owner role';
    end if;
  elsif lower(coalesce(target_member.role, '')) = 'owner' then
    if not public.is_server_owner(target_member.server_id) then
      raise exception 'Only owners can change another owner''s role';
    end if;
  elsif not (
    public.is_server_owner(target_member.server_id)
    or public.is_server_admin(target_member.server_id)
  ) then
    raise exception 'Missing permission to assign roles';
  end if;

  update public.server_members
  set role = lower(trim(target_role.name)),
      role_id = target_role.id
  where id = target_member.id;

  if lower(trim(coalesce(target_role.name, ''))) = 'member' then
    for tier_row in
      select sts.tier_id
      from public.server_tier_subscriptions sts
      where sts.server_id = target_member.server_id
        and sts.user_id = target_member.user_id
        and sts.status in ('active', 'trialing')
    loop
      perform public.grant_server_tier_role(
        target_member.server_id,
        tier_row.tier_id,
        target_member.user_id,
        'canceled'
      );
    end loop;
  end if;
end;
$$;

revoke all on function public.revoke_server_member_role(bigint, bigint) from public;
grant execute on function public.revoke_server_member_role(bigint, bigint) to authenticated;

revoke all on function public.assign_server_member_role(bigint, bigint) from public;
grant execute on function public.assign_server_member_role(bigint, bigint) to authenticated;
