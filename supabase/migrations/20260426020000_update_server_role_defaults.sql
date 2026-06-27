create or replace function public.create_default_server_roles_and_owner_membership()
returns trigger
language plpgsql
security definer
as $$
declare
  owner_role_id bigint;
begin
  insert into public.server_roles (server_id, name, color, permissions, position, is_default)
  values
    (
      new.id,
      'Owner',
      '#F0B232',
      '{"manage_channels": true, "manage_roles": true, "manage_server": true, "kick_members": true, "ban_members": true, "manage_messages": true}',
      400,
      true
    ),
    (
      new.id,
      'Admin',
      '#FF6B00',
      '{"manage_channels": true, "manage_roles": true, "manage_server": true, "kick_members": true, "ban_members": true, "manage_messages": true}',
      300,
      true
    ),
    (
      new.id,
      'Mod',
      '#00CC66',
      '{"manage_channels": false, "manage_roles": false, "manage_server": false, "kick_members": true, "ban_members": false, "manage_messages": true}',
      200,
      true
    ),
    (
      new.id,
      'Member',
      '#999999',
      '{"manage_channels": false, "manage_roles": false, "manage_server": false, "kick_members": false, "ban_members": false, "manage_messages": false}',
      100,
      true
    );

  select sr.id
    into owner_role_id
  from public.server_roles sr
  where sr.server_id = new.id
    and lower(sr.name) = 'owner'
  order by sr.position desc, sr.id asc
  limit 1;

  insert into public.server_members (server_id, user_id, role, role_id)
  values (new.id, new.owner_id, 'owner', owner_role_id)
  on conflict (server_id, user_id)
  do update
    set role = 'owner',
        role_id = excluded.role_id;

  return new;
end;
$$;

create or replace function public.guard_server_owner_membership()
returns trigger
language plpgsql
security definer
as $$
declare
  owner_count bigint;
begin
  if tg_op = 'DELETE' then
    if lower(coalesce(old.role, '')) = 'owner' then
      select count(*)
        into owner_count
      from public.server_members sm
      where sm.server_id = old.server_id
        and lower(coalesce(sm.role, '')) = 'owner';

      if owner_count <= 1 then
        raise exception 'Servers must have at least one owner';
      end if;
    end if;

    return old;
  end if;

  if tg_op = 'UPDATE' then
    if lower(coalesce(old.role, '')) = 'owner'
       and lower(coalesce(new.role, '')) <> 'owner' then
      select count(*)
        into owner_count
      from public.server_members sm
      where sm.server_id = old.server_id
        and lower(coalesce(sm.role, '')) = 'owner';

      if owner_count <= 1 then
        raise exception 'Servers must have at least one owner';
      end if;
    end if;

    return new;
  end if;

  return coalesce(new, old);
end;
$$;

create or replace function public.protect_builtin_server_roles()
returns trigger
language plpgsql
security definer
as $$
begin
  if tg_op = 'DELETE' then
    if lower(coalesce(old.name, '')) in ('owner', 'member') then
      raise exception 'The % role cannot be deleted', old.name;
    end if;

    return old;
  end if;

  if tg_op = 'UPDATE' then
    if lower(coalesce(old.name, '')) = 'owner' then
      new.name := 'Owner';
      new.permissions := '{"manage_channels": true, "manage_roles": true, "manage_server": true, "kick_members": true, "ban_members": true, "manage_messages": true}'::jsonb;
      new.position := 400;
      new.is_default := true;
    elsif lower(coalesce(old.name, '')) = 'member' then
      new.name := 'Member';
      new.position := 100;
      new.is_default := true;
    end if;

    return new;
  end if;

  return coalesce(new, old);
end;
$$;

drop trigger if exists on_server_created_owner on public.servers;
drop trigger if exists on_server_created_roles on public.servers;

create trigger on_server_created_defaults
after insert on public.servers
for each row
execute function public.create_default_server_roles_and_owner_membership();

drop trigger if exists guard_last_owner_on_server_members on public.server_members;

create trigger guard_last_owner_on_server_members
before update or delete on public.server_members
for each row
execute function public.guard_server_owner_membership();

drop trigger if exists protect_builtin_server_roles on public.server_roles;

create trigger protect_builtin_server_roles
before update or delete on public.server_roles
for each row
execute function public.protect_builtin_server_roles();

update public.server_roles
set name = 'Owner',
    color = '#F0B232',
    permissions = '{"manage_channels": true, "manage_roles": true, "manage_server": true, "kick_members": true, "ban_members": true, "manage_messages": true}'::jsonb,
    position = 400,
    is_default = true
where lower(name) = 'owner';

update public.server_roles
set name = 'Admin',
    color = '#FF6B00',
    permissions = '{"manage_channels": true, "manage_roles": true, "manage_server": true, "kick_members": true, "ban_members": true, "manage_messages": true}'::jsonb,
    position = 300,
    is_default = true
where lower(name) = 'admin';

update public.server_roles
set name = 'Mod',
    color = '#00CC66',
    permissions = '{"manage_channels": false, "manage_roles": false, "manage_server": false, "kick_members": true, "ban_members": false, "manage_messages": true}'::jsonb,
    position = 200,
    is_default = true
where lower(name) in ('mod', 'moderator');

update public.server_roles
set name = 'Member',
    color = '#999999',
    permissions = '{"manage_channels": false, "manage_roles": false, "manage_server": false, "kick_members": false, "ban_members": false, "manage_messages": false}'::jsonb,
    position = 100,
    is_default = true
where lower(name) = 'member';

insert into public.server_roles (server_id, name, color, permissions, position, is_default)
select
  s.id,
  'Owner',
  '#F0B232',
  '{"manage_channels": true, "manage_roles": true, "manage_server": true, "kick_members": true, "ban_members": true, "manage_messages": true}'::jsonb,
  400,
  true
from public.servers s
where not exists (
  select 1
  from public.server_roles sr
  where sr.server_id = s.id
    and lower(sr.name) = 'owner'
);

insert into public.server_roles (server_id, name, color, permissions, position, is_default)
select
  s.id,
  'Admin',
  '#FF6B00',
  '{"manage_channels": true, "manage_roles": true, "manage_server": true, "kick_members": true, "ban_members": true, "manage_messages": true}'::jsonb,
  300,
  true
from public.servers s
where not exists (
  select 1
  from public.server_roles sr
  where sr.server_id = s.id
    and lower(sr.name) = 'admin'
);

insert into public.server_roles (server_id, name, color, permissions, position, is_default)
select
  s.id,
  'Mod',
  '#00CC66',
  '{"manage_channels": false, "manage_roles": false, "manage_server": false, "kick_members": true, "ban_members": false, "manage_messages": true}'::jsonb,
  200,
  true
from public.servers s
where not exists (
  select 1
  from public.server_roles sr
  where sr.server_id = s.id
    and lower(sr.name) in ('mod', 'moderator')
);

insert into public.server_roles (server_id, name, color, permissions, position, is_default)
select
  s.id,
  'Member',
  '#999999',
  '{"manage_channels": false, "manage_roles": false, "manage_server": false, "kick_members": false, "ban_members": false, "manage_messages": false}'::jsonb,
  100,
  true
from public.servers s
where not exists (
  select 1
  from public.server_roles sr
  where sr.server_id = s.id
    and lower(sr.name) = 'member'
);

update public.server_members
set role = 'mod'
where lower(coalesce(role, '')) = 'moderator';

update public.server_members sm
set role = 'owner',
    role_id = sr.id
from public.servers s
join public.server_roles sr
  on sr.server_id = s.id
 and lower(sr.name) = 'owner'
where sm.server_id = s.id
  and sm.user_id = s.owner_id;

insert into public.server_members (server_id, user_id, role, role_id)
select
  s.id,
  s.owner_id,
  'owner',
  sr.id
from public.servers s
join public.server_roles sr
  on sr.server_id = s.id
 and lower(sr.name) = 'owner'
where s.owner_id is not null
  and not exists (
    select 1
    from public.server_members sm
    where sm.server_id = s.id
      and sm.user_id = s.owner_id
  );
