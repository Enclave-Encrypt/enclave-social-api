create or replace function public.guard_server_owner_membership()
returns trigger
language plpgsql
security definer
set search_path to public
as $$
declare
  owner_count bigint;
  server_exists boolean;
begin
  if tg_op = 'DELETE' then
    select exists (
      select 1
      from public.servers s
      where s.id = old.server_id
    )
    into server_exists;

    if not server_exists then
      return old;
    end if;

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
set search_path to public
as $$
declare
  server_exists boolean;
begin
  if tg_op = 'DELETE' then
    select exists (
      select 1
      from public.servers s
      where s.id = old.server_id
    )
    into server_exists;

    if not server_exists then
      return old;
    end if;

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
