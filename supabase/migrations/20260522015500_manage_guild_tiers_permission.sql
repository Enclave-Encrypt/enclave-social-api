update public.server_roles
set permissions = coalesce(permissions, '{}'::jsonb) || '{"manage_guild_tiers": true}'::jsonb
where lower(coalesce(name, '')) in ('owner', 'admin');

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
      new.permissions := '{"manage_channels": true, "manage_roles": true, "manage_guild_tiers": true, "manage_server": true, "kick_members": true, "ban_members": true, "manage_messages": true}'::jsonb;
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

create or replace function public.user_can_manage_guild_tiers(
  p_server_id bigint,
  p_user_id uuid default auth.uid()
)
returns boolean
language sql
stable
security definer
set search_path to public
as $$
  select exists (
    select 1
    from public.servers s
    left join public.server_members sm
      on sm.server_id = s.id
      and sm.user_id = p_user_id
    left join public.server_roles primary_role
      on primary_role.id = sm.role_id
    where s.id = p_server_id
      and p_user_id is not null
      and (
        s.owner_id = p_user_id
        or lower(coalesce(sm.role, '')) in ('owner', 'admin')
        or coalesce((primary_role.permissions ->> 'manage_guild_tiers')::boolean, false)
        or exists (
          select 1
          from public.server_member_roles smr
          join public.server_roles sr
            on sr.id = smr.role_id
          where smr.server_id = p_server_id
            and smr.user_id = p_user_id
            and coalesce((sr.permissions ->> 'manage_guild_tiers')::boolean, false)
        )
      )
  );
$$;

grant execute on function public.user_can_manage_guild_tiers(bigint, uuid) to authenticated;

create or replace function public.user_has_server_mod_power(
  p_server_id bigint,
  p_user_id uuid
)
returns boolean
language sql
stable
security definer
set search_path to public
as $$
  select exists (
    select 1
    from public.servers s
    left join public.server_members sm
      on sm.server_id = s.id
      and sm.user_id = p_user_id
    left join public.server_roles primary_role
      on primary_role.id = sm.role_id
    where s.id = p_server_id
      and p_user_id is not null
      and (
        s.owner_id = p_user_id
        or lower(coalesce(sm.role, '')) in ('owner', 'admin', 'mod', 'moderator')
        or coalesce((primary_role.permissions ->> 'manage_server')::boolean, false)
        or coalesce((primary_role.permissions ->> 'manage_roles')::boolean, false)
        or coalesce((primary_role.permissions ->> 'manage_guild_tiers')::boolean, false)
        or coalesce((primary_role.permissions ->> 'manage_channels')::boolean, false)
        or coalesce((primary_role.permissions ->> 'ban_members')::boolean, false)
        or coalesce((primary_role.permissions ->> 'kick_members')::boolean, false)
        or coalesce((primary_role.permissions ->> 'manage_messages')::boolean, false)
        or exists (
          select 1
          from public.server_member_roles smr
          join public.server_roles sr
            on sr.id = smr.role_id
          where smr.server_id = p_server_id
            and smr.user_id = p_user_id
            and (
              coalesce((sr.permissions ->> 'manage_server')::boolean, false)
              or coalesce((sr.permissions ->> 'manage_roles')::boolean, false)
              or coalesce((sr.permissions ->> 'manage_guild_tiers')::boolean, false)
              or coalesce((sr.permissions ->> 'manage_channels')::boolean, false)
              or coalesce((sr.permissions ->> 'ban_members')::boolean, false)
              or coalesce((sr.permissions ->> 'kick_members')::boolean, false)
              or coalesce((sr.permissions ->> 'manage_messages')::boolean, false)
            )
        )
      )
  );
$$;

create or replace function public.sync_mod_power_role_perks()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  server_plan text;
  has_mod_power boolean;
begin
  if tg_op = 'DELETE' then
    return old;
  end if;

  has_mod_power :=
    coalesce((new.permissions ->> 'manage_server')::boolean, false)
    or coalesce((new.permissions ->> 'manage_roles')::boolean, false)
    or coalesce((new.permissions ->> 'manage_guild_tiers')::boolean, false)
    or coalesce((new.permissions ->> 'manage_channels')::boolean, false)
    or coalesce((new.permissions ->> 'ban_members')::boolean, false)
    or coalesce((new.permissions ->> 'kick_members')::boolean, false)
    or coalesce((new.permissions ->> 'manage_messages')::boolean, false)
    or lower(coalesce(new.name, '')) in ('owner', 'admin', 'mod', 'moderator');

  if has_mod_power then
    select s.server_type
      into server_plan
    from public.servers s
    where s.id = new.server_id
    limit 1;

    new.upload_limit_bytes := public.server_attachment_upload_limit_bytes(server_plan);
  end if;

  return new;
end;
$$;

update public.server_roles sr
set upload_limit_bytes = public.server_attachment_upload_limit_bytes(s.server_type)
from public.servers s
where s.id = sr.server_id
  and coalesce((sr.permissions ->> 'manage_guild_tiers')::boolean, false);
