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
              or coalesce((sr.permissions ->> 'manage_channels')::boolean, false)
              or coalesce((sr.permissions ->> 'ban_members')::boolean, false)
              or coalesce((sr.permissions ->> 'kick_members')::boolean, false)
              or coalesce((sr.permissions ->> 'manage_messages')::boolean, false)
            )
        )
      )
  );
$$;

create or replace function public.user_can_access_channel(
  p_channel_id bigint,
  p_user_id uuid
)
returns boolean
language sql
security definer
set search_path to public
as $$
  with channel_row as (
    select
      c.id,
      c.server_id,
      c.tier_id,
      st.role_id,
      coalesce(st.price, 0) as tier_price,
      coalesce(s.visibility, 'public') as visibility,
      s.owner_id
    from public.channels c
    join public.servers s
      on s.id = c.server_id
    left join public.subscription_tiers st
      on st.id = c.tier_id
    where c.id = p_channel_id
    limit 1
  ),
  member_row as (
    select sm.server_id, sm.role, sm.role_id
    from public.server_members sm
    join channel_row c
      on c.server_id = sm.server_id
    where sm.user_id = p_user_id
    limit 1
  )
  select exists (
    select 1
    from channel_row c
    left join member_row sm
      on sm.server_id = c.server_id
    where
      p_user_id is not null
      and (
        c.owner_id = p_user_id
        or sm.server_id is not null
        or c.visibility = 'public'
      )
      and (
        c.tier_id is null
        or c.tier_price <= 0
        or public.user_has_server_mod_power(c.server_id, p_user_id)
        or (c.role_id is not null and public.user_has_server_role(c.server_id, p_user_id, c.role_id))
        or exists (
          select 1
          from public.server_tier_subscriptions sts
          where sts.server_id = c.server_id
            and sts.tier_id = c.tier_id
            and sts.user_id = p_user_id
            and sts.status in ('active', 'trialing')
        )
      )
  );
$$;

create or replace function public.user_can_view_channel(
  p_channel_id bigint,
  p_user_id uuid
)
returns boolean
language sql
security definer
set search_path to public
as $$
  select public.user_can_access_channel(p_channel_id, p_user_id);
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

drop trigger if exists sync_mod_power_role_perks on public.server_roles;
create trigger sync_mod_power_role_perks
before insert or update on public.server_roles
for each row
execute function public.sync_mod_power_role_perks();

update public.server_roles sr
set upload_limit_bytes = public.server_attachment_upload_limit_bytes(s.server_type)
from public.servers s
where s.id = sr.server_id
  and (
    coalesce((sr.permissions ->> 'manage_server')::boolean, false)
    or coalesce((sr.permissions ->> 'manage_roles')::boolean, false)
    or coalesce((sr.permissions ->> 'manage_channels')::boolean, false)
    or coalesce((sr.permissions ->> 'ban_members')::boolean, false)
    or coalesce((sr.permissions ->> 'kick_members')::boolean, false)
    or coalesce((sr.permissions ->> 'manage_messages')::boolean, false)
    or lower(coalesce(sr.name, '')) in ('owner', 'admin', 'mod', 'moderator')
  );
