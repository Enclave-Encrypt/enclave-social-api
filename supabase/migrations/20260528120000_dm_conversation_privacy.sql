-- 1:1 DM conversation privacy (forward security for new devices / web sessions).

create table if not exists public.dm_conversation_privacy (
  user_a uuid not null references auth.users (id) on delete cascade,
  user_b uuid not null references auth.users (id) on delete cascade,
  forward_encryption boolean not null default false,
  forward_enabled_at timestamptz,
  forward_epoch bigint,
  updated_at timestamptz not null default timezone('utc', now()),
  updated_by uuid references auth.users (id) on delete set null,
  constraint dm_conversation_privacy_pair_order check (user_a < user_b),
  primary key (user_a, user_b)
);

alter table public.dm_conversation_privacy enable row level security;

create or replace function public.dm_conversation_pair(p_user_a uuid, p_user_b uuid)
returns table (user_a uuid, user_b uuid)
language sql
immutable
as $$
  select
    least(p_user_a, p_user_b),
    greatest(p_user_a, p_user_b);
$$;

create or replace function public.is_dm_conversation_participant(p_user_a uuid, p_user_b uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    auth.uid() is not null
    and auth.uid() in (p_user_a, p_user_b)
    and (
      exists (
        select 1
        from public.friendships f
        where f.status = 'accepted'
          and (
            (f.requester_id = p_user_a and f.recipient_id = p_user_b)
            or (f.requester_id = p_user_b and f.recipient_id = p_user_a)
          )
      )
      or exists (
        select 1
        from public.direct_messages dm
        where (
          dm.sender_id = p_user_a and dm.recipient_id = p_user_b
        ) or (
          dm.sender_id = p_user_b and dm.recipient_id = p_user_a
        )
      )
    );
$$;

grant execute on function public.is_dm_conversation_participant(uuid, uuid) to authenticated;

drop policy if exists "DM privacy readable by participants" on public.dm_conversation_privacy;
create policy "DM privacy readable by participants"
on public.dm_conversation_privacy
for select
to authenticated
using (auth.uid() in (user_a, user_b));

drop policy if exists "DM privacy writable by participants" on public.dm_conversation_privacy;
create policy "DM privacy writable by participants"
on public.dm_conversation_privacy
for all
to authenticated
using (auth.uid() in (user_a, user_b))
with check (auth.uid() in (user_a, user_b));

create or replace function public.get_dm_conversation_privacy(
  p_peer_id uuid,
  p_device_id bigint default null
)
returns table (
  forward_encryption boolean,
  history_visible_from timestamptz,
  forward_enabled_at timestamptz
)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_me uuid := auth.uid();
  v_user_a uuid;
  v_user_b uuid;
  v_device_id bigint;
  v_forward boolean := false;
  v_forward_enabled_at timestamptz;
  v_forward_epoch bigint;
  v_visible_from timestamptz;
  v_group_id bigint;
  v_member_epoch bigint;
  v_member_created timestamptz;
begin
  if v_me is null or p_peer_id is null or p_peer_id = v_me then
    return;
  end if;

  if not public.is_dm_conversation_participant(v_me, p_peer_id) then
    return;
  end if;

  select pair.user_a, pair.user_b
  into v_user_a, v_user_b
  from public.dm_conversation_pair(v_me, p_peer_id) pair;

  select
    p.forward_encryption,
    p.forward_enabled_at,
    p.forward_epoch
  into v_forward, v_forward_enabled_at, v_forward_epoch
  from public.dm_conversation_privacy p
  where p.user_a = v_user_a
    and p.user_b = v_user_b;

  v_forward := coalesce(v_forward, false);

  if not v_forward then
    return query
    select false, null::timestamptz, v_forward_enabled_at;
    return;
  end if;

  v_device_id := p_device_id;
  if v_device_id is null then
    select ud.id
    into v_device_id
    from public.user_devices ud
    where ud.user_id = v_me
      and ud.is_active = true
      and ud.revoked_at is null
    order by ud.last_seen_at desc nulls last, ud.id desc
    limit 1;
  end if;

  select g.id
  into v_group_id
  from public.mls_groups g
  where g.conversation_kind = 'dm'
    and g.is_active = true
    and (
      (g.dm_user_a = v_user_a and g.dm_user_b = v_user_b)
      or (g.dm_user_a = v_user_b and g.dm_user_b = v_user_a)
    )
  order by g.id desc
  limit 1;

  if v_group_id is null or v_device_id is null then
    return query
    select true, v_forward_enabled_at, v_forward_enabled_at;
    return;
  end if;

  select mgm.joined_at_epoch, mgm.created_at
  into v_member_epoch, v_member_created
  from public.mls_group_members mgm
  where mgm.mls_group_id = v_group_id
    and mgm.user_id = v_me
    and mgm.user_device_id = v_device_id
    and mgm.membership_status = 'active'
  limit 1;

  if v_member_epoch is null then
    v_visible_from := v_forward_enabled_at;
  elsif v_forward_epoch is not null and v_member_epoch < v_forward_epoch then
    v_visible_from := null;
  else
    v_visible_from := v_member_created;
  end if;

  return query
  select v_forward, v_visible_from, v_forward_enabled_at;
end;
$$;

grant execute on function public.get_dm_conversation_privacy(uuid, bigint) to authenticated;

create or replace function public.set_dm_conversation_privacy(
  p_peer_id uuid,
  p_forward_encryption boolean
)
returns table (
  forward_encryption boolean,
  history_visible_from timestamptz,
  forward_enabled_at timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_me uuid := auth.uid();
  v_user_a uuid;
  v_user_b uuid;
  v_was_enabled boolean := false;
  v_group_id bigint;
  v_current_epoch bigint;
begin
  if v_me is null or p_peer_id is null or p_peer_id = v_me then
    raise exception 'Invalid peer';
  end if;

  if not public.is_dm_conversation_participant(v_me, p_peer_id) then
    raise exception 'Not a participant in this conversation';
  end if;

  select pair.user_a, pair.user_b
  into v_user_a, v_user_b
  from public.dm_conversation_pair(v_me, p_peer_id) pair;

  select p.forward_encryption
  into v_was_enabled
  from public.dm_conversation_privacy p
  where p.user_a = v_user_a
    and p.user_b = v_user_b;

  v_was_enabled := coalesce(v_was_enabled, false);

  select g.id, g.current_epoch
  into v_group_id, v_current_epoch
  from public.mls_groups g
  where g.conversation_kind = 'dm'
    and g.is_active = true
    and (
      (g.dm_user_a = v_user_a and g.dm_user_b = v_user_b)
      or (g.dm_user_a = v_user_b and g.dm_user_b = v_user_a)
    )
  order by g.id desc
  limit 1;

  insert into public.dm_conversation_privacy as p (
    user_a,
    user_b,
    forward_encryption,
    forward_enabled_at,
    forward_epoch,
    updated_at,
    updated_by
  )
  values (
    v_user_a,
    v_user_b,
    p_forward_encryption,
    case when p_forward_encryption then timezone('utc', now()) else null end,
    case
      when p_forward_encryption and not v_was_enabled and v_group_id is not null
        then v_current_epoch
      else null
    end,
    timezone('utc', now()),
    v_me
  )
  on conflict (user_a, user_b) do update
  set
    forward_encryption = excluded.forward_encryption,
    forward_enabled_at = case
      when excluded.forward_encryption
        and not dm_conversation_privacy.forward_encryption
        then timezone('utc', now())
      when not excluded.forward_encryption then null
      else dm_conversation_privacy.forward_enabled_at
    end,
    forward_epoch = case
      when excluded.forward_encryption
        and not dm_conversation_privacy.forward_encryption
        and v_group_id is not null
        then v_current_epoch
      when not excluded.forward_encryption then null
      else dm_conversation_privacy.forward_epoch
    end,
    updated_at = excluded.updated_at,
    updated_by = excluded.updated_by;

  return query
  select *
  from public.get_dm_conversation_privacy(p_peer_id, null);
end;
$$;

grant execute on function public.set_dm_conversation_privacy(uuid, boolean) to authenticated;
