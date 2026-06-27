-- Forward encryption: per-channel key epoch tracking and access control.
-- Private servers can opt into forward encryption so new members only see
-- messages sent after they join. Existing members keep full history access.

-- ── 1. Server-level toggle ────────────────────────────────────────────────────
alter table public.servers
  add column if not exists forward_encryption boolean not null default false;

-- ── 2. Key epoch history ──────────────────────────────────────────────────────
create table if not exists public.channel_key_epochs (
  id                 bigint generated always as identity primary key,
  channel_id         bigint not null references public.channels(id) on delete cascade,
  server_id          bigint not null references public.servers(id)  on delete cascade,
  key_base64         text   not null,
  created_at         timestamptz not null default now(),
  created_by_user_id uuid references auth.users(id) on delete set null
);
create index if not exists channel_key_epochs_channel_idx
  on public.channel_key_epochs(channel_id, id);

-- ── 3. Per-member access floor ────────────────────────────────────────────────
create table if not exists public.member_channel_key_access (
  id                bigint generated always as identity primary key,
  user_id           uuid   not null references auth.users(id)           on delete cascade,
  channel_id        bigint not null references public.channels(id)      on delete cascade,
  earliest_epoch_id bigint not null references public.channel_key_epochs(id) on delete cascade,
  granted_at        timestamptz not null default now(),
  constraint member_channel_key_access_uq unique (user_id, channel_id)
);
create index if not exists member_channel_key_access_idx
  on public.member_channel_key_access(user_id, channel_id);

-- ── 4. Tag each message with its key epoch ────────────────────────────────────
alter table public.messages
  add column if not exists key_epoch_id bigint
    references public.channel_key_epochs(id) on delete set null;

-- ── 5. Seed epochs from existing snapshots ───────────────────────────────────
insert into public.channel_key_epochs (channel_id, server_id, key_base64, created_at)
select
  s.channel_id,
  s.server_id,
  s.snapshot_payload ->> 'channel_key_base64',
  coalesce(s.created_at, now())
from public.mls_channel_state_snapshots s
where s.snapshot_payload ->> 'channel_key_base64' is not null
  and s.channel_id is not null
  and s.server_id  is not null
  and not exists (
    select 1
    from public.channel_key_epochs existing_epoch
    where existing_epoch.channel_id = s.channel_id
      and existing_epoch.key_base64 = s.snapshot_payload ->> 'channel_key_base64'
  );

-- Stamp the epoch IDs back into the snapshot payloads
update public.mls_channel_state_snapshots s
set snapshot_payload = jsonb_set(
  coalesce(s.snapshot_payload, '{}'),
  '{current_key_epoch_id}',
  to_jsonb(eke.id)
)
from public.channel_key_epochs eke
where eke.channel_id = s.channel_id
  and eke.key_base64 = s.snapshot_payload ->> 'channel_key_base64';

-- ── 6. Grant all current members full access (from first epoch) ───────────────
insert into public.member_channel_key_access (user_id, channel_id, earliest_epoch_id)
select distinct
  sm.user_id,
  c.id                                                          as channel_id,
  min(eke.id) over (partition by c.id)                         as earliest_epoch_id
from public.server_members sm
join public.channels             c   on c.server_id   = sm.server_id
join public.channel_key_epochs   eke on eke.channel_id = c.id
on conflict (user_id, channel_id) do nothing;

-- ── 7. RLS ────────────────────────────────────────────────────────────────────
alter table public.channel_key_epochs       enable row level security;
alter table public.member_channel_key_access enable row level security;

-- Members can read epochs they have access to (epoch id >= their floor)
drop policy if exists "read_accessible_epochs"
  on public.channel_key_epochs;

create policy "read_accessible_epochs"
  on public.channel_key_epochs for select
  using (
    exists (
      select 1 from public.member_channel_key_access mka
      where mka.user_id            = auth.uid()
        and mka.channel_id         = channel_key_epochs.channel_id
        and mka.earliest_epoch_id <= channel_key_epochs.id
    )
  );

-- Users can read their own access grants
drop policy if exists "read_own_key_access"
  on public.member_channel_key_access;

create policy "read_own_key_access"
  on public.member_channel_key_access for select
  using (user_id = auth.uid());

-- ── 8. RPC: initialise a brand-new channel epoch ─────────────────────────────
-- Called from TypeScript when a fresh channel snapshot is first created.
-- Inserts the epoch, stamps the snapshot, and grants every current server member.
create or replace function public.init_channel_key_epoch(
  p_channel_id  bigint,
  p_server_id   bigint,
  p_key_base64  text
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  v_epoch_id bigint;
begin
  insert into public.channel_key_epochs (channel_id, server_id, key_base64)
  values (p_channel_id, p_server_id, p_key_base64)
  returning id into v_epoch_id;

  -- Stamp epoch ID into the snapshot
  update public.mls_channel_state_snapshots
  set snapshot_payload = jsonb_set(
    coalesce(snapshot_payload, '{}'),
    '{current_key_epoch_id}',
    to_jsonb(v_epoch_id)
  )
  where channel_id = p_channel_id;

  -- Grant all current server members access from this epoch
  insert into public.member_channel_key_access (user_id, channel_id, earliest_epoch_id)
  select sm.user_id, p_channel_id, v_epoch_id
  from public.server_members sm
  where sm.server_id = p_server_id
  on conflict (user_id, channel_id) do nothing;

  return v_epoch_id;
end;
$$;

-- ── 9. RPC: handle channel key access on server join ─────────────────────────
-- forward_encryption = false → grant access from the first epoch (open history).
-- forward_encryption = true  → rotate key for every channel, grant only new epoch.
create or replace function public.handle_server_join_key_access(
  p_server_id   bigint,
  p_new_user_id uuid
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_forward     boolean;
  v_channel     record;
  v_new_epoch   bigint;
  v_new_key     text;
  v_first_epoch bigint;
begin
  select coalesce(forward_encryption, false) into v_forward
  from public.servers where id = p_server_id;

  for v_channel in
    select id from public.channels where server_id = p_server_id
  loop
    if v_forward then
      -- Rotate: generate new key, update snapshot, grant only new epoch to joiner
      v_new_key := encode(gen_random_bytes(32), 'base64');

      insert into public.channel_key_epochs (channel_id, server_id, key_base64, created_by_user_id)
      values (v_channel.id, p_server_id, v_new_key, p_new_user_id)
      returning id into v_new_epoch;

      update public.mls_channel_state_snapshots
      set snapshot_payload = jsonb_set(
        jsonb_set(coalesce(snapshot_payload, '{}'), '{channel_key_base64}',    to_jsonb(v_new_key)),
        '{current_key_epoch_id}', to_jsonb(v_new_epoch)
      )
      where channel_id = v_channel.id;

      insert into public.member_channel_key_access (user_id, channel_id, earliest_epoch_id)
      values (p_new_user_id, v_channel.id, v_new_epoch)
      on conflict (user_id, channel_id) do update set earliest_epoch_id = excluded.earliest_epoch_id;

    else
      -- Open: grant from the earliest available epoch
      select min(id) into v_first_epoch
      from public.channel_key_epochs
      where channel_id = v_channel.id;

      if v_first_epoch is not null then
        insert into public.member_channel_key_access (user_id, channel_id, earliest_epoch_id)
        values (p_new_user_id, v_channel.id, v_first_epoch)
        on conflict (user_id, channel_id) do nothing;
      end if;
    end if;
  end loop;
end;
$$;

-- ── 10. Expose forward_encryption in server settings context ──────────────────
drop function if exists public.get_server_settings_context(bigint);

create or replace function public.get_server_settings_context(p_server_id bigint)
returns table (
  id                       bigint,
  display_name             text,
  description              text,
  category                 text,
  visibility               text,
  rules                    text,
  welcome_message          text,
  banner_url               text,
  icon_url                 text,
  invite_code              text,
  show_posts_in_global_feed boolean,
  monetization_enabled     boolean,
  theme_enabled            boolean,
  theme_id                 text,
  appearance_preferences   jsonb,
  use_server_theme         boolean,
  forward_encryption       boolean,
  my_role                  text,
  nickname                 text
)
language sql
stable
set search_path to public
as $$
  select
    s.id,
    s.display_name,
    s.description,
    s.category,
    s.visibility,
    s.rules,
    s.welcome_message,
    s.banner_url,
    s.icon_url,
    s.invite_code,
    coalesce(s.show_posts_in_global_feed, true),
    coalesce(s.monetization_enabled, false),
    coalesce(s.theme_enabled, false),
    coalesce(s.theme_id, 'default'),
    coalesce(s.appearance_preferences, '{}'::jsonb),
    coalesce(stp.use_server_theme, true),
    coalesce(s.forward_encryption, false),
    coalesce(
      case
        when s.owner_id = auth.uid() then 'owner'
        when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
        else lower(trim(coalesce(sm.role, 'member')))
      end,
      'member'
    ),
    sn.nickname
  from public.servers s
  left join public.server_members sm
    on sm.server_id = s.id and sm.user_id = auth.uid()
  left join public.server_nicknames sn
    on sn.server_id = s.id and sn.user_id = auth.uid()
  left join public.server_theme_preferences stp
    on stp.server_id = s.id and stp.user_id = auth.uid()
  where s.id = p_server_id
  limit 1;
$$;
