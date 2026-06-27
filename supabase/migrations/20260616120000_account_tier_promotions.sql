-- Temporary global account key tier promotions.
-- Boosts effective tier for all users without overwriting paid tier in public.users.

create table if not exists public.platform_account_tier_promotions (
  id bigint generated always as identity primary key,
  tier text not null,
  starts_at timestamptz not null default now(),
  ends_at timestamptz not null,
  note text,
  cancelled_at timestamptz,
  created_at timestamptz not null default now(),
  constraint platform_account_tier_promotions_tier_check
    check (tier in ('silver', 'gold', 'platinum')),
  constraint platform_account_tier_promotions_window_check
    check (ends_at > starts_at)
);

create index if not exists platform_account_tier_promotions_active_idx
  on public.platform_account_tier_promotions (ends_at desc)
  where cancelled_at is null;

comment on table public.platform_account_tier_promotions is
  'Global account key tier promos. Effective tier is max(stored tier, active promo tier).';

alter table public.platform_account_tier_promotions enable row level security;

create or replace function public.account_tier_rank(p_tier text)
returns integer
language sql
immutable
as $$
  select case lower(coalesce(p_tier, 'bronze'))
    when 'silver' then 1
    when 'gold' then 2
    when 'platinum' then 3
    else 0
  end;
$$;

create or replace function public.higher_account_tier(p_left text, p_right text)
returns text
language sql
immutable
as $$
  select case
    when public.account_tier_rank(p_left) >= public.account_tier_rank(p_right) then lower(coalesce(p_left, 'bronze'))
    else lower(coalesce(p_right, 'bronze'))
  end;
$$;

create or replace function public.get_active_account_tier_promo_tier()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select p.tier
  from public.platform_account_tier_promotions p
  where p.cancelled_at is null
    and p.starts_at <= now()
    and p.ends_at > now()
  order by public.account_tier_rank(p.tier) desc, p.ends_at desc
  limit 1;
$$;

create or replace function public.effective_account_tier(p_stored_tier text)
returns text
language sql
stable
security definer
set search_path = public
as $$
  select public.higher_account_tier(
    lower(coalesce(p_stored_tier, 'bronze')),
    coalesce(public.get_active_account_tier_promo_tier(), lower(coalesce(p_stored_tier, 'bronze')))
  );
$$;

revoke all on function public.get_active_account_tier_promo_tier() from public;
revoke all on function public.effective_account_tier(text) from public;
grant execute on function public.get_active_account_tier_promo_tier() to authenticated;
grant execute on function public.effective_account_tier(text) to authenticated;

create or replace function public.refresh_public_profile_effective_tiers()
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  updated_count bigint;
begin
  update public.public_user_profiles pup
     set tier = public.effective_account_tier(u.tier)
    from public.users u
   where u.auth_id = pup.auth_id
     and pup.tier is distinct from public.effective_account_tier(u.tier);

  get diagnostics updated_count = row_count;
  return updated_count;
end;
$$;

revoke all on function public.refresh_public_profile_effective_tiers() from public;

create or replace function public.sync_public_user_profile_row()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if tg_op = 'DELETE' then
    if old.auth_id is not null then
      delete from public.public_user_profiles where auth_id = old.auth_id;
    end if;
    return old;
  end if;

  if new.auth_id is null then
    return new;
  end if;

  insert into public.public_user_profiles (
    auth_id,
    username,
    display_name,
    avatar_url,
    banner_url,
    bio,
    presence,
    status_message,
    tier,
    created_at,
    last_seen
  )
  values (
    new.auth_id,
    new.username,
    new.display_name,
    new.avatar_url,
    new.banner_url,
    new.bio,
    new.presence,
    new.status_message,
    public.effective_account_tier(new.tier),
    new.created_at,
    new.last_seen
  )
  on conflict (auth_id) do update set
    username = excluded.username,
    display_name = excluded.display_name,
    avatar_url = excluded.avatar_url,
    banner_url = excluded.banner_url,
    bio = excluded.bio,
    presence = excluded.presence,
    status_message = excluded.status_message,
    tier = excluded.tier,
    created_at = excluded.created_at,
    last_seen = excluded.last_seen;

  return new;
end;
$$;

create or replace function public.get_my_account()
returns table (
  id bigint,
  auth_id uuid,
  email text,
  username text,
  display_name text,
  avatar_url text,
  banner_url text,
  bio text,
  username_updated_at timestamptz,
  created_at timestamptz,
  last_seen timestamptz,
  presence text,
  status_message text,
  age_range public.age_range_type,
  nsfw_enabled boolean,
  app_theme text,
  tier text,
  token_balance integer,
  key_credit_balance integer,
  platform_stripe_customer_id text,
  stripe_customer_id text,
  creator_pending_tokens integer,
  creator_available_tokens integer,
  creator_stripe_account_id text,
  marketing_emails_enabled boolean,
  marketing_emails_opted_in_at timestamptz,
  marketing_emails_opted_in_source text,
  marketing_emails_unsubscribed_at timestamptz
)
language sql
stable
security definer
set search_path = public
as $$
  select
    u.id,
    u.auth_id,
    u.email,
    u.username,
    u.display_name,
    u.avatar_url,
    u.banner_url,
    u.bio,
    u.username_updated_at,
    u.created_at,
    u.last_seen,
    u.presence,
    u.status_message,
    u.age_range,
    u.nsfw_enabled,
    u.app_theme,
    public.effective_account_tier(u.tier) as tier,
    u.token_balance,
    u.key_credit_balance,
    u.platform_stripe_customer_id,
    u.stripe_customer_id,
    u.creator_pending_tokens,
    u.creator_available_tokens,
    u.creator_stripe_account_id,
    u.marketing_emails_enabled,
    u.marketing_emails_opted_in_at,
    u.marketing_emails_opted_in_source,
    u.marketing_emails_unsubscribed_at
  from public.users u
  where u.auth_id = auth.uid();
$$;

create or replace function public.get_server_member_list(p_server_id bigint)
returns table (
  auth_id uuid,
  username text,
  display_name text,
  avatar_url text,
  presence text,
  tier text,
  status_message text,
  last_seen timestamptz,
  role text,
  owned_guild_plan text,
  has_custom_role boolean
)
language sql
stable
security definer
set search_path = public
as $$
  with current_server_plan as (
    select public.get_server_verified_guild_plan(p_server_id) as guild_plan
  ),
  members as (
    select
      u.auth_id,
      u.username,
      u.display_name,
      u.avatar_url,
      u.presence,
      public.effective_account_tier(u.tier) as tier,
      u.status_message,
      u.last_seen,
      case
        when lower(trim(coalesce(sm.role, 'member'))) = 'moderator' then 'mod'
        else lower(trim(coalesce(sm.role, 'member')))
      end as normalized_role,
      public.pick_higher_guild_plan(
        (
          select ggp.guild_plan
          from public.get_users_owned_guild_plans(array[u.auth_id]) ggp
          where ggp.user_id = u.auth_id
          limit 1
        ),
        case
          when lower(trim(coalesce(sm.role, ''))) = 'owner'
            then (select guild_plan from current_server_plan)
          else null
        end
      ) as owned_guild_plan
    from public.server_members sm
    join public.users u on u.auth_id = sm.user_id
    where sm.server_id = p_server_id
      and public.user_can_view_server(p_server_id)
  )
  select
    m.auth_id,
    m.username,
    m.display_name,
    m.avatar_url,
    m.presence,
    m.tier,
    m.status_message,
    m.last_seen,
    m.normalized_role as role,
    m.owned_guild_plan,
    public.member_has_custom_server_role(p_server_id, m.auth_id, m.normalized_role) as has_custom_role
  from members m;
$$;

create or replace function public.reserve_message_attachment_upload(
  p_attachment_id text,
  p_context text,
  p_server_id bigint,
  p_channel_id bigint,
  p_recipient_id uuid,
  p_storage_path text,
  p_file_name text,
  p_mime_type text,
  p_size_bytes bigint
)
returns public.message_attachments
language plpgsql
security definer
set search_path = public, storage
as $$
declare
  current_user_id uuid := auth.uid();
  user_tier text;
  account_upload_limit bigint;
  server_upload_limit_cap bigint;
  server_base_upload_limit bigint := 25 * 1024 * 1024;
  effective_upload_limit bigint;
  account_quota bigint;
  server_quota bigint;
  current_usage bigint;
  channel_server_id bigint;
  server_type text;
  role_upload_limit bigint;
  reserved_row public.message_attachments;
begin
  if current_user_id is null then
    raise exception 'Authentication required.';
  end if;

  if p_size_bytes <= 0 then
    raise exception 'Attachment size is invalid.';
  end if;

  if p_storage_path is null or p_storage_path = '' or p_storage_path not like current_user_id::text || '/%' then
    raise exception 'Attachment storage path must be in your user folder.';
  end if;

  select tier into user_tier
  from public.users
  where auth_id = current_user_id
  limit 1;

  user_tier := public.effective_account_tier(user_tier);

  account_upload_limit := public.account_attachment_upload_limit_bytes(user_tier);

  if p_context = 'dm' then
    effective_upload_limit := account_upload_limit;
    account_quota := public.account_attachment_storage_quota_bytes(user_tier);

    select coalesce(sum(size_bytes), 0)
      into current_usage
    from public.message_attachments
    where owner_id = current_user_id
      and context = 'dm'
      and status in ('pending', 'attached');

    if current_usage + p_size_bytes > account_quota then
      raise exception 'Attachment storage quota exceeded. Delete older DM attachments or upgrade your key.';
    end if;
  elsif p_context = 'channel' then
    select c.server_id, s.server_type
      into channel_server_id, server_type
    from public.channels c
    join public.servers s on s.id = c.server_id
    where c.id = p_channel_id
    limit 1;

    if channel_server_id is null or channel_server_id <> p_server_id then
      raise exception 'Channel does not belong to this server.';
    end if;

    if not public.user_can_access_channel(p_channel_id, current_user_id) then
      raise exception 'You cannot upload attachments to this channel.';
    end if;

    server_upload_limit_cap := public.server_attachment_upload_limit_bytes(server_type);
    select greatest(
      coalesce((
        select max(sr.upload_limit_bytes)
        from public.server_roles sr
        where sr.server_id = p_server_id
          and sr.upload_limit_bytes is not null
          and public.user_has_server_role(p_server_id, current_user_id, sr.id)
      ), 0),
      coalesce((
        select max(st.upload_limit_bytes)
        from public.subscription_tiers st
        where st.server_id = p_server_id
          and st.upload_limit_bytes is not null
          and exists (
            select 1
            from public.server_tier_subscriptions sts
            where sts.server_id = st.server_id
              and sts.tier_id = st.id
              and sts.user_id = current_user_id
              and sts.status in ('active', 'trialing')
          )
      ), 0)
    ) into role_upload_limit;

    effective_upload_limit := greatest(
      account_upload_limit,
      server_base_upload_limit,
      least(coalesce(role_upload_limit, 0), server_upload_limit_cap)
    );
    server_quota := public.server_attachment_storage_quota_bytes(server_type);

    select coalesce(sum(size_bytes), 0)
      into current_usage
    from public.message_attachments
    where server_id = p_server_id
      and status in ('pending', 'attached');

    if current_usage + p_size_bytes > server_quota then
      raise exception 'Guild attachment storage quota exceeded. Delete older attachments or upgrade the guild.';
    end if;
  else
    raise exception 'Attachment context is invalid.';
  end if;

  if p_size_bytes > effective_upload_limit then
    raise exception 'Attachment is over the upload limit.';
  end if;

  insert into public.message_attachments (
    attachment_id,
    owner_id,
    context,
    server_id,
    channel_id,
    recipient_id,
    storage_path,
    file_name,
    mime_type,
    size_bytes
  )
  values (
    p_attachment_id,
    current_user_id,
    p_context,
    case when p_context = 'channel' then p_server_id else null end,
    case when p_context = 'channel' then p_channel_id else null end,
    case when p_context = 'dm' then p_recipient_id else null end,
    p_storage_path,
    coalesce(nullif(p_file_name, ''), 'attachment'),
    coalesce(nullif(p_mime_type, ''), 'application/octet-stream'),
    p_size_bytes
  )
  returning * into reserved_row;

  return reserved_row;
end;
$$;

create or replace function public.get_active_account_tier_promotion()
returns table (
  id bigint,
  tier text,
  starts_at timestamptz,
  ends_at timestamptz,
  note text
)
language sql
stable
security definer
set search_path = public
as $$
  select
    p.id,
    p.tier,
    p.starts_at,
    p.ends_at,
    p.note
  from public.platform_account_tier_promotions p
  where p.cancelled_at is null
    and p.starts_at <= now()
    and p.ends_at > now()
  order by public.account_tier_rank(p.tier) desc, p.ends_at desc
  limit 1;
$$;

revoke all on function public.get_active_account_tier_promotion() from public;
grant execute on function public.get_active_account_tier_promotion() to authenticated;

create or replace function public.start_account_tier_promotion(
  p_tier text,
  p_duration_days integer default 30,
  p_note text default null
)
returns public.platform_account_tier_promotions
language plpgsql
security definer
set search_path = public
as $$
declare
  normalized_tier text;
  safe_duration integer;
  promo_row public.platform_account_tier_promotions;
begin
  normalized_tier := lower(trim(coalesce(p_tier, '')));
  if normalized_tier not in ('silver', 'gold', 'platinum') then
    raise exception 'Promotion tier must be silver, gold, or platinum';
  end if;

  safe_duration := greatest(coalesce(p_duration_days, 0), 1);

  update public.platform_account_tier_promotions
     set cancelled_at = now()
   where cancelled_at is null
     and ends_at > now();

  insert into public.platform_account_tier_promotions (
    tier,
    starts_at,
    ends_at,
    note
  )
  values (
    normalized_tier,
    now(),
    now() + make_interval(days => safe_duration),
    nullif(trim(coalesce(p_note, '')), '')
  )
  returning * into promo_row;

  perform public.refresh_public_profile_effective_tiers();

  return promo_row;
end;
$$;

create or replace function public.cancel_account_tier_promotion(p_promotion_id bigint)
returns public.platform_account_tier_promotions
language plpgsql
security definer
set search_path = public
as $$
declare
  promo_row public.platform_account_tier_promotions;
begin
  update public.platform_account_tier_promotions
     set cancelled_at = now()
   where id = p_promotion_id
     and cancelled_at is null
  returning * into promo_row;

  if promo_row.id is null then
    raise exception 'Promotion not found or already cancelled';
  end if;

  perform public.refresh_public_profile_effective_tiers();

  return promo_row;
end;
$$;

revoke all on function public.start_account_tier_promotion(text, integer, text) from public;
revoke all on function public.cancel_account_tier_promotion(bigint) from public;

do $$
begin
  if exists (select 1 from pg_namespace where nspname = 'cron') then
    perform cron.unschedule(jobid)
    from cron.job
    where jobname = 'refresh-account-tier-promo-profiles';

    perform cron.schedule(
      'refresh-account-tier-promo-profiles',
      '15 * * * *',
      $cron$
        select public.refresh_public_profile_effective_tiers();
      $cron$
    );
  end if;
exception
  when others then
    null;
end;
$$;
