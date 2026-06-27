create table if not exists public.message_attachments (
  id uuid primary key default gen_random_uuid(),
  attachment_id text not null unique,
  owner_id uuid not null references auth.users(id) on delete cascade,
  context text not null check (context in ('dm', 'channel')),
  server_id bigint references public.servers(id) on delete cascade,
  channel_id bigint references public.channels(id) on delete cascade,
  recipient_id uuid references auth.users(id) on delete set null,
  channel_message_id bigint references public.messages(id) on delete set null,
  direct_message_id bigint references public.direct_messages(id) on delete set null,
  storage_bucket text not null default 'message-attachments',
  storage_path text not null unique,
  file_name text not null,
  mime_type text not null,
  size_bytes bigint not null check (size_bytes > 0),
  status text not null default 'pending' check (status in ('pending', 'attached', 'deleted')),
  created_at timestamptz not null default now(),
  attached_at timestamptz,
  deleted_at timestamptz
);

alter table public.subscription_tiers
  add column if not exists upload_limit_bytes bigint;

alter table public.server_roles
  add column if not exists upload_limit_bytes bigint;

update storage.buckets
   set file_size_limit = 1024 * 1024 * 1024
 where id = 'message-attachments';

create index if not exists message_attachments_owner_status_idx
  on public.message_attachments (owner_id, status, created_at);

create index if not exists message_attachments_server_status_idx
  on public.message_attachments (server_id, status, created_at)
  where server_id is not null;

create index if not exists message_attachments_channel_message_idx
  on public.message_attachments (channel_message_id)
  where channel_message_id is not null;

create index if not exists message_attachments_direct_message_idx
  on public.message_attachments (direct_message_id)
  where direct_message_id is not null;

alter table public.message_attachments enable row level security;

drop policy if exists "Users can read their message attachment ledger" on public.message_attachments;
create policy "Users can read their message attachment ledger"
on public.message_attachments
for select
to authenticated
using (owner_id = auth.uid());

drop policy if exists "Users can delete their unattached message attachment ledger" on public.message_attachments;
create policy "Users can delete their unattached message attachment ledger"
on public.message_attachments
for delete
to authenticated
using (
  owner_id = auth.uid()
  and status = 'pending'
);

create or replace function public.account_attachment_upload_limit_bytes(p_tier text)
returns bigint
language sql
immutable
as $$
  select case lower(coalesce(p_tier, 'bronze'))
    when 'silver' then 50 * 1024 * 1024
    when 'gold' then 250 * 1024 * 1024
    when 'platinum' then 500 * 1024 * 1024
    else 10 * 1024 * 1024
  end::bigint;
$$;

create or replace function public.server_attachment_upload_limit_bytes(p_server_type text)
returns bigint
language sql
immutable
as $$
  select case lower(coalesce(p_server_type, 'stone'))
    when 'community' then 25 * 1024 * 1024
    when 'emerald' then 100 * 1024 * 1024
    when 'business_lite' then 100 * 1024 * 1024
    when 'ruby' then 500 * 1024 * 1024
    when 'business' then 500 * 1024 * 1024
    when 'diamond' then 1024 * 1024 * 1024
    when 'business_pro' then 1024 * 1024 * 1024
    else 25 * 1024 * 1024
  end::bigint;
$$;

update public.subscription_tiers st
   set upload_limit_bytes = public.server_attachment_upload_limit_bytes(s.server_type)
  from public.servers s
 where s.id = st.server_id
   and st.upload_limit_bytes is null;

update public.server_roles sr
   set upload_limit_bytes = public.server_attachment_upload_limit_bytes(s.server_type)
  from public.subscription_tiers st
  join public.servers s on s.id = st.server_id
 where st.role_id = sr.id
   and sr.upload_limit_bytes is null
   and st.upload_limit_bytes is not null;

create or replace function public.account_attachment_storage_quota_bytes(p_tier text)
returns bigint
language sql
immutable
as $$
  select case lower(coalesce(p_tier, 'bronze'))
    when 'silver' then 2 * 1024 * 1024 * 1024
    when 'gold' then 10 * 1024 * 1024 * 1024
    when 'platinum' then 25 * 1024 * 1024 * 1024
    else 250 * 1024 * 1024
  end::bigint;
$$;

create or replace function public.server_attachment_storage_quota_bytes(p_server_type text)
returns bigint
language sql
immutable
as $$
  select case lower(coalesce(p_server_type, 'stone'))
    when 'community' then 5 * 1024 * 1024 * 1024
    when 'emerald' then 25 * 1024 * 1024 * 1024
    when 'business_lite' then 25 * 1024 * 1024 * 1024
    when 'ruby' then 100 * 1024 * 1024 * 1024
    when 'business' then 100 * 1024 * 1024 * 1024
    when 'diamond' then 250 * 1024 * 1024 * 1024
    when 'business_pro' then 250 * 1024 * 1024 * 1024
    else 5 * 1024 * 1024 * 1024
  end::bigint;
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

create or replace function public.finalize_message_attachments(
  p_attachment_ids text[],
  p_context text,
  p_message_id bigint
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  current_user_id uuid := auth.uid();
begin
  if current_user_id is null then
    raise exception 'Authentication required.';
  end if;

  if coalesce(array_length(p_attachment_ids, 1), 0) = 0 then
    return;
  end if;

  if p_context = 'channel' then
    if not exists (
      select 1
      from public.messages m
      where m.id = p_message_id
        and m.sender_id = current_user_id
    ) then
      raise exception 'Message not found.';
    end if;

    update public.message_attachments
       set status = 'attached',
           attached_at = coalesce(attached_at, now()),
           channel_message_id = p_message_id
     where owner_id = current_user_id
       and attachment_id = any(p_attachment_ids)
       and context = 'channel'
       and status = 'pending';
  elsif p_context = 'dm' then
    if not exists (
      select 1
      from public.direct_messages dm
      where dm.id = p_message_id
        and dm.sender_id = current_user_id
    ) then
      raise exception 'Message not found.';
    end if;

    update public.message_attachments
       set status = 'attached',
           attached_at = coalesce(attached_at, now()),
           direct_message_id = p_message_id
     where owner_id = current_user_id
       and attachment_id = any(p_attachment_ids)
       and context = 'dm'
       and status = 'pending';
  else
    raise exception 'Attachment context is invalid.';
  end if;
end;
$$;

create or replace function public.release_message_attachments(p_attachment_ids text[])
returns void
language plpgsql
security definer
set search_path = public, storage
as $$
declare
  current_user_id uuid := auth.uid();
begin
  if current_user_id is null then
    raise exception 'Authentication required.';
  end if;

  if coalesce(array_length(p_attachment_ids, 1), 0) = 0 then
    return;
  end if;

  delete from storage.objects so
  using public.message_attachments ma
  where so.bucket_id = ma.storage_bucket
    and so.name = ma.storage_path
    and ma.owner_id = current_user_id
    and ma.attachment_id = any(p_attachment_ids)
    and ma.status = 'pending';

  delete from public.message_attachments
  where owner_id = current_user_id
    and attachment_id = any(p_attachment_ids)
    and status = 'pending';
end;
$$;

create or replace function public.cleanup_message_attachments(p_limit integer default 500)
returns integer
language plpgsql
security definer
set search_path = public, storage
as $$
declare
  cleaned_count integer;
begin
  with doomed as (
    select id, storage_bucket, storage_path
    from public.message_attachments
    where status = 'pending'
      and created_at < now() - interval '7 days'
    order by created_at
    limit greatest(1, least(coalesce(p_limit, 500), 5000))
  ),
  deleted_objects as (
    delete from storage.objects so
    using doomed d
    where so.bucket_id = d.storage_bucket
      and so.name = d.storage_path
    returning so.id
  ),
  deleted_rows as (
    delete from public.message_attachments ma
    using doomed d
    where ma.id = d.id
    returning ma.id
  )
  select count(*) into cleaned_count from deleted_rows;

  return coalesce(cleaned_count, 0);
end;
$$;

do $$
begin
  create extension if not exists pg_cron with schema extensions;
exception
  when others then
    null;
end;
$$;

do $$
begin
  if exists (select 1 from pg_namespace where nspname = 'cron') then
    perform cron.unschedule(jobid)
    from cron.job
    where jobname = 'cleanup-message-attachments';

    perform cron.schedule(
      'cleanup-message-attachments',
      '17 * * * *',
      'select public.cleanup_message_attachments(1000);'
    );
  end if;
exception
  when others then
    null;
end;
$$;

create or replace function public.cleanup_message_attachment_refs_on_channel_delete()
returns trigger
language plpgsql
security definer
set search_path = public, storage
as $$
begin
  delete from storage.objects so
  using public.message_attachments ma
  where ma.channel_message_id = old.id
    and so.bucket_id = ma.storage_bucket
    and so.name = ma.storage_path;

  update public.message_attachments
     set status = 'deleted',
         deleted_at = now()
   where channel_message_id = old.id
     and status <> 'deleted';

  return old;
end;
$$;

create or replace function public.cleanup_message_attachment_refs_on_dm_delete()
returns trigger
language plpgsql
security definer
set search_path = public, storage
as $$
begin
  delete from storage.objects so
  using public.message_attachments ma
  where ma.direct_message_id = old.id
    and so.bucket_id = ma.storage_bucket
    and so.name = ma.storage_path;

  update public.message_attachments
     set status = 'deleted',
         deleted_at = now()
   where direct_message_id = old.id
     and status <> 'deleted';

  return old;
end;
$$;

drop trigger if exists cleanup_message_attachments_after_channel_delete on public.messages;
create trigger cleanup_message_attachments_after_channel_delete
after delete on public.messages
for each row
execute function public.cleanup_message_attachment_refs_on_channel_delete();

drop trigger if exists cleanup_message_attachments_after_dm_delete on public.direct_messages;
create trigger cleanup_message_attachments_after_dm_delete
after delete on public.direct_messages
for each row
execute function public.cleanup_message_attachment_refs_on_dm_delete();

drop policy if exists "Authenticated users can upload encrypted message attachments" on storage.objects;
create policy "Authenticated users can upload encrypted message attachments"
on storage.objects for insert
to authenticated
with check (
  bucket_id = 'message-attachments'
  and owner = auth.uid()
  and exists (
    select 1
    from public.message_attachments ma
    where ma.owner_id = auth.uid()
      and ma.storage_bucket = bucket_id
      and ma.storage_path = name
      and ma.status = 'pending'
  )
);
