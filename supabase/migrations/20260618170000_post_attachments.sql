insert into storage.buckets (id, name, public)
values ('post-attachments', 'post-attachments', false)
on conflict (id) do nothing;

update storage.buckets
   set file_size_limit = 1024 * 1024 * 1024
 where id = 'post-attachments';

create table if not exists public.post_attachments (
  id uuid primary key default gen_random_uuid(),
  attachment_id text not null unique,
  owner_id uuid not null references auth.users(id) on delete cascade,
  context text not null check (context in ('profile', 'server')),
  server_id bigint references public.servers(id) on delete cascade,
  post_id uuid references public.posts(id) on delete cascade,
  storage_bucket text not null default 'post-attachments',
  storage_path text not null unique,
  file_name text not null,
  mime_type text not null,
  size_bytes bigint not null check (size_bytes > 0),
  status text not null default 'pending' check (status in ('pending', 'attached', 'deleted')),
  created_at timestamptz not null default now(),
  attached_at timestamptz,
  deleted_at timestamptz
);

create index if not exists post_attachments_owner_status_idx
  on public.post_attachments (owner_id, status, created_at);

create index if not exists post_attachments_server_status_idx
  on public.post_attachments (server_id, status, created_at)
  where server_id is not null;

create index if not exists post_attachments_post_idx
  on public.post_attachments (post_id)
  where post_id is not null;

alter table public.post_attachments enable row level security;

drop policy if exists "Users can read their post attachment ledger" on public.post_attachments;
create policy "Users can read their post attachment ledger"
on public.post_attachments
for select
to authenticated
using (owner_id = auth.uid());

drop policy if exists "Users can delete their unattached post attachment ledger" on public.post_attachments;
create policy "Users can delete their unattached post attachment ledger"
on public.post_attachments
for delete
to authenticated
using (
  owner_id = auth.uid()
  and status = 'pending'
);

create or replace function public.reserve_post_attachment_upload(
  p_attachment_id text,
  p_context text,
  p_server_id bigint,
  p_storage_path text,
  p_file_name text,
  p_mime_type text,
  p_size_bytes bigint
)
returns public.post_attachments
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
  server_type text;
  role_upload_limit bigint;
  reserved_row public.post_attachments;
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

  if p_context = 'profile' then
    effective_upload_limit := account_upload_limit;
    account_quota := public.account_attachment_storage_quota_bytes(user_tier);

    select coalesce(sum(size_bytes), 0)
      into current_usage
    from public.post_attachments
    where owner_id = current_user_id
      and context = 'profile'
      and status in ('pending', 'attached');

    if current_usage + p_size_bytes > account_quota then
      raise exception 'Attachment storage quota exceeded. Delete older post attachments or upgrade your key.';
    end if;
  elsif p_context = 'server' then
    if p_server_id is null then
      raise exception 'Server is required for server post attachments.';
    end if;

    select s.server_type
      into server_type
    from public.servers s
    where s.id = p_server_id
    limit 1;

    if server_type is null then
      raise exception 'Server not found.';
    end if;

    if not exists (
      select 1
      from public.server_members sm
      where sm.server_id = p_server_id
        and sm.user_id = current_user_id
    )
    and not exists (
      select 1
      from public.servers s
      where s.id = p_server_id
        and s.visibility = 'public'
    ) then
      raise exception 'You cannot upload attachments to this server.';
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
    from public.post_attachments
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

  insert into public.post_attachments (
    attachment_id,
    owner_id,
    context,
    server_id,
    storage_path,
    file_name,
    mime_type,
    size_bytes
  )
  values (
    p_attachment_id,
    current_user_id,
    p_context,
    case when p_context = 'server' then p_server_id else null end,
    p_storage_path,
    coalesce(nullif(p_file_name, ''), 'attachment'),
    coalesce(nullif(p_mime_type, ''), 'application/octet-stream'),
    p_size_bytes
  )
  returning * into reserved_row;

  return reserved_row;
end;
$$;

create or replace function public.finalize_post_attachments(
  p_attachment_ids text[],
  p_post_id uuid
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

  if not exists (
    select 1
    from public.posts p
    where p.id = p_post_id
      and p.author_id = current_user_id
  ) then
    raise exception 'Post not found.';
  end if;

  update public.post_attachments
     set status = 'attached',
         attached_at = coalesce(attached_at, now()),
         post_id = p_post_id
   where owner_id = current_user_id
     and attachment_id = any(p_attachment_ids)
     and status = 'pending';
end;
$$;

create or replace function public.release_post_attachments(p_attachment_ids text[])
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
  using public.post_attachments pa
  where so.bucket_id = pa.storage_bucket
    and so.name = pa.storage_path
    and pa.owner_id = current_user_id
    and pa.attachment_id = any(p_attachment_ids)
    and pa.status = 'pending';

  delete from public.post_attachments
  where owner_id = current_user_id
    and attachment_id = any(p_attachment_ids)
    and status = 'pending';
end;
$$;

create or replace function public.cleanup_post_attachment_refs_on_post_delete()
returns trigger
language plpgsql
security definer
set search_path = public, storage
as $$
begin
  delete from storage.objects so
  using public.post_attachments pa
  where pa.post_id = old.id
    and so.bucket_id = pa.storage_bucket
    and so.name = pa.storage_path;

  update public.post_attachments
     set status = 'deleted',
         deleted_at = now()
   where post_id = old.id
     and status <> 'deleted';

  return old;
end;
$$;

drop trigger if exists cleanup_post_attachments_after_post_delete on public.posts;
create trigger cleanup_post_attachments_after_post_delete
after delete on public.posts
for each row
execute function public.cleanup_post_attachment_refs_on_post_delete();

drop policy if exists "Authenticated users can upload encrypted post attachments" on storage.objects;
create policy "Authenticated users can upload encrypted post attachments"
on storage.objects for insert
to authenticated
with check (
  bucket_id = 'post-attachments'
  and owner = auth.uid()
  and exists (
    select 1
    from public.post_attachments pa
    where pa.owner_id = auth.uid()
      and pa.storage_bucket = bucket_id
      and pa.storage_path = name
      and pa.status = 'pending'
  )
);

drop policy if exists "Authenticated users can read encrypted post attachments" on storage.objects;
create policy "Authenticated users can read encrypted post attachments"
on storage.objects for select
to authenticated
using (bucket_id = 'post-attachments');

drop policy if exists "Attachment owners can delete encrypted post attachments" on storage.objects;
create policy "Attachment owners can delete encrypted post attachments"
on storage.objects for delete
to authenticated
using (
  bucket_id = 'post-attachments'
  and owner = auth.uid()
);
