create or replace function public.is_server_owner(p_server_id bigint)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = auth.uid()
      and lower(coalesce(sm.role, '')) = 'owner'
  );
$$;

create or replace function public.is_server_admin(p_server_id bigint)
returns boolean
language sql
security definer
set search_path = public
as $$
  select public.is_server_owner(p_server_id) or exists (
    select 1
    from public.server_members sm
    where sm.server_id = p_server_id
      and sm.user_id = auth.uid()
      and lower(coalesce(sm.role, '')) = 'admin'
  );
$$;

create or replace function public.get_my_account_deletion_status()
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  current_user_id uuid := auth.uid();
  blocking_servers jsonb := '[]'::jsonb;
begin
  if current_user_id is null then
    raise exception 'Not authenticated';
  end if;

  with owned_servers as (
    select distinct
      s.id,
      coalesce(s.display_name, s.handle, 'Untitled Server') as name
    from public.server_members sm
    join public.servers s
      on s.id = sm.server_id
    where sm.user_id = current_user_id
      and lower(coalesce(sm.role, '')) = 'owner'
  )
  select coalesce(
    (
      select jsonb_agg(
        jsonb_build_object(
          'server_id', os.id,
          'name', os.name
        )
        order by os.name
      )
      from owned_servers os
      where not exists (
        select 1
        from public.server_members sm
        where sm.server_id = os.id
          and sm.user_id <> current_user_id
          and lower(coalesce(sm.role, '')) = 'owner'
      )
    ),
    '[]'::jsonb
  )
  into blocking_servers;

  return jsonb_build_object(
    'blocking_servers', blocking_servers,
    'transferable_servers', '[]'::jsonb
  );
end;
$$;

create or replace function public.delete_my_account()
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  current_user_id uuid := auth.uid();
  status jsonb;
  blocking_count integer;
begin
  if current_user_id is null then
    raise exception 'Not authenticated';
  end if;

  status := public.get_my_account_deletion_status();
  blocking_count := coalesce(jsonb_array_length(status->'blocking_servers'), 0);

  if blocking_count > 0 then
    raise exception 'Delete blocked. Add another owner or delete these servers first: %',
      (
        select string_agg(value->>'name', ', ')
        from jsonb_array_elements(status->'blocking_servers')
      );
  end if;

  update public.servers
  set owner_id = null
  where owner_id = current_user_id;

  delete from public.server_nicknames
  where user_id = current_user_id;

  delete from public.server_members
  where user_id = current_user_id;

  delete from storage.objects
  where owner_id = current_user_id::text
    and bucket_id = 'avatars';

  delete from auth.users
  where id = current_user_id;

  return jsonb_build_object(
    'deleted', true,
    'transferred_servers', 0
  );
end;
$$;

drop policy if exists "Server owners can upload their icons" on storage.objects;
drop policy if exists "Server owners can update their icons" on storage.objects;
drop policy if exists "Server owners can delete their icons" on storage.objects;

create policy "Server owners can upload their icons"
on storage.objects for insert
to authenticated
with check (
  bucket_id = 'server-icons'
  and public.is_server_owner(((storage.foldername(name))[1])::bigint)
);

create policy "Server owners can update their icons"
on storage.objects for update
to authenticated
using (
  bucket_id = 'server-icons'
  and public.is_server_owner(((storage.foldername(name))[1])::bigint)
)
with check (
  bucket_id = 'server-icons'
  and public.is_server_owner(((storage.foldername(name))[1])::bigint)
);

create policy "Server owners can delete their icons"
on storage.objects for delete
to authenticated
using (
  bucket_id = 'server-icons'
  and public.is_server_owner(((storage.foldername(name))[1])::bigint)
);
