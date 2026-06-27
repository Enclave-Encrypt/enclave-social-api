create or replace function public.get_my_account_deletion_status()
returns jsonb
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  current_user_id uuid := auth.uid();
  blocking_servers jsonb := '[]'::jsonb;
  transferable_servers jsonb := '[]'::jsonb;
begin
  if current_user_id is null then
    raise exception 'Not authenticated';
  end if;

  with owned_servers as (
    select s.id, coalesce(s.display_name, s.handle, 'Untitled Server') as name
    from public.servers s
    where s.owner_id = current_user_id
  ),
  other_owners as (
    select
      os.id as server_id,
      os.name,
      sm.user_id,
      row_number() over (partition by os.id order by sm.created_at asc, sm.id asc) as owner_rank
    from owned_servers os
    join public.server_members sm
      on sm.server_id = os.id
     and sm.user_id <> current_user_id
     and lower(coalesce(sm.role, '')) = 'owner'
  )
  select
    coalesce(
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
          from other_owners oo
          where oo.server_id = os.id
        )
      ),
      '[]'::jsonb
    ),
    coalesce(
      (
        select jsonb_agg(
          jsonb_build_object(
            'server_id', oo.server_id,
            'name', oo.name,
            'new_owner_id', oo.user_id
          )
          order by oo.name
        )
        from other_owners oo
        where oo.owner_rank = 1
      ),
      '[]'::jsonb
    )
  into blocking_servers, transferable_servers;

  return jsonb_build_object(
    'blocking_servers', blocking_servers,
    'transferable_servers', transferable_servers
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

  update public.servers s
  set owner_id = reassignment.new_owner_id
  from (
    select
      (item->>'server_id')::bigint as server_id,
      (item->>'new_owner_id')::uuid as new_owner_id
    from jsonb_array_elements(status->'transferable_servers') item
  ) reassignment
  where s.id = reassignment.server_id
    and s.owner_id = current_user_id;

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
    'transferred_servers', coalesce(jsonb_array_length(status->'transferable_servers'), 0)
  );
end;
$$;

revoke all on function public.get_my_account_deletion_status() from public;
revoke all on function public.delete_my_account() from public;

grant execute on function public.get_my_account_deletion_status() to authenticated;
grant execute on function public.delete_my_account() to authenticated;
