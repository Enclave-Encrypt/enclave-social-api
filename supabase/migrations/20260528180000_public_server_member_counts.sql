-- Discovery / explore need member counts for servers the viewer is not in.
-- Direct reads on server_members are blocked by RLS for non-members.

create or replace function public.get_server_member_counts(p_server_ids bigint[])
returns table (server_id bigint, member_count integer)
language sql
stable
security definer
set search_path = public
as $$
  select
    s.id as server_id,
    count(sm.user_id)::integer as member_count
  from public.servers s
  left join public.server_members sm on sm.server_id = s.id
  where s.id = any(coalesce(p_server_ids, array[]::bigint[]))
    and (
      coalesce(s.visibility, 'public') = 'public'
      or (
        auth.uid() is not null
        and exists (
          select 1
          from public.server_members viewer
          where viewer.server_id = s.id
            and viewer.user_id = auth.uid()
        )
      )
    )
  group by s.id;
$$;

revoke all on function public.get_server_member_counts(bigint[]) from public;
grant execute on function public.get_server_member_counts(bigint[]) to authenticated;
grant execute on function public.get_server_member_counts(bigint[]) to anon;
