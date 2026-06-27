-- Function to check MLS group membership without RLS recursion
create or replace function public.check_mls_group_membership(p_group_id bigint, p_user_id uuid)
returns boolean
language sql
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.mls_group_members
    where mls_group_id = p_group_id
      and user_id = p_user_id
      and membership_status = 'active'
  );
$$;

grant execute on function public.check_mls_group_membership(bigint, uuid) to authenticated;

-- Drop existing recursive/problematic policies
drop policy if exists "Users can read MLS groups they belong to" on public.mls_groups;
drop policy if exists "Users can read MLS group members for their groups" on public.mls_group_members;
drop policy if exists "Users can read MLS commits for their groups" on public.mls_commits;
drop policy if exists "Users can insert MLS commits from their own devices" on public.mls_commits;

-- New non-recursive policies for mls_groups
create policy "Users can read MLS groups they belong to"
on public.mls_groups
for select
to authenticated
using (
  (conversation_kind = 'dm' and (dm_user_a = auth.uid() or dm_user_b = auth.uid()))
  or
  public.check_mls_group_membership(id, auth.uid())
);

-- New non-recursive policies for mls_group_members
create policy "Users can read MLS group members for their groups"
on public.mls_group_members
for select
to authenticated
using (
  user_id = auth.uid() -- Always allow seeing own membership
  or
  public.check_mls_group_membership(mls_group_id, auth.uid())
);

-- New non-recursive policies for mls_commits
create policy "Users can read MLS commits for their groups"
on public.mls_commits
for select
to authenticated
using (
  public.check_mls_group_membership(mls_group_id, auth.uid())
);

create policy "Users can insert MLS commits from their own devices"
on public.mls_commits
for insert
to authenticated
with check (
  public.check_mls_group_membership(mls_group_id, auth.uid())
  and exists (
    select 1
    from public.user_devices ud
    where ud.id = sender_device_id
      and ud.user_id = auth.uid()
  )
);
