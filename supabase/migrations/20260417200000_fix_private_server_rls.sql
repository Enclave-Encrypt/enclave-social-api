-- Fix servers SELECT policy so private servers are only visible to members.

-- Drop the existing permissive policy (created outside migrations, name may vary).
-- Using DO block to suppress errors if the policy doesn't exist under this name.
DO $$
BEGIN
  DROP POLICY IF EXISTS "Public servers are viewable by everyone" ON public.servers;
  DROP POLICY IF EXISTS "Servers are viewable by everyone" ON public.servers;
  DROP POLICY IF EXISTS "Anyone can view servers" ON public.servers;
  DROP POLICY IF EXISTS "Authenticated users can view servers" ON public.servers;
END
$$;

-- Recreate with correct visibility rules:
--   • public servers  → visible to all authenticated users
--   • private servers → visible only to members in server_members
create policy "Servers visible based on visibility"
on public.servers
for select
to authenticated
using (
  visibility = 'public'
  or visibility is null
  or exists (
    select 1
    from public.server_members sm
    where sm.server_id = id
      and sm.user_id = auth.uid()
  )
);
