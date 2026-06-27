-- Table is synced from public.users via trigger.
-- Direct writes from authenticated role are unnecessary and bypass enforce_user_display_name_terms.

REVOKE INSERT, UPDATE, DELETE ON public.public_user_profiles FROM authenticated;

DROP POLICY IF EXISTS "Users can update own profile" ON public.public_user_profiles;
DROP POLICY IF EXISTS "Users can insert own profile" ON public.public_user_profiles;
DROP POLICY IF EXISTS "Users can delete own profile" ON public.public_user_profiles;
