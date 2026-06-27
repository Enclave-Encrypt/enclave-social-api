-- search_public_profiles queries public_user_profiles; trgm indexes were on users.username only.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS public_user_profiles_username_trgm_idx
  ON public.public_user_profiles USING gin (username gin_trgm_ops);

CREATE INDEX IF NOT EXISTS public_user_profiles_display_name_trgm_idx
  ON public.public_user_profiles USING gin (display_name gin_trgm_ops);
