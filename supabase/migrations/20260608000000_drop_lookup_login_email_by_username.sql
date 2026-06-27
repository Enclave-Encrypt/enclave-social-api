-- Username login belongs entirely on enclave-account.
-- This function is no longer callable by anon or authenticated roles.
-- Dropping to eliminate residual surface area.
DROP FUNCTION IF EXISTS public.lookup_login_email_by_username(text);
