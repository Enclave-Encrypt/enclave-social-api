-- Social no longer accepts public signups (see config.toml enable_signup = false).
-- Email domain blocking for auth.users INSERT belonged to the old local signup path.
-- Account (enclave-account) owns signup validation.

drop trigger if exists enforce_auth_signup_email_domain on auth.users;

drop function if exists public.enforce_auth_signup_email_domain();
drop function if exists public.is_blocked_auth_email_domain(text);
drop function if exists public.auth_email_domain(text);

drop table if exists public.blocked_auth_email_domains;
