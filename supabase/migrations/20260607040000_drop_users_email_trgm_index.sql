-- Phase 4c: email is no longer searchable cross-user (search_public_profiles RPC only).
drop index if exists public.users_email_trgm_idx;
