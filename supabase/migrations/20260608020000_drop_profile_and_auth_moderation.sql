-- Profile/auth moderation is owned by Enclave Account; remove Social-side enforcement.

drop trigger if exists enforce_user_profile_terms on public.users;
drop trigger if exists enforce_server_profile_terms on public.servers;
drop trigger if exists enforce_auth_user_metadata_terms on auth.users;
drop trigger if exists enforce_auth_identity_metadata_terms on auth.identities;
drop trigger if exists enforce_server_nickname_terms on public.server_nicknames;

drop function if exists public.enforce_user_profile_terms();
drop function if exists public.enforce_server_profile_terms();
drop function if exists public.enforce_auth_user_metadata_terms();
drop function if exists public.enforce_auth_identity_metadata_terms();
drop function if exists public.enforce_server_nickname_terms();
drop function if exists public.has_blocked_profile_term(text, text);
drop function if exists public.normalize_moderation_text(text);
drop function if exists public.has_html_like_markup(text);

drop table if exists public.blocked_profile_terms;
