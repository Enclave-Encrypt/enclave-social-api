-- Close username→email enumeration for signed-in clients.
-- Username login is handled by Enclave Account; this RPC is not used by enclave-social.
revoke execute on function public.lookup_login_email_by_username(text) from authenticated;

comment on function public.lookup_login_email_by_username(text) is
  'Deprecated for client use. No anon/authenticated grants. Account auth must resolve usernames server-side.';
