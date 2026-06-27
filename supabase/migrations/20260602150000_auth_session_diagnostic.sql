-- Lightweight check that the current JWT is trusted by this project (auth.uid() populated).

create or replace function public.auth_session_diagnostic()
returns jsonb
language sql
stable
security invoker
set search_path = public
as $$
  select jsonb_build_object(
    'auth_uid', auth.uid(),
    'jwt_sub', auth.jwt() ->> 'sub',
    'jwt_role', auth.jwt() ->> 'role',
    'jwt_iss', auth.jwt() ->> 'iss',
    'email', auth.jwt() ->> 'email'
  );
$$;

revoke all on function public.auth_session_diagnostic() from public;
grant execute on function public.auth_session_diagnostic() to authenticated;
