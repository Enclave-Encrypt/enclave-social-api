create or replace function public.cancel_server_join_request(p_server_id bigint)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'Sign in required.';
  end if;

  delete from public.server_join_requests
  where server_id = p_server_id
    and user_id = auth.uid()
    and status = 'pending';

  return found;
end;
$$;

revoke all on function public.cancel_server_join_request(bigint) from public;
grant execute on function public.cancel_server_join_request(bigint) to authenticated;
