create or replace function public.update_server_privacy_settings(
  p_server_id bigint,
  p_visibility text,
  p_forward_encryption boolean,
  p_require_approval boolean,
  p_show_posts_in_global_feed boolean
)
returns table (
  id bigint,
  visibility text,
  forward_encryption boolean,
  require_approval boolean,
  show_posts_in_global_feed boolean
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_visibility text := lower(trim(coalesce(p_visibility, 'public')));
begin
  if auth.uid() is null then
    raise exception 'Sign in required.';
  end if;

  if v_visibility not in ('public', 'private') then
    raise exception 'Server visibility must be public or private.';
  end if;

  if not public.is_server_admin(p_server_id) then
    raise exception 'Only server owners and admins can update privacy settings.';
  end if;

  update public.servers s
  set
    visibility = v_visibility,
    forward_encryption = coalesce(p_forward_encryption, false),
    require_approval = coalesce(p_require_approval, false),
    show_posts_in_global_feed = coalesce(p_show_posts_in_global_feed, true)
  where s.id = p_server_id
  returning
    s.id,
    s.visibility,
    coalesce(s.forward_encryption, false),
    coalesce(s.require_approval, false),
    coalesce(s.show_posts_in_global_feed, true)
  into
    id,
    visibility,
    forward_encryption,
    require_approval,
    show_posts_in_global_feed;

  if id is null then
    raise exception 'Server not found.';
  end if;

  return next;
end;
$$;

grant execute on function public.update_server_privacy_settings(bigint, text, boolean, boolean, boolean) to authenticated;
