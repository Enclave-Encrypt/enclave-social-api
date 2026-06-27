-- Auto-provision Social profiles on login (no onboarding modal).

create or replace function public.ensure_social_profile(
  p_username text,
  p_age_range public.age_range_type default '18_plus'
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  uid uuid := auth.uid();
  jwt_email text := nullif(trim(coalesce(auth.jwt() ->> 'email', '')), '');
  normalized_username text;
  display_name text;
  existing public.users%rowtype;
begin
  if uid is null then
    return jsonb_build_object('ok', false, 'reason', 'not_authenticated');
  end if;

  normalized_username := lower(regexp_replace(coalesce(p_username, ''), '[^a-z0-9_]', '', 'g'));
  if normalized_username !~ '^[a-z0-9_]{3,20}$' then
    return jsonb_build_object('ok', false, 'reason', 'invalid_username');
  end if;

  if p_age_range not in ('13_17', '18_plus') then
    return jsonb_build_object('ok', false, 'reason', 'invalid_age_range');
  end if;

  display_name := normalized_username;

  if public.has_blocked_profile_term(display_name, 'user_display_name') then
    return jsonb_build_object('ok', false, 'reason', 'blocked_display_name');
  end if;

  select *
    into existing
  from public.users u
  where u.auth_id = uid;

  if existing.auth_id is null then
    if exists (
      select 1
      from public.users u
      where u.username = normalized_username
    ) then
      return jsonb_build_object('ok', false, 'reason', 'username_taken');
    end if;

    insert into public.users (
      auth_id,
      email,
      username,
      display_name,
      age_range,
      nsfw_enabled,
      username_updated_at
    )
    values (
      uid,
      jwt_email,
      normalized_username,
      display_name,
      p_age_range,
      false,
      timezone('utc', now())
    );
  else
    if coalesce(btrim(existing.username), '') = '' then
      if exists (
        select 1
        from public.users u
        where u.username = normalized_username
          and u.auth_id is distinct from uid
      ) then
        return jsonb_build_object('ok', false, 'reason', 'username_taken');
      end if;
    elsif lower(existing.username) is distinct from normalized_username then
      normalized_username := lower(existing.username);
      display_name := normalized_username;
    end if;

    update public.users u
    set
      username = case
        when coalesce(btrim(u.username), '') = '' then normalized_username
        else u.username
      end,
      display_name = case
        when coalesce(btrim(u.display_name), '') = '' then coalesce(btrim(u.username), normalized_username)
        else u.display_name
      end,
      age_range = coalesce(u.age_range, p_age_range),
      username_updated_at = case
        when coalesce(btrim(existing.username), '') = '' then timezone('utc', now())
        else u.username_updated_at
      end
    where u.auth_id = uid;
  end if;

  return jsonb_build_object('ok', true);
exception
  when others then
    return jsonb_build_object('ok', false, 'reason', sqlerrm);
end;
$$;

revoke all on function public.ensure_social_profile(text, public.age_range_type) from public;
grant execute on function public.ensure_social_profile(text, public.age_range_type) to authenticated;
