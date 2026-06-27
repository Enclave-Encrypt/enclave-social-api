-- Social onboarding must not rely on direct authenticated INSERT/UPDATE to public.users.

drop policy if exists "Users can insert their own profile" on public.users;
create policy "Users can insert their own profile"
  on public.users
  for insert
  to authenticated
  with check (auth_id = auth.uid());

drop policy if exists "Users can update their own profile" on public.users;
create policy "Users can update their own profile"
  on public.users
  for update
  to authenticated
  using (auth_id = auth.uid())
  with check (auth_id = auth.uid());

create or replace function public.complete_social_onboarding(
  p_username text,
  p_display_name text,
  p_age_range public.age_range_type,
  p_avatar_url text default null,
  p_banner_url text default null,
  p_nsfw_enabled boolean default false
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
  existing public.users%rowtype;
begin
  if uid is null then
    return jsonb_build_object('ok', false, 'reason', 'not_authenticated');
  end if;

  normalized_username := lower(regexp_replace(coalesce(p_username, ''), '[^a-z0-9_]', '', 'g'));
  if normalized_username !~ '^[a-z0-9_]{3,20}$' then
    return jsonb_build_object('ok', false, 'reason', 'invalid_username');
  end if;

  if nullif(trim(p_display_name), '') is null or char_length(trim(p_display_name)) < 2 then
    return jsonb_build_object('ok', false, 'reason', 'invalid_display_name');
  end if;

  if p_age_range not in ('13_17', '18_plus') then
    return jsonb_build_object('ok', false, 'reason', 'invalid_age_range');
  end if;

  if public.has_blocked_profile_term(trim(p_display_name), 'user_display_name') then
    return jsonb_build_object('ok', false, 'reason', 'Display name contains a word that is not allowed');
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
      avatar_url,
      banner_url,
      username_updated_at
    )
    values (
      uid,
      jwt_email,
      normalized_username,
      trim(p_display_name),
      p_age_range,
      coalesce(p_nsfw_enabled, false),
      p_avatar_url,
      p_banner_url,
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
      return jsonb_build_object(
        'ok',
        false,
        'reason',
        'That username is already taken on Social. Update it in Account settings.'
      );
    end if;

    update public.users u
    set
      username = case
        when coalesce(btrim(u.username), '') = '' then normalized_username
        else u.username
      end,
      display_name = trim(p_display_name),
      age_range = p_age_range,
      nsfw_enabled = coalesce(p_nsfw_enabled, false),
      avatar_url = coalesce(p_avatar_url, u.avatar_url),
      banner_url = coalesce(p_banner_url, u.banner_url),
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

revoke all on function public.complete_social_onboarding(text, text, public.age_range_type, text, text, boolean) from public;
grant execute on function public.complete_social_onboarding(text, text, public.age_range_type, text, text, boolean) to authenticated;
