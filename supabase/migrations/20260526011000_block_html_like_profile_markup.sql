create or replace function public.has_html_like_markup(p_value text)
returns boolean
language sql
immutable
as $$
  select coalesce(p_value, '') ~* '</?[a-z][a-z0-9-]*(\s[^<>]*)?>';
$$;

create or replace function public.enforce_user_profile_terms()
returns trigger
language plpgsql
security definer
set search_path to public
as $$
begin
  if public.has_blocked_profile_term(new.username, 'username') then
    raise exception 'Username contains a word that is not allowed';
  end if;

  if public.has_blocked_profile_term(new.display_name, 'user_display_name') then
    raise exception 'Display name contains a word that is not allowed';
  end if;

  if public.has_html_like_markup(new.display_name) then
    raise exception 'Display name cannot contain HTML-like tags';
  end if;

  if public.has_blocked_profile_term(new.bio, 'user_bio') then
    raise exception 'Bio contains a word that is not allowed';
  end if;

  if public.has_html_like_markup(new.bio) then
    raise exception 'Bio cannot contain HTML-like tags';
  end if;

  return new;
end;
$$;

create or replace function public.enforce_auth_user_metadata_terms()
returns trigger
language plpgsql
security definer
set search_path to public
as $$
begin
  if public.has_blocked_profile_term(new.raw_user_meta_data ->> 'username', 'username') then
    raise exception 'Username contains a word that is not allowed';
  end if;

  if public.has_blocked_profile_term(new.raw_user_meta_data ->> 'display_name', 'user_display_name') then
    raise exception 'Display name contains a word that is not allowed';
  end if;

  if public.has_html_like_markup(new.raw_user_meta_data ->> 'display_name') then
    raise exception 'Display name cannot contain HTML-like tags';
  end if;

  return new;
end;
$$;

create or replace function public.enforce_server_nickname_terms()
returns trigger
language plpgsql
security definer
set search_path to public
as $$
begin
  if public.has_html_like_markup(new.nickname) then
    raise exception 'Server nickname cannot contain HTML-like tags';
  end if;

  return new;
end;
$$;

drop trigger if exists enforce_server_nickname_terms on public.server_nicknames;
create trigger enforce_server_nickname_terms
before insert or update of nickname on public.server_nicknames
for each row
execute function public.enforce_server_nickname_terms();
