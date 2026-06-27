update public.users
set username = 'user_' || left(replace(auth_id::text, '-', ''), 8)
where auth_id is not null
  and public.has_blocked_profile_term(username, 'username');

update public.users
set display_name = coalesce(nullif(username, ''), 'User')
where auth_id is not null
  and public.has_blocked_profile_term(display_name, 'user_display_name');

update public.users
set bio = null
where public.has_blocked_profile_term(bio, 'user_bio');

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

  return new;
end;
$$;

drop trigger if exists enforce_auth_user_metadata_terms on auth.users;
create trigger enforce_auth_user_metadata_terms
before insert or update of raw_user_meta_data on auth.users
for each row
execute function public.enforce_auth_user_metadata_terms();

create or replace function public.sync_auth_user_profile_metadata()
returns trigger
language plpgsql
security definer
set search_path to public, auth
as $$
begin
  if new.auth_id is null then
    return new;
  end if;

  update auth.users
  set raw_user_meta_data =
    coalesce(raw_user_meta_data, '{}'::jsonb)
    || jsonb_build_object(
      'username', new.username,
      'display_name', new.display_name
    )
  where id = new.auth_id;

  return new;
end;
$$;

drop trigger if exists sync_auth_user_profile_metadata on public.users;
create trigger sync_auth_user_profile_metadata
after insert or update of username, display_name on public.users
for each row
execute function public.sync_auth_user_profile_metadata();

update auth.users au
set raw_user_meta_data =
  coalesce(au.raw_user_meta_data, '{}'::jsonb)
  || jsonb_build_object(
    'username', pu.username,
    'display_name', pu.display_name
  )
from public.users pu
where pu.auth_id = au.id
  and not public.has_blocked_profile_term(pu.username, 'username')
  and not public.has_blocked_profile_term(pu.display_name, 'user_display_name');
