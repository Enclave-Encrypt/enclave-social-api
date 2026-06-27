create or replace function public.enforce_auth_identity_metadata_terms()
returns trigger
language plpgsql
security definer
set search_path to public
as $$
begin
  if public.has_blocked_profile_term(new.identity_data ->> 'username', 'username') then
    raise exception 'Username contains a word that is not allowed';
  end if;

  if public.has_blocked_profile_term(new.identity_data ->> 'display_name', 'user_display_name') then
    raise exception 'Display name contains a word that is not allowed';
  end if;

  return new;
end;
$$;

drop trigger if exists enforce_auth_identity_metadata_terms on auth.identities;
create trigger enforce_auth_identity_metadata_terms
before insert or update of identity_data on auth.identities
for each row
execute function public.enforce_auth_identity_metadata_terms();

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

  update auth.identities
  set identity_data =
    coalesce(identity_data, '{}'::jsonb)
    || jsonb_build_object(
      'username', new.username,
      'display_name', new.display_name
    )
  where user_id = new.auth_id;

  return new;
end;
$$;

update auth.identities ai
set identity_data =
  coalesce(ai.identity_data, '{}'::jsonb)
  || jsonb_build_object(
    'username', pu.username,
    'display_name', pu.display_name
  )
from public.users pu
where pu.auth_id = ai.user_id
  and not public.has_blocked_profile_term(pu.username, 'username')
  and not public.has_blocked_profile_term(pu.display_name, 'user_display_name');
