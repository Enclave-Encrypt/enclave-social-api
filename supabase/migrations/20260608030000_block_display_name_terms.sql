-- Blocked terms for Social display names only (username moderation stays on Enclave Account).

create table if not exists public.blocked_profile_terms (
  term text primary key,
  contexts text[] not null default array['user_display_name'],
  active boolean not null default true,
  created_at timestamptz not null default now(),
  constraint blocked_profile_terms_term_not_empty check (btrim(term) <> '')
);

alter table public.blocked_profile_terms enable row level security;

insert into public.blocked_profile_terms (term)
values
  ('nigga'),
  ('nigger'),
  ('faggot'),
  ('kike'),
  ('spic'),
  ('chink'),
  ('gook'),
  ('wetback')
on conflict (term) do update
set active = true,
    contexts = excluded.contexts;

create or replace function public.normalize_moderation_text(p_value text)
returns text
language sql
immutable
as $$
  select regexp_replace(
    translate(lower(coalesce(p_value, '')), '013457@$!', 'oieastasi'),
    '[^a-z0-9]+',
    '',
    'g'
  );
$$;

create or replace function public.has_blocked_profile_term(
  p_value text,
  p_context text
)
returns boolean
language sql
stable
security definer
set search_path to public
as $$
  select exists (
    select 1
    from public.blocked_profile_terms bpt
    where bpt.active
      and p_context = any(bpt.contexts)
      and public.normalize_moderation_text(p_value) like '%' || public.normalize_moderation_text(bpt.term) || '%'
  );
$$;

create or replace function public.enforce_user_display_name_terms()
returns trigger
language plpgsql
security definer
set search_path to public
as $$
begin
  if public.has_blocked_profile_term(new.display_name, 'user_display_name') then
    raise exception 'Display name contains a word that is not allowed';
  end if;

  return new;
end;
$$;

drop trigger if exists enforce_user_display_name_terms on public.users;
create trigger enforce_user_display_name_terms
before insert or update of display_name on public.users
for each row
execute function public.enforce_user_display_name_terms();
