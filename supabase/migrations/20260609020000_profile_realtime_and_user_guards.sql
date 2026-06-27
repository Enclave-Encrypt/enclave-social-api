-- Realtime presence/profile updates: public.users SELECT RLS blocks cross-user events.
alter table public.public_user_profiles replica identity full;

do $$
begin
  if not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'public_user_profiles'
  ) then
    alter publication supabase_realtime add table public.public_user_profiles;
  end if;
end $$;

-- Search moved to public_user_profiles; drop dead index on users.username.
drop index if exists public.users_username_trgm_idx;

-- Extend billing guard to legacy stripe_customer_id.
create or replace function public.guard_users_billing_columns()
returns trigger
language plpgsql
as $$
begin
  if public.billing_mutation_allowed() then
    return new;
  end if;

  if new.tier is distinct from old.tier
     or new.token_balance is distinct from old.token_balance
     or new.key_credit_balance is distinct from old.key_credit_balance
     or new.platform_stripe_customer_id is distinct from old.platform_stripe_customer_id
     or new.stripe_customer_id is distinct from old.stripe_customer_id
     or new.creator_pending_tokens is distinct from old.creator_pending_tokens
     or new.creator_available_tokens is distinct from old.creator_available_tokens
     or new.creator_stripe_account_id is distinct from old.creator_stripe_account_id then
    raise exception 'Billing fields on users cannot be updated directly';
  end if;

  return new;
end;
$$;

create or replace function public.guard_users_billing_columns_insert()
returns trigger
language plpgsql
as $$
begin
  if public.billing_mutation_allowed() then
    return new;
  end if;

  if coalesce(new.tier, 'bronze') <> 'bronze'
     or coalesce(new.token_balance, 0) <> 0
     or coalesce(new.key_credit_balance, 0) <> 0
     or new.platform_stripe_customer_id is not null
     or new.stripe_customer_id is not null
     or coalesce(new.creator_pending_tokens, 0) <> 0
     or coalesce(new.creator_available_tokens, 0) <> 0
     or new.creator_stripe_account_id is not null then
    raise exception 'Billing fields on users cannot be set directly';
  end if;

  return new;
end;
$$;

-- Block direct email/auth_id changes on public.users (Account owns identity).
create or replace function public.guard_users_identity_columns()
returns trigger
language plpgsql
as $$
begin
  if new.email is distinct from old.email
     or new.auth_id is distinct from old.auth_id then
    raise exception 'Identity fields on users cannot be updated directly';
  end if;

  return new;
end;
$$;

drop trigger if exists guard_users_identity_columns on public.users;
create trigger guard_users_identity_columns
before update on public.users
for each row
execute function public.guard_users_identity_columns();
