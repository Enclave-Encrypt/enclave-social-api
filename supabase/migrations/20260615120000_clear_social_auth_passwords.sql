-- Social auth is Account-only: passwords live on Enclave Account, not Social data.
-- Remove legacy bcrypt hashes left from pre-migration local signup on Social.

update auth.users
set
  encrypted_password = null,
  updated_at = timezone('utc', now())
where encrypted_password is not null;
