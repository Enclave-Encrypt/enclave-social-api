# delete-account-cleanup

Invoked by `public.delete_my_account()` through `pg_net` after account deletion is approved.

Handles:

- Stripe subscription cancellation and customer deletion
- Storage blob removal via the **Storage API** (avatars, banners, message attachments)

Postgres must **not** `DELETE` from `storage.objects` directly — Supabase blocks that.

## Deploy

1. Push the migration: `supabase db push`
2. Deploy the function: `supabase functions deploy delete-account-cleanup`
3. Set Edge Function secrets:
   - `ACCOUNT_DELETION_SECRET` (same value as vault)
   - `SUPABASE_SERVICE_ROLE_KEY` (for Storage API deletes)
   - `STRIPE_SECRET_KEY` (if Stripe cleanup is used)
4. Store the deletion secret in Vault:
   ```sql
   select vault.create_secret('<random-secret>', 'account_deletion_secret');
   ```

If the vault secret is missing, account deletion still proceeds; Stripe and storage cleanup are skipped with a warning in database logs.

## Auth model

- `verify_jwt = false` in `supabase/config.toml` because this function is invoked from Postgres via `pg_net`, not by user clients.
- Access is restricted by `x-account-deletion-secret`, validated against `ACCOUNT_DELETION_SECRET`.

This endpoint must remain non-public and callable only by trusted backend workflows.
