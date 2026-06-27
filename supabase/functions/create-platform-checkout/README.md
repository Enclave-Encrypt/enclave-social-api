# create-platform-checkout

Creates Stripe Checkout sessions for platform token purchases.

## Auth model

- `verify_jwt = true` in `supabase/config.toml`.
- Caller must send a valid Supabase bearer token.
- Function resolves user identity via `supabase.auth.getUser(token)` before creating a checkout session.

## Required secrets

- `STRIPE_SECRET_KEY`
- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`

## Notes

- This is an internal user-initiated endpoint and should not be callable anonymously.
