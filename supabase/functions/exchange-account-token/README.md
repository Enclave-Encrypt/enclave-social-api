# exchange-account-token

Exchanges a valid **Enclave Account** access token for a **Social data** Supabase session.

## Auth model

- `verify_jwt = false` in `supabase/config.toml` because callers send an Account-project JWT, which the Social data gateway cannot validate.
- Handler verifies the bearer token against Account JWKS (`eyqaeigblulbtnorqyts`) and rejects Social data tokens with a clear error.
- Only issues a Social data session after Account identity is confirmed.

## Required secrets

- `SUPABASE_URL` / `SUPABASE_SERVICE_ROLE_KEY` (Social data)
- `ACCOUNT_SUPABASE_URL` / `ACCOUNT_SUPABASE_ANON_KEY` (Account project, for fallback `getUser`)

## Client

- `src/lib/supabase/exchangeAccountToken.ts` — invoked during app boot after Account sign-in.

## Notes

- Must remain callable only with a valid Account JWT; never accept anonymous requests.
