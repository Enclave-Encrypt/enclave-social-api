# create-payment-intent

Legacy Stripe payment-intent endpoint. **Deprecated** — returns HTTP 410.

## Auth model

- `verify_jwt = true` in `supabase/config.toml`.
- Function is retained for deploy compatibility; all requests receive a 410 with guidance to use token checkout instead.

## Notes

- Server memberships are purchased with Enclave Social tokens via `create-platform-checkout`.
