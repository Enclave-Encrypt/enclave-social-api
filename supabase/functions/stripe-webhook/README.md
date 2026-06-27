# stripe-webhook

Processes Stripe webhook events (checkout completion and token purchase fulfillment).

## Auth model

- `verify_jwt = false` in `supabase/config.toml` because Stripe does not send Supabase JWTs.
- Request authenticity is validated with Stripe signature verification using `stripe-signature` and `STRIPE_WEBHOOK_SECRET`.

## Required secrets

- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

## Notes

- This endpoint is intentionally public but cryptographically authenticated via Stripe signatures.
