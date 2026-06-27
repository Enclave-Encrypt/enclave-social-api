# send-message-notification

Dispatches Expo push notifications when new messages are inserted.

## Auth model

- `verify_jwt = false` in `supabase/config.toml` because this is invoked by a database trigger (`supabase_functions.http_request`) rather than a user client.
- Requests must include `x-webhooks-secret`.
- Function validates `x-webhooks-secret` against `MESSAGE_NOTIFICATION_WEBHOOK_SECRET`.

## Required secrets

- `MESSAGE_NOTIFICATION_WEBHOOK_SECRET` (must match `internal_job_secrets.message_notification`)
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

## Notes

- Keep this endpoint private to trigger callers only.
- If rotating the webhook secret, update both:
  - edge function secret `MESSAGE_NOTIFICATION_WEBHOOK_SECRET`
  - database row `internal_job_secrets` where `job_key = 'message_notification'`
