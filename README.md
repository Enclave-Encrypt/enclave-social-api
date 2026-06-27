# Enclave Social API

Supabase edge functions and migrations for **Enclave Social**. Lives in **Enclave-Encrypt** alongside other product APIs.

The Social **app** is [`Enclave-Social/enclave-social`](https://github.com/Enclave-Social/enclave-social). E2EE/MLS cryptography is client-side in [`Enclave-Social/enclave-social-sdk`](https://github.com/Enclave-Social/enclave-social-sdk) (AGPL).

## Layout

```
enclave-social-api/
  supabase/
    functions/           # Social edge handlers (auth exchange, LiveKit, Stripe, notifications)
    migrations/          # Core Social schema (excludes sign_* and verify_* product migrations)
```

Sign and Verify APIs are separate: `enclave-sign-api`, `enclave-verify-api`.

## Deploy

Currently on the Social data Supabase project (`kltykhkcvdwhfjgvevbt`):

```bash
npm run deploy
# or
npx supabase db push
```

## License

AGPL-3.0-or-later
