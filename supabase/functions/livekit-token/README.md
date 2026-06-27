# livekit-token

Mints LiveKit room tokens for Enclave Social voice channels.

## Status

**Required in production** — the app calls this endpoint via `supabase.functions.invoke` (`src/lib/livekit.ts`). Implementation is in `index.ts`.

## Auth model

- `verify_jwt = true` in `supabase/config.toml` (gateway rejects missing/invalid Social data JWTs).
- Handler also calls `supabase.auth.getUser(token)` before minting a room token.
- Caller uses `supabase.functions.invoke` with the active Social data session.

## Request / response

```http
POST /functions/v1/livekit-token
Content-Type: application/json

{
  "roomName": "channel-<id>",
  "participantName": "display name",
  "participantIdentity": "<auth user id>"
}
```

```json
{
  "token": "<livekit access token>",
  "url": "wss://enclave-social-nwgzvm4x.livekit.cloud"
}
```

## Required secrets (Social data project)

| Secret | Purpose |
|--------|---------|
| `LIVEKIT_API_KEY` | LiveKit API key |
| `LIVEKIT_API_SECRET` | LiveKit API secret |
| `LIVEKIT_URL` | Optional; default matches client `LIVEKIT_URL` |

Also standard Supabase function env: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, service role as needed for user lookup.

## Deploy

```bash
npx supabase link --project-ref kltykhkcvdwhfjgvevbt
npx supabase secrets set LIVEKIT_API_KEY=... LIVEKIT_API_SECRET=...
npx supabase functions deploy livekit-token
```

## Client references

- `src/lib/livekit.ts` — `fetchLiveKitToken`
- `src/lib/supabase.ts` — startup OPTIONS health probe
