# Discord Roblox Link

A small Vercel service for linking a Discord user to a Roblox account using Roblox OAuth 2.0 + PKCE.

## Vercel environment variables

- `ROBLOX_CLIENT_ID`
- `ROBLOX_CLIENT_SECRET`
- `ROBLOX_REDIRECT_URI`
- `DISCORD_OAUTH_SECRET`
- `KV_REST_API_URL`
- `KV_REST_API_TOKEN`

The Redis variables are supplied by an Upstash Redis integration.

## Roblox callback

Set `ROBLOX_REDIRECT_URI` to:

`https://YOUR-SERVICE-DOMAIN/callback`

That exact URI must also be registered in the Roblox OAuth application.

## Routes

`/start?discord_user_id=...&sig=...`

`/callback`

`/lookup?discord_user_id=...`

`/unlink?discord_user_id=...`

Roblox OAuth uses the authorization-code flow with PKCE and the `openid profile` scopes.
