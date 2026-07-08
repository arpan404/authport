# Example consumer

A minimal app that signs in against AuthPort using the Better Auth client SDK,
including the enterprise SSO flow (`ssoClient()` → `signIn.sso`). It runs on
`http://localhost:3001`, the origin AuthPort trusts for the `authport-web` app in
`apps.yaml`.

> This models an **external consumer app**, so it uses the plain Better Auth SDK
> (what real customers write) — unlike the AuthPort service itself, which is
> Effect-based.

## Run

```sh
# 1. Start AuthPort (repo root), migrated against Postgres:
bun run auth:migrate
bun run dev                     # http://localhost:3000

# 2. Start this consumer:
bun examples/consumer/serve.ts  # http://localhost:3001
```

Open http://localhost:3001 and try the buttons.

## What it shows

- `authClient` (`authClient.ts`) — `createAuthClient` pointed at AuthPort with the
  only AuthPort-specific bit: `fetchOptions` attaching `x-app-key` + `credentials`.
- `signIn.sso({ providerId })` — enterprise SSO to a specific IdP.
- `signIn.sso({ email })` — enterprise SSO routed by the email's domain.
- `signIn.social({ provider })` — social login.
- `getSession()` / `signOut()`.

To actually complete an SSO login you need the matching provider configured on the
AuthPort side (`samlProviders`/`socialProviders` in `apps.yaml` + credentials in env).
