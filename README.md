# AuthPort

[![CI](https://github.com/arpan404/authport/actions/workflows/ci.yml/badge.svg)](https://github.com/arpan404/authport/actions/workflows/ci.yml)

Self-hosted, multi-app authentication gateway powered by
[Better Auth](https://better-auth.com). AuthPort gives every app an isolated user
pool while running passwords, passkeys, passwordless email/phone, social login,
OIDC, and SAML from one Bun service.

AuthPort is a thin gateway, not a shared identity provider. Apps share the service,
but not users, sessions, keys, or database tables.

## Features

- Isolated Better Auth instance and PostgreSQL schema per app
- Passwords, usernames, passkeys, magic links, email/phone OTP, and 2FA
- Social login, generic OIDC, and SAML SSO
- Host-only, app-namespaced cookies by default
- Per-app JWKS, bearer tokens, and Redis namespaces
- Config-driven app and provider registration
- Rate limiting, readiness checks, graceful shutdown, and security headers
- Strict startup validation for production configuration

Every app supports email verification, link and OTP password recovery, password
changes, TOTP, email-code 2FA, trusted devices, and encrypted backup codes. See
[`docs/authentication.md`](docs/authentication.md) for client methods.

## How it works

Apps are declared in `apps.yaml`. Each entry gets its own Better Auth instance,
PostgreSQL schema, cookie prefix, JWKS keys, and optional Redis namespace.

Browser requests send the app's public `clientId` in `x-app-key` from an allowed
origin. Server-to-server requests send a secret key instead. Provider callbacks are
routed using provider state, cookies, or a globally unique SAML provider ID.

> `x-app-key` selects an app and enforces the browser origin allowlist. It is not
> user authentication; Better Auth credentials and sessions remain the security
> boundary.

## Requirements

- [Bun](https://bun.sh) 1.3.14
- PostgreSQL
- Redis (optional; recommended when running more than one instance)

## Quick start

```sh
git clone https://github.com/arpan404/authport.git
cd authport
bun install
cp .env.example .env
```

Set `DATABASE_URL` and generate an auth secret:

```sh
openssl rand -base64 32
```

Put the result in `BETTER_AUTH_SECRET`, configure your apps in `apps.yaml`, then
create the database schemas and start the service:

```sh
bun run auth:migrate
bun run dev
```

AuthPort starts at `http://localhost:3000` by default. Liveness and readiness are
available at `/health` and `/ready`.

## Configure apps

```yaml
apps:
  - id: authport-web
    name: AuthPort Web
    url: http://localhost:3001
    origins:
      - http://localhost:3001

    # Public browser identifier. Trusted only with an allowed Origin.
    clientId: authport-web

    # Private server-to-server credentials. sha256:<hex> is also supported.
    secretKeys:
      - dev-secret-change-me

    # Required for production email delivery.
    emailFrom: auth@example.com

    socialProviders:
      - google

    oidcProviders:
      - providerId: okta
        discoveryUrl: https://example.okta.com/.well-known/openid-configuration
        scopes: [openid, email, profile]

    samlProviders:
      - providerId: acme-okta
        domain: acme.com
        issuer: https://acme.okta.com/example
        entryPoint: https://acme.okta.com/app/example/sso/saml

    # Optional: share this app's cookie with trusted sibling subdomains.
    # cookieDomain: ".example.com"

    # Optional: allow same-email linking from explicitly trusted providers.
    # accountLinking:
    #   trustedProviders: [google]
```

App and provider IDs use lowercase letters, digits, and single hyphens. Startup
rejects duplicate IDs, derived schema collisions, cross-app secret reuse, invalid
provider URLs, and unconfigured trusted link providers.

## Connect an app

Use the standard Better Auth client and attach the app's public `clientId` to every
request:

```ts
import { ssoClient } from "@better-auth/sso/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { createAuthClient } from "better-auth/client";
import {
  emailOTPClient,
  genericOAuthClient,
  magicLinkClient,
  phoneNumberClient,
  twoFactorClient,
  usernameClient,
} from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: "https://auth.example.com",
  plugins: [
    ssoClient(),
    genericOAuthClient(),
    usernameClient(),
    passkeyClient(),
    magicLinkClient(),
    emailOTPClient(),
    phoneNumberClient(),
    twoFactorClient(),
  ],
  fetchOptions: {
    credentials: "include",
    headers: { "x-app-key": "authport-web" },
  },
});

await authClient.signUp.email({ email, password, name });
await authClient.signIn.email({ email, password });
await authClient.signIn.social({ provider: "google", callbackURL: "/" });
await authClient.signIn.oauth2({ providerId: "okta", callbackURL: "/" });
await authClient.signIn.sso({ providerId: "acme-okta", callbackURL: "/" });
await authClient.signIn.passkey();
await authClient.signIn.magicLink({ email, callbackURL: "/" });
```

See [`examples/consumer`](examples/consumer) for a runnable browser client.

## Providers

Provider secrets are stored in environment variables, never in `apps.yaml`.

| Type | Configuration | Redirect URL |
| --- | --- | --- |
| Social | `<APP_ID>_<PROVIDER>_CLIENT_ID` and `_SECRET` | `${BETTER_AUTH_URL}/api/auth/callback/<provider>` |
| OIDC | `<APP_ID>_OIDC_<PROVIDER_ID>_CLIENT_ID` and `_SECRET` | `${BETTER_AUTH_URL}/api/auth/oauth2/callback/<providerId>` |
| SAML | `<APP_ID>_SAML_<PROVIDER_ID>_IDP_CERT` and optional `_SP_PRIVATE_KEY` | `${BETTER_AUTH_URL}/api/auth/sso/saml2/sp/acs/<providerId>` |

For environment variable names, app and provider IDs are uppercased and
non-alphanumeric characters become underscores. SAML metadata is available at:

```text
${BETTER_AUTH_URL}/api/auth/sso/saml2/sp/metadata?providerId=<providerId>
```

SAML assertions must be signed, audience-restricted, timestamped, use current
algorithms, and match a recent AuthnRequest. Unsolicited IdP-initiated responses are
rejected.

## Sessions across domains

Cookies are host-only by default. For trusted sibling subdomains, set an app's
`cookieDomain` to a shared parent such as `.example.com`. Do not enable this for
apps that do not trust every sibling receiving the cookie.

For unrelated domains or non-browser clients, use Better Auth's bearer/JWT flow.
Each app exposes its own `/api/auth/token` and `/api/auth/jwks` endpoints.

## Production

### Transactional delivery

Local development defaults to `NOTIFICATION_DELIVERY=console`, which prints links
and OTPs. Production rejects console delivery and requires Cloudflare Email Service
and Twilio credentials from `.env.example`.

Onboard every `emailFrom` domain before sending:

```sh
npx wrangler email sending enable example.com
```

Use a Twilio API key in production and set `TWILIO_FROM` to a Twilio sender. Run
`bun run auth:migrate` after enabling these auth methods so every app schema gains
the passkey, username, phone, and two-factor fields/tables.

Important environment settings are documented in `.env.example`:

| Variable | Purpose |
| --- | --- |
| `BETTER_AUTH_URL` | Public HTTPS origin of AuthPort |
| `BETTER_AUTH_SECRET` | Random secret with at least 32 characters |
| `DATABASE_URL` | PostgreSQL connection string |
| `DATABASE_POOL_MAX_PER_APP` | Maximum connections in each app pool |
| `MAX_REQUEST_BODY_SIZE` | Bun request body limit, up to 1 MiB |
| `REDIS_URL` | Shared session cache and atomic rate-limit storage |
| `IP_ADDRESS_HEADERS` | Trusted proxy headers used to resolve client IPs |
| `NOTIFICATION_DELIVERY` | `console` locally or `providers` in production |
| `CLOUDFLARE_*` | Cloudflare account and Email Service API credentials |
| `TWILIO_*` | Twilio API credentials and SMS sender |

Production mode requires HTTPS and a strong auth secret. Terminate TLS at the edge,
configure HSTS there, keep Better Auth and the SSO plugin patched, use Redis when
scaling horizontally, and budget database connections as:

```text
pool size per app × app count × replica count
```

## Commands

| Command | Purpose |
| --- | --- |
| `bun run dev` | Start with file watching |
| `bun run start` | Start the service |
| `bun run auth:migrate` | Apply additive Better Auth migrations per app |
| `bun test` | Run the test suite |
| `bun run typecheck` | Type-check without emitting files |

## Project structure

```text
src/apps.ts          App config, validation, and request routing
src/auth-factory.ts  Per-app Better Auth configuration
src/auth.ts          App registry and Effect layers
src/db.ts            Scoped PostgreSQL pools
src/redis.ts         Optional namespaced Redis storage
src/notifications.ts Cloudflare email and Twilio SMS delivery
src/server.ts        Bun HTTP server and lifecycle
src/migrate.ts       Per-app additive migrations
examples/consumer    Minimal browser client
```

## License

[MIT](LICENSE) © 2026 arpan404
