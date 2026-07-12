# AuthPort

[![CI](https://github.com/arpan404/authport/actions/workflows/ci.yml/badge.svg)](https://github.com/arpan404/authport/actions/workflows/ci.yml)

Centralized, self-hosted [Better Auth](https://better-auth.com) service for multiple
apps. Bun + TypeScript, written in [Effect](https://effect.website) (typed error
channels, `Config`, `Layer` services, scoped resources), backed by Postgres.

## Requirements

- [Bun](https://bun.sh) 1.3.14
- PostgreSQL
- Redis (optional; recommended for multiple server instances)

## Quick start

```sh
bun install
cp .env.example .env
bun run auth:migrate   # creates a schema + tables per app
bun run dev
```

## Apps

The app allowlist lives in `apps.yaml`:

- `id` and provider IDs use canonical lowercase letters, digits, and single hyphens.
  Startup rejects derived-schema, provider, client routing, and secret-key collisions.
- `url` is the app's URL.
- `origins` are browser origins allowed to call this auth service (used for CORS).
- `clientId` is a **public** identifier a browser app sends via the `x-app-key`
  header. It is only trusted when the request's `Origin` is one of `origins`, so it
  is safe to ship in client-side code.
- `secretKeys` are **secret** credentials for server-to-server calls, also sent via
  `x-app-key`. They are trusted on their own (no `Origin` required), so never expose
  them to a browser.
- `socialProviders` lists enabled social logins (see below).

The `Authorization` header is left untouched by the app gate so it can carry a
Better Auth session/bearer token.

## Consuming apps (client SDK)

Apps use the standard Better Auth client SDK — AuthPort is just a Better Auth
`/api/auth/*` server behind a thin gate. Point `baseURL` at AuthPort and attach the
app key on every request via `fetchOptions` (this is the only AuthPort-specific bit):

```ts
import { createAuthClient } from "better-auth/client";
import { genericOAuthClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  baseURL: import.meta.env.VITE_AUTH_URL,       // e.g. https://auth.example.com
  plugins: [genericOAuthClient()],              // adds signIn.oauth2 for enterprise OIDC
  fetchOptions: {
    credentials: "include",                     // send/receive the session cookie
    headers: { "x-app-key": import.meta.env.VITE_APP_KEY }, // the app's public clientId
  },
});

await authClient.signUp.email({ email, password, name });
await authClient.signIn.email({ email, password });
await authClient.signIn.social({ provider: "google", callbackURL: "/" });
await authClient.signIn.oauth2({ providerId: "okta", callbackURL: "/" }); // enterprise OIDC
const { data: session } = await authClient.getSession();
```

Notes:

- In a browser the `x-app-key` value is the app's **public `clientId`** (safe to embed;
  only trusted alongside a configured `Origin`). Server-to-server callers send a
  **`secretKey`** instead.
- Add the matching client plugins for server features you use: `genericOAuthClient()`
  for enterprise OIDC, `jwtClient()` if you consume the JWT/JWKS endpoints. Framework
  wrappers (`better-auth/react`, `/vue`, `/svelte`) work the same way.
- All apps are structurally identical, so one client shape serves every app; the raw
  `fetch` calls shown below are just the low-level equivalent of these SDK methods.

## Isolation model

Each app is a **fully isolated user pool**. Every app gets its own Better Auth
instance bound to its own Postgres schema (`app_<id>`), so:

- The same email can register independently in two apps as separate accounts.
- Sessions, accounts, and JWKS signing keys never cross app boundaries — a token
  minted for one app is meaningless to another.
- Cookies are namespaced per app (`cookiePrefix`), so apps served from the same
  auth domain don't clobber each other's sessions.
- Redis keys are also namespaced per app, so cached sessions, verification records,
  and rate-limit counters cannot cross tenant boundaries.

`bun run auth:migrate` provisions the schema and Better Auth tables for every app
in `apps.yaml`. Re-run it after adding an app or upgrading Better Auth.

## Social login (Google, GitHub, Facebook, …)

1. Enable the provider under the app in `apps.yaml`:

   ```yaml
   apps:
     - id: authport-web
       # …
       socialProviders:
         - google
         - github
   ```

2. Provide credentials via env, named `<APP_ID>_<PROVIDER>_CLIENT_ID` / `_SECRET`
   where `<APP_ID>` is the uppercased app id (non-alphanumeric → `_`):

   ```sh
   AUTHPORT_WEB_GOOGLE_CLIENT_ID="…"
   AUTHPORT_WEB_GOOGLE_CLIENT_SECRET="…"
   ```

   Startup fails fast (typed `ProviderCredentialsError`) if an enabled provider is missing
   credentials. Credentials are per app, so the same provider can use different
   OAuth clients for different apps.

3. Register this exact redirect URI with the provider (one URI covers every app —
   requests are routed to the right app instance by the OAuth `state` cookie):

   ```
   ${BETTER_AUTH_URL}/api/auth/callback/<provider>
   ```

4. From a browser app, start the flow (include the app key and credentials):

   ```ts
   await fetch(`${AUTH_URL}/api/auth/sign-in/social`, {
     method: "POST",
     credentials: "include",
     headers: { "content-type": "application/json", "x-app-key": CLIENT_ID },
     body: JSON.stringify({ provider: "google", callbackURL: "/" }),
   });
   ```

Supported provider ids are Better Auth's built-in set (google, github, facebook,
apple, microsoft, discord, twitter, linkedin, gitlab, spotify, …).

## Session validation across domains

Two supported paths, both enabled per app:

- **Cross-subdomain cookies** — opt in **per app** with `cookieDomain` in `apps.yaml`
  (e.g. `.example.com`) so `auth.example.com` issues cookies usable by
  `app.example.com`. Only enable it for apps that trust their subdomain siblings —
  a shared cookie domain sends that app's session cookie to every subdomain under
  it. Without `cookieDomain`, cookies stay host-only on the auth origin and never
  reach other apps. Cookies are `SameSite=None; Secure` in production or whenever a
  `cookieDomain` is set.
- **Bearer / JWT** — for apps on unrelated domains or non-browser clients. The
  `bearer` plugin accepts `Authorization: Bearer <session-token>`; the `jwt` plugin
  exposes `/api/auth/token` and `/api/auth/jwks` (per app) so an app backend can
  verify sessions statelessly against that app's JWKS.

## Enterprise SSO (delegate to an external IdP)

Apps can delegate authentication to an external **OIDC** identity provider (Okta,
Azure AD / Entra, Google Workspace, Keycloak, Auth0 — anything with OIDC discovery).
This is wired via Better Auth's `genericOAuth` plugin, config-driven like social login.

1. Declare the IdP under the app in `apps.yaml` (non-secret bits):

   ```yaml
   apps:
     - id: authport-web
       # …
       oidcProviders:
         - providerId: okta
           discoveryUrl: https://your-tenant.okta.com/.well-known/openid-configuration
           scopes: [openid, email, profile]   # optional
   ```

2. Provide credentials via env, `<APP_ID>_OIDC_<PROVIDER_ID>_CLIENT_ID` / `_SECRET`:

   ```sh
   AUTHPORT_WEB_OIDC_OKTA_CLIENT_ID="…"
   AUTHPORT_WEB_OIDC_OKTA_CLIENT_SECRET="…"
   ```

3. Register this redirect URI with the IdP:

   ```
   ${BETTER_AUTH_URL}/api/auth/oauth2/callback/<providerId>
   ```

4. Start the flow from the app: `POST /api/auth/sign-in/oauth2` with `x-app-key` and
   `{ "providerId": "okta", "callbackURL": "/" }`.

### SAML

SAML IdPs are supported via the `@better-auth/sso` plugin, provisioned statically
from config (no dynamic registration needed).

1. Declare the IdP under the app in `apps.yaml`:

   ```yaml
   apps:
     - id: authport-web
       # …
       samlProviders:
         - providerId: acme-okta        # globally unique across all apps
           domain: acme.com             # email domain that routes users here
           issuer: https://acme.okta.com/exk...          # IdP entityID
           entryPoint: https://acme.okta.com/app/abc/sso/saml   # IdP SSO URL
   ```

   Signed assertions and an audience restriction (default: AuthPort's SP entityID)
   are **enforced automatically** — there is no option to disable them.

2. Put the IdP signing certificate (and optional SP private key) in env:

   ```sh
   AUTHPORT_WEB_SAML_ACME_OKTA_IDP_CERT="-----BEGIN CERTIFICATE-----…"
   # optional, for signing AuthnRequests / decryption:
   AUTHPORT_WEB_SAML_ACME_OKTA_SP_PRIVATE_KEY="…"
   ```

3. Give the IdP this **ACS (Assertion Consumer Service) URL**. Tenant-specific SP
   metadata is public at `${BETTER_AUTH_URL}/api/auth/sso/saml2/sp/metadata?providerId=<providerId>`:

   ```
   ${BETTER_AUTH_URL}/api/auth/sso/saml2/sp/acs/<providerId>
   ```

4. Start the flow from the app: `authClient.signIn.sso({ providerId: "acme-okta",
   callbackURL: "https://app.example.com/" })` (or by `{ email }` for domain
   routing). Pass `callbackURL` — it's the post-login redirect. Use the
   `ssoClient()` client plugin.

`providerId` must be globally unique because the IdP's ACS POST is a cross-site
request that carries no app key or cookie — AuthPort routes it to the right app
instance by the providerId in the ACS URL. Run `bun run auth:migrate` after adding
a SAML app (the plugin adds an `ssoProvider` table per schema).

SAML is strict by default: assertions must be signed, audience-restricted, timestamped,
use non-deprecated algorithms, and match a recent AuthnRequest. Unsolicited
IdP-initiated responses are rejected.

### AuthPort as an identity provider (not enabled)

The inverse — "Sign in with AuthPort" for your apps via the `oidc-provider` plugin —
is intentionally not enabled: an OIDC provider is a shared-identity surface, which
cuts against the fully-isolated model. It would apply to one designated app.

## Rate limiting

Rate limiting is enabled on every app instance (100 requests / 60s by default).
Set `REDIS_URL` so app-namespaced counters and session cache are shared across instances;
without it, storage falls back to per-process memory — fine for a single instance,
not for a horizontally-scaled deployment. Behind a proxy, set `IP_ADDRESS_HEADERS`
(e.g. `x-forwarded-for`) so per-IP limits resolve the real client instead of a
single shared bucket. Redis increments use one atomic operation, so parallel requests
cannot pass a stale read of the counter.

## Operations and capacity

- `/health` is a liveness endpoint. `/ready` checks PostgreSQL and Redis with a
  three-second timeout and returns 503 while dependencies are unavailable.
- SIGTERM/SIGINT stop new connections, allow up to ten seconds for in-flight requests,
  then close PostgreSQL, Redis, and the Effect runtime.
- Each app owns a bounded PostgreSQL pool. Total possible connections are
  `DATABASE_POOL_MAX_PER_APP × app count × replica count`; size the database and
  replica count together (or place PgBouncer in front).
- Bun rejects request bodies above `MAX_REQUEST_BODY_SIZE` before Better Auth parses
  them. The default is 512 KiB, leaving room for base64/form encoding around the
  SAML plugin's smaller decoded-response ceiling.
- HSTS is intentionally owned by the TLS edge, where domain-wide HTTPS readiness is
  known. Do not enable `includeSubDomains` or preload without reviewing every sibling.

## Security posture

Built-in, on by default:

- **Tenant isolation** — per-app Better Auth instance, Postgres schema, JWKS keys,
  and cookie prefix. Tokens/sessions never cross apps.
- **HTTPS enforced in production** — startup fails if `BETTER_AUTH_URL` is not
  an HTTPS origin, or if `BETTER_AUTH_SECRET` is weak, when `NODE_ENV=production`.
- **Host-only cookies by default**; cross-subdomain sharing is opt-in per app.
- **No cross-provider account linking by default** — an external IdP asserting an
  email cannot take over an existing account. Opt in per app via
  `accountLinking.trustedProviders` in `apps.yaml` (must name a provider configured
  on that app); linking then still requires a **matching email**
  (`allowDifferentEmails: false`), so a trusted provider can only link to an account
  with the same address.
- **SAML**: signed, audience-restricted, timestamped assertions using current
  algorithms; ACS routed by a globally-unique providerId.
- **Constant-time key comparison**; secret keys may be stored hashed as
  `sha256:<hex>` in `apps.yaml` so a config leak doesn't expose them.
- **Security headers** on every response (`X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, and COOP). HSTS is configured at the TLS edge.
- **Log hygiene** — raw error causes (possible tokens/PII) are never logged.

Your responsibility (deployment): terminate TLS, keep dependencies patched
(especially `@better-auth/sso`), set `IP_ADDRESS_HEADERS` + `REDIS_URL` when scaled,
and rotate `secretKeys`. Note the `x-app-key` gate is multi-tenant **routing + CORS**,
not app authentication — the security boundary is Better Auth itself.

## Layout

- `src/env.ts` — `Env` service; typed env loading via Effect `Config`.
- `src/apps.ts` — `apps.yaml` parsing (typed `AppsConfigError`) and the request gate.
- `src/db.ts` / `src/redis.ts` — scoped Postgres pools and optional Redis storage.
- `src/auth-factory.ts` — builds per-app Better Auth options (social, cookies, JWT).
- `src/auth.ts` — `AppsConfig` + `AuthRegistry` services and the composed `AppLive` layer.
- `src/server.ts` — Bun HTTP server; runs the Effect handler via `ManagedRuntime`.
- `src/migrate.ts` — per-app schema migrations.
- `src/errors.ts` — tagged error types.
