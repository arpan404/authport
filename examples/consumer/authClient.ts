import { createAuthClient } from "better-auth/client";
import { genericOAuthClient } from "better-auth/client/plugins";
import { ssoClient } from "@better-auth/sso/client";

// The AuthPort service origin. AuthPort appends /api/auth itself.
const AUTH_URL = "http://localhost:3000";

// This app's PUBLIC identifier from apps.yaml (`clientId`). Safe to ship in the
// browser — AuthPort only trusts it alongside a configured Origin.
const APP_KEY = "authport-web";

/**
 * A standard Better Auth client, pointed at AuthPort. The only AuthPort-specific
 * config is `fetchOptions`: attach `x-app-key` on every request and send cookies.
 *
 * - ssoClient()         -> authClient.signIn.sso(...)      (enterprise SAML/OIDC)
 * - genericOAuthClient() -> authClient.signIn.oauth2(...)  (generic OIDC)
 */
export const authClient = createAuthClient({
  baseURL: AUTH_URL,
  plugins: [ssoClient(), genericOAuthClient()],
  fetchOptions: {
    credentials: "include",
    headers: { "x-app-key": APP_KEY },
  },
});
