import { describe, expect, test } from "bun:test";
import { Effect, Option } from "effect";
import {
  appForRequest,
  appForSamlCallback,
  appForSamlMetadata,
  corsHeadersFor,
  parseAppsConfig,
  type AppsConfig,
} from "./apps";

const load = (yaml: string): AppsConfig => Effect.runSync(parseAppsConfig(yaml));

const config = load(`
apps:
  - id: web
    name: Web app
    url: http://localhost:3001
    origins:
      - https://app.example.com
    clientId: web-client
    secretKeys:
      - web-secret
`);

const appId = (request: Request) =>
  Option.map(appForRequest(request, config), (app) => app.id);

describe("app allowlist", () => {
  test("allows a browser clientId from a configured origin", () => {
    const request = new Request("http://auth.local/api/auth/session", {
      headers: {
        origin: "https://app.example.com",
        "x-app-key": "web-client",
      },
    });

    expect(appId(request)).toEqual(Option.some("web"));
    expect(
      Option.map(corsHeadersFor(request, config), (h) =>
        h.get("access-control-allow-origin"),
      ),
    ).toEqual(Option.some("https://app.example.com"));
  });

  test("allows a server-to-server secret key with no origin", () => {
    const request = new Request("http://auth.local/api/auth/session", {
      headers: { "x-app-key": "web-secret" },
    });

    expect(appId(request)).toEqual(Option.some("web"));
  });

  test("rejects a clientId from an unknown origin", () => {
    const request = new Request("http://auth.local/api/auth/session", {
      headers: {
        origin: "https://evil.example.com",
        "x-app-key": "web-client",
      },
    });

    expect(appForRequest(request, config)).toEqual(Option.none());
    expect(corsHeadersFor(request, config)).toEqual(Option.none());
  });

  test("rejects a public clientId sent without an origin", () => {
    const request = new Request("http://auth.local/api/auth/session", {
      headers: { "x-app-key": "web-client" },
    });

    expect(appForRequest(request, config)).toEqual(Option.none());
  });

  test("rejects a configured origin without any app key", () => {
    const request = new Request("http://auth.local/api/auth/session", {
      headers: { origin: "https://app.example.com" },
    });

    expect(appForRequest(request, config)).toEqual(Option.none());
  });

  test("ignores Authorization bearer for the app gate", () => {
    const request = new Request("http://auth.local/api/auth/session", {
      headers: {
        origin: "https://app.example.com",
        authorization: "Bearer web-secret",
      },
    });

    expect(appForRequest(request, config)).toEqual(Option.none());
  });

  test("derives an isolated Postgres schema from a canonical app id", () => {
    const derived = load(`
apps:
  - id: authport-web
    url: http://localhost:3001
    clientId: c
`);

    expect(derived.apps[0]?.schema).toBe("app_authport_web");
  });

  test("rejects app ids that normalize ambiguously", () => {
    const result = Effect.runSync(
      parseAppsConfig(`
apps:
  - id: authport--web
    url: http://localhost:3001
    clientId: c
`).pipe(Effect.either),
    );

    expect(result._tag).toBe("Left");
  });

  test("parses enterprise OIDC providers", () => {
    const derived = load(`
apps:
  - id: web
    url: http://localhost:3001
    clientId: c
    oidcProviders:
      - providerId: okta
        discoveryUrl: https://acme.okta.com/.well-known/openid-configuration
        scopes: [openid, email]
`);

    expect(derived.apps[0]?.oidcProviders[0]).toEqual({
      providerId: "okta",
      discoveryUrl: "https://acme.okta.com/.well-known/openid-configuration",
      scopes: ["openid", "email"],
    });
  });

  test("rejects an OIDC provider with an invalid discoveryUrl", () => {
    const result = Effect.runSync(
      parseAppsConfig(`
apps:
  - id: web
    url: http://localhost:3001
    clientId: c
    oidcProviders:
      - providerId: okta
        discoveryUrl: not-a-url
`).pipe(Effect.either),
    );

    expect(result._tag).toBe("Left");
  });

  test("parses SAML providers and routes ACS callbacks by providerId", () => {
    const derived = load(`
apps:
  - id: web
    url: http://localhost:3001
    clientId: c
    samlProviders:
      - providerId: acme-okta
        domain: acme.com
        issuer: https://acme.okta.com/exk123
        entryPoint: https://acme.okta.com/app/abc/sso/saml
`);

    expect(derived.apps[0]?.samlProviders[0]?.providerId).toBe("acme-okta");

    // A cross-site SAML ACS POST — no x-app-key, no cookie — routes by providerId.
    const acs = new Request(
      "http://auth.local/api/auth/sso/saml2/sp/acs/acme-okta",
      { method: "POST" },
    );
    expect(Option.map(appForSamlCallback(acs, derived), (a) => a.id)).toEqual(
      Option.some("web"),
    );
  });

  test("does not treat a social callback as a SAML callback", () => {
    const derived = load(`
apps:
  - id: web
    url: http://localhost:3001
    clientId: c
    samlProviders:
      - providerId: google
        domain: acme.com
        issuer: https://acme.example/issuer
        entryPoint: https://acme.example/sso
`);
    const callback = new Request("http://auth.local/api/auth/callback/google");
    expect(appForSamlCallback(callback, derived)).toEqual(Option.none());
  });

  test("routes public SAML metadata by providerId", () => {
    const derived = load(`
apps:
  - id: web
    url: http://localhost:3001
    clientId: c
    samlProviders:
      - providerId: acme
        domain: acme.com
        issuer: https://acme.example/issuer
        entryPoint: https://acme.example/sso
`);
    const request = new Request(
      "http://auth.local/api/auth/sso/saml2/sp/metadata?providerId=acme",
    );
    expect(Option.map(appForSamlMetadata(request, derived), (a) => a.id)).toEqual(
      Option.some("web"),
    );
  });

  test("rejects SAML providerIds that collide across apps", () => {
    const result = Effect.runSync(
      parseAppsConfig(`
apps:
  - id: a
    url: http://localhost:3001
    clientId: a
    samlProviders:
      - providerId: shared
        domain: a.com
        issuer: https://a.example/i
        entryPoint: https://a.example/sso
  - id: b
    url: http://localhost:3002
    clientId: b
    samlProviders:
      - providerId: shared
        domain: b.com
        issuer: https://b.example/i
        entryPoint: https://b.example/sso
`).pipe(Effect.either),
    );

    expect(result._tag).toBe("Left");
  });

  test("accepts trusted link providers that reference a configured provider", () => {
    const derived = load(`
apps:
  - id: web
    url: http://localhost:3001
    clientId: c
    socialProviders: [google]
    accountLinking:
      trustedProviders: [google]
`);

    expect(derived.apps[0]?.trustedLinkProviders).toEqual(["google"]);
  });

  test("rejects a trusted link provider that is not configured on the app", () => {
    const result = Effect.runSync(
      parseAppsConfig(`
apps:
  - id: web
    url: http://localhost:3001
    clientId: c
    socialProviders: [google]
    accountLinking:
      trustedProviders: [github]
`).pipe(Effect.either),
    );

    expect(result._tag).toBe("Left");
  });

  test("rejects duplicate app ids", () => {
    const result = Effect.runSync(
      parseAppsConfig(`
apps:
  - id: web
    url: http://localhost:3001
    clientId: a
  - id: web
    url: http://localhost:3002
    clientId: b
`).pipe(Effect.either),
    );

    expect(result._tag).toBe("Left");
  });

  test("rejects shared server secrets across apps", () => {
    const result = Effect.runSync(
      parseAppsConfig(`
apps:
  - id: a
    url: http://localhost:3001
    secretKeys: [shared]
  - id: b
    url: http://localhost:3002
    secretKeys: [shared]
`).pipe(Effect.either),
    );

    expect(result._tag).toBe("Left");
  });

  test("rejects a provider id shared across provider types", () => {
    const result = Effect.runSync(
      parseAppsConfig(`
apps:
  - id: web
    url: http://localhost:3001
    clientId: c
    socialProviders: [google]
    oidcProviders:
      - providerId: google
        discoveryUrl: https://accounts.example/.well-known/openid-configuration
`).pipe(Effect.either),
    );

    expect(result._tag).toBe("Left");
  });
});
