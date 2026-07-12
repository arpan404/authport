import { expect, test } from "bun:test";
import { Effect, Option, Redacted } from "effect";
import { parseAppsConfig } from "./apps";
import { buildAuthOptions, passkeyOptionsFor } from "./auth-factory";

test("passkeys are bound to the app origin and namespaced challenge cookie", () => {
  const config = Effect.runSync(
    parseAppsConfig(`
apps:
  - id: web
    name: Web
    url: https://app.example.com/path
    clientId: web
`),
  );

  expect(passkeyOptionsFor(config.apps[0]!)).toEqual({
    rpID: "app.example.com",
    rpName: "Web",
    origin: "https://app.example.com",
    advanced: { webAuthnChallengeCookie: "app_web.passkey_challenge" },
  });
});

test("every app exposes the configured authentication methods", async () => {
  const config = Effect.runSync(
    parseAppsConfig(`
apps:
  - id: web
    url: https://app.example.com
    clientId: web
`),
  );
  const built = await Effect.runPromise(
    buildAuthOptions(
      config.apps[0]!,
      {
        databaseUrl: Redacted.make("postgres://user:pass@localhost/authport"),
        authUrl: "https://auth.example.com",
        secret: Redacted.make("test-secret"),
        appName: "AuthPort",
        port: 3000,
        databasePoolMaxPerApp: 1,
        maxRequestBodySize: 524288,
        isProd: false,
        redisUrl: Option.none(),
        notifications: { mode: "console" },
        ipAddressHeaders: Option.none(),
      },
      Option.none(),
    ).pipe(Effect.scoped),
  );

  expect(built.options.plugins?.map((plugin) => plugin.id)).toEqual([
    "jwt",
    "bearer",
    "username",
    "passkey",
    "magic-link",
    "email-otp",
    "phone-number",
    "two-factor",
  ]);
});
