import { expect, test } from "bun:test";
import { Effect } from "effect";
import { parseAppsConfig } from "./apps";
import { passkeyOptionsFor } from "./auth-factory";

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
