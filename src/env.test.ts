import { expect, test } from "bun:test";
import { ConfigProvider, Effect } from "effect";
import { Env, EnvLive } from "./env";

const load = (values: Record<string, string>) =>
  Effect.runSync(
    Env.pipe(
      Effect.provide(EnvLive),
      Effect.withConfigProvider(
        ConfigProvider.fromMap(new Map(Object.entries(values))),
      ),
      Effect.either,
    ),
  );

const base = {
  DATABASE_URL: "postgres://user:password@localhost/authport",
  BETTER_AUTH_URL: "https://auth.example.com",
  NODE_ENV: "production",
  CLOUDFLARE_ACCOUNT_ID: "account",
  CLOUDFLARE_EMAIL_API_TOKEN: "email-token",
  TWILIO_ACCOUNT_SID: "AC00000000000000000000000000000000",
  TWILIO_API_KEY: "SK00000000000000000000000000000000",
  TWILIO_API_SECRET: "sms-secret",
  TWILIO_FROM: "+15555550100",
};

test("production rejects a weak Better Auth secret", () => {
  const result = load({ ...base, BETTER_AUTH_SECRET: "weak" });
  expect(result._tag).toBe("Left");
});

test("production accepts a random 32-byte Better Auth secret", () => {
  const result = load({
    ...base,
    BETTER_AUTH_SECRET: "p9Q3xL7mV2kN8sR4wT6yB1cD5fG0hJzA",
  });
  expect(result._tag).toBe("Right");
});

test("production rejects console notification delivery", () => {
  const result = load({
    ...base,
    BETTER_AUTH_SECRET: "p9Q3xL7mV2kN8sR4wT6yB1cD5fG0hJzA",
    NOTIFICATION_DELIVERY: "console",
  });
  expect(result._tag).toBe("Left");
});
