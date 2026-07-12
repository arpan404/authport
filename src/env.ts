import { Config, Context, Effect, Layer, Option, Redacted } from "effect";
import { InsecureConfigError } from "./errors";

export type EnvValues = {
  readonly databaseUrl: Redacted.Redacted<string>;
  readonly authUrl: string;
  readonly secret: Redacted.Redacted<string>;
  readonly appName: string;
  readonly port: number;
  readonly databasePoolMaxPerApp: number;
  readonly maxRequestBodySize: number;
  readonly isProd: boolean;
  readonly redisUrl: Option.Option<Redacted.Redacted<string>>;
  /** Headers to resolve the real client IP behind a trusted proxy (rate limiting). */
  readonly ipAddressHeaders: Option.Option<string[]>;
};

/** Resolved process configuration. Reading is effectful and fails (Effect's own
 * ConfigError, or InsecureConfigError) if a required/secure variable is missing. */
export class Env extends Context.Tag("Env")<Env, EnvValues>() {}

const load = Effect.gen(function* () {
  const databaseUrl = yield* Config.redacted("DATABASE_URL");
  const authUrl = yield* Config.string("BETTER_AUTH_URL");
  const secret = yield* Config.redacted("BETTER_AUTH_SECRET");
  const appName: string = yield* Config.string("APP_NAME").pipe(
    Config.withDefault("AuthPort"),
  );
  const port: number = yield* Config.integer("PORT").pipe(
    Config.withDefault(3000),
  );
  const databasePoolMaxPerApp = yield* Config.integer(
    "DATABASE_POOL_MAX_PER_APP",
  ).pipe(Config.withDefault(5));
  const maxRequestBodySize = yield* Config.integer("MAX_REQUEST_BODY_SIZE").pipe(
    Config.withDefault(512 * 1024),
  );
  const isProd: boolean = yield* Config.string("NODE_ENV").pipe(
    Config.withDefault("development"),
    Config.map((value) => value === "production"),
  );
  const redisUrl = yield* Config.option(Config.redacted("REDIS_URL"));
  const ipAddressHeaders = yield* Config.option(
    Config.string("IP_ADDRESS_HEADERS"),
  ).pipe(
    Effect.map(
      Option.map((raw) =>
        raw
          .split(",")
          .map((header) => header.trim().toLowerCase())
          .filter(Boolean),
      ),
    ),
  );
  if (
    Option.isSome(ipAddressHeaders) &&
    (ipAddressHeaders.value.length === 0 ||
      ipAddressHeaders.value.some(
        (header) => !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(header),
      ))
  ) {
    yield* Effect.fail(
      new InsecureConfigError({
        message: "IP_ADDRESS_HEADERS must contain valid comma-separated header names",
      }),
    );
  }

  const parsedAuthUrl = yield* Effect.try({
    try: () => new URL(authUrl),
    catch: () =>
      new InsecureConfigError({ message: "BETTER_AUTH_URL must be a valid URL" }),
  });
  if (
    !["http:", "https:"].includes(parsedAuthUrl.protocol) ||
    parsedAuthUrl.username ||
    parsedAuthUrl.password ||
    parsedAuthUrl.pathname !== "/" ||
    parsedAuthUrl.search ||
    parsedAuthUrl.hash
  ) {
    yield* Effect.fail(
      new InsecureConfigError({
        message: "BETTER_AUTH_URL must be an http(s) origin without credentials or a path",
      }),
    );
  }
  if (isProd && parsedAuthUrl.protocol !== "https:") {
    yield* Effect.fail(
      new InsecureConfigError({
        message: "BETTER_AUTH_URL must use https:// in production",
      }),
    );
  }
  const secretValue = Redacted.value(secret);
  const estimatedEntropy =
    secretValue.length * Math.log2(new Set(secretValue).size || 1);
  if (
    isProd &&
    (secretValue.length < 32 ||
      estimatedEntropy < 120 ||
      secretValue === "replace-with-openssl-rand-base64-32")
  ) {
    yield* Effect.fail(
      new InsecureConfigError({
        message: "BETTER_AUTH_SECRET must be a random, high-entropy value of at least 32 characters",
      }),
    );
  }
  if (port < 1 || port > 65535) {
    yield* Effect.fail(new InsecureConfigError({ message: "PORT must be 1-65535" }));
  }
  if (databasePoolMaxPerApp < 1 || databasePoolMaxPerApp > 20) {
    yield* Effect.fail(
      new InsecureConfigError({
        message: "DATABASE_POOL_MAX_PER_APP must be 1-20",
      }),
    );
  }
  if (maxRequestBodySize < 1024 || maxRequestBodySize > 1024 * 1024) {
    yield* Effect.fail(
      new InsecureConfigError({
        message: "MAX_REQUEST_BODY_SIZE must be between 1 KiB and 1 MiB",
      }),
    );
  }

  return {
    databaseUrl,
    authUrl,
    secret,
    appName,
    port,
    databasePoolMaxPerApp,
    maxRequestBodySize,
    isProd,
    redisUrl,
    ipAddressHeaders,
  } satisfies EnvValues;
});

export const EnvLive = Layer.effect(Env, load);
