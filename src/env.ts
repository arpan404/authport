import { Config, Context, Effect, Layer, Option, Redacted } from "effect";

export type EnvValues = {
  readonly databaseUrl: Redacted.Redacted<string>;
  readonly authUrl: string;
  readonly secret: Redacted.Redacted<string>;
  readonly appName: string;
  readonly port: number;
  readonly cookieDomain: Option.Option<string>;
  readonly isProd: boolean;
  readonly redisUrl: Option.Option<Redacted.Redacted<string>>;
};

/** Resolved process configuration. Reading is effectful and fails (with Effect's
 * own ConfigError) if a required variable is missing. */
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
    const cookieDomain = yield* Config.option(Config.string("COOKIE_DOMAIN"));
    const isProd: boolean = yield* Config.string("NODE_ENV").pipe(
      Config.withDefault("development"),
      Config.map((value) => value === "production"),
    );
    const redisUrl = yield* Config.option(Config.redacted("REDIS_URL"));

    return {
      databaseUrl,
      authUrl,
      secret,
      appName,
      port,
      cookieDomain,
      isProd,
      redisUrl,
    } satisfies EnvValues;
  });

export const EnvLive = Layer.effect(Env, load);
