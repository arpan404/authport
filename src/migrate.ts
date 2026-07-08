import { getMigrations } from "better-auth/db/migration";
import { Effect, Option, Redacted } from "effect";
import { loadAppsConfig } from "./apps";
import { buildAuthOptions } from "./auth-factory";
import { acquirePool } from "./db";
import { Env, EnvLive } from "./env";
import { MigrationError } from "./errors";

/**
 * Runs Better Auth's schema migrations once per app. Each app's tables live in
 * its own Postgres schema (isolated user pools), so we create the schema first,
 * then let Better Auth create/patch its tables inside it via the search_path set
 * on that app's pool.
 */
const program = Effect.gen(function* () {
  const env = yield* Env;
  const { apps } = yield* loadAppsConfig;
  const admin = yield* acquirePool(Redacted.value(env.databaseUrl));

  yield* Effect.forEach(
    apps,
    (app) =>
      Effect.gen(function* () {
        yield* Effect.tryPromise({
          try: () => admin.query(`CREATE SCHEMA IF NOT EXISTS "${app.schema}"`),
          catch: (cause) => new MigrationError({ appId: app.id, cause }),
        });

        const options = yield* buildAuthOptions(app, env, Option.none());
        const { runMigrations } = yield* Effect.tryPromise({
          try: () => getMigrations(options),
          catch: (cause) => new MigrationError({ appId: app.id, cause }),
        });
        yield* Effect.tryPromise({
          try: () => runMigrations(),
          catch: (cause) => new MigrationError({ appId: app.id, cause }),
        });

        yield* Effect.log(`migrated ${app.id} (schema "${app.schema}")`);
      }),
    { discard: true },
  );
});

Effect.runPromise(program.pipe(Effect.scoped, Effect.provide(EnvLive))).catch(
  (error) => {
    Effect.runSync(Effect.logError(error));
    process.exit(1);
  },
);
