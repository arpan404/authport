import { getMigrations } from "better-auth/db/migration";
import { Effect, Option, Redacted } from "effect";
import { loadAppsConfig } from "./apps";
import { buildAuthOptions } from "./auth-factory";
import { acquirePool } from "./db";
import { Env, EnvLive } from "./env";
import { MigrationError } from "./errors";

/**
 * Idempotent, non-destructive migrator. For each app in apps.yaml it:
 *   - creates the app's Postgres schema if it doesn't exist (new app), else reuses it;
 *   - applies only Better Auth's ADDITIVE migrations (new tables / new columns).
 *
 * Better Auth migrations never drop tables or columns, so re-running only creates
 * new apps and updates existing ones — it never overwrites or deletes data.
 */
const program = Effect.gen(function* () {
  const env = yield* Env;
  const { apps } = yield* loadAppsConfig;
  const admin = yield* acquirePool(Redacted.value(env.databaseUrl), undefined, 1);

  const query = (appId: string, sql: string, params?: unknown[]) =>
    Effect.tryPromise({
      try: () => admin.query(sql, params),
      catch: (cause) => new MigrationError({ appId, cause }),
    });

  yield* Effect.forEach(
    apps,
    (app) =>
      Effect.gen(function* () {
        const existing = yield* query(
          app.id,
          "SELECT 1 FROM information_schema.schemata WHERE schema_name = $1",
          [app.schema],
        );
        const isNew = (existing.rowCount ?? 0) === 0;

        yield* query(app.id, `CREATE SCHEMA IF NOT EXISTS "${app.schema}"`);

        const { options } = yield* buildAuthOptions(app, env, Option.none());
        const { toBeCreated, toBeAdded, runMigrations } = yield* Effect.tryPromise({
          try: () => getMigrations(options),
          catch: (cause) => new MigrationError({ appId: app.id, cause }),
        });

        if (toBeCreated.length === 0 && toBeAdded.length === 0) {
          yield* Effect.log(`= ${app.id} (${app.schema}): up to date`);
          return;
        }

        yield* Effect.log(
          `${isNew ? "+ create" : "~ update"} ${app.id} (${app.schema}): ` +
            `${toBeCreated.length} new table(s), ${toBeAdded.length} table(s) gaining columns`,
        );
        yield* Effect.tryPromise({
          try: () => runMigrations(),
          catch: (cause) => new MigrationError({ appId: app.id, cause }),
        });
      }).pipe(Effect.scoped),
    { discard: true },
  );

  yield* Effect.log("migration complete — additive only, no data dropped");
});

Effect.runPromise(program.pipe(Effect.scoped, Effect.provide(EnvLive))).catch(
  (error) => {
    Effect.runSync(
      Effect.logError(error instanceof Error ? error.message : String(error)),
    );
    process.exit(1);
  },
);
