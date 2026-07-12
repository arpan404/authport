import { Effect, Scope } from "effect";
import { Kysely, PostgresDialect } from "kysely";
import { Pool } from "pg";

/**
 * Acquires a connection pool as a scoped resource (closed on scope teardown).
 * When `schema` is provided, every connection resolves unqualified table names
 * inside it — combined with one pool per app, this is what keeps each app's user
 * pool fully isolated. `schema` is derived and sanitized upstream (apps.ts).
 */
export const acquirePool = (
  connectionString: string,
  schema?: string,
  max = 5,
): Effect.Effect<Pool, never, Scope.Scope> =>
  Effect.acquireRelease(
    Effect.sync(
      () =>
        new Pool({
          connectionString,
          max,
          connectionTimeoutMillis: 5_000,
          idleTimeoutMillis: 30_000,
          ...(schema ? { options: `-c search_path=${schema}` } : {}),
        }),
    ),
    (pool) => Effect.promise(() => pool.end()),
  );

export const createDb = (pool: Pool) =>
  new Kysely({ dialect: new PostgresDialect({ pool }) });
