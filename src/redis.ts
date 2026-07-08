import { RedisClient } from "bun";
import { Context, Effect, Layer, Option, Redacted } from "effect";
import { Env } from "./env";

/** The shape Better Auth expects for `secondaryStorage`. */
export type SecondaryStorageApi = {
  get: (key: string) => Promise<string | null>;
  set: (key: string, value: string, ttl?: number) => Promise<void>;
  delete: (key: string) => Promise<void>;
};

/**
 * Optional shared storage for rate-limit counters and session cache. `Some` when
 * `REDIS_URL` is set, `None` otherwise (falling back to Better Auth's in-memory
 * storage). The adapter methods are the boundary to Better Auth's Promise-based
 * API — each runs a small Effect against a scoped Redis client.
 */
export class SecondaryStorage extends Context.Tag("SecondaryStorage")<
  SecondaryStorage,
  Option.Option<SecondaryStorageApi>
>() {}

const acquireClient = (url: string) =>
  Effect.acquireRelease(
    Effect.sync(() => new RedisClient(url)),
    (client) => Effect.sync(() => client.close()),
  );

const make = Effect.gen(function* () {
  const { redisUrl } = yield* Env;
  if (Option.isNone(redisUrl)) return Option.none<SecondaryStorageApi>();

  const client = yield* acquireClient(Redacted.value(redisUrl.value));

  const api: SecondaryStorageApi = {
    get: (key) => Effect.runPromise(Effect.promise(() => client.get(key))),
    set: (key, value, ttl) =>
      Effect.runPromise(
        Effect.promise(() =>
          ttl ? client.set(key, value, "EX", ttl) : client.set(key, value),
        ).pipe(Effect.asVoid),
      ),
    delete: (key) =>
      Effect.runPromise(Effect.promise(() => client.del(key)).pipe(Effect.asVoid)),
  };

  return Option.some(api);
});

export const SecondaryStorageLive = Layer.scoped(SecondaryStorage, make);
