import { betterAuth } from "better-auth";
import { Context, Effect, Layer, Option } from "effect";
import type { App, AppsConfig as AppsConfigValue } from "./apps";
import { loadAppsConfig } from "./apps";
import { buildAuthOptions } from "./auth-factory";
import { Env, EnvLive } from "./env";
import { SecondaryStorage, SecondaryStorageLive } from "./redis";

type AuthInstance = ReturnType<typeof betterAuth>;

export type AuthApp = {
  app: App;
  auth: AuthInstance;
  checkDatabase: () => Promise<void>;
};

/** The parsed apps.yaml, available as a service. */
export class AppsConfig extends Context.Tag("AppsConfig")<
  AppsConfig,
  AppsConfigValue
>() {}

export const AppsConfigLive = Layer.effect(AppsConfig, loadAppsConfig);

/**
 * One Better Auth instance per app, keyed by app id. Each is bound to its own
 * Postgres schema, so user pools, sessions, accounts and JWKS keys are fully
 * isolated. Built once as a scoped layer; the per-app pools live for the layer's
 * lifetime and are released on teardown.
 */
export class AuthRegistry extends Context.Tag("AuthRegistry")<
  AuthRegistry,
  {
    readonly lookup: (appId: string) => Option.Option<AuthApp>;
    readonly checkReadiness: () => Promise<void>;
  }
>() {}

const buildRegistry = Effect.gen(function* () {
  const env = yield* Env;
  const { apps } = yield* AppsConfig;
  const storage = yield* SecondaryStorage;

  const entries = yield* Effect.forEach(apps, (app) =>
    buildAuthOptions(app, env, storage).pipe(
      Effect.map(({ options, checkDatabase }) =>
        [app.id, { app, auth: betterAuth(options), checkDatabase }] as const,
      ),
    ),
  );

  const map = new Map<string, AuthApp>(entries);
  return AuthRegistry.of({
    lookup: (appId) => Option.fromNullable(map.get(appId)),
    checkReadiness: async () => {
      const first = entries[0]?.[1];
      if (!first) throw new Error("No auth apps configured");
      await Promise.all([
        first.checkDatabase(),
        ...(Option.isSome(storage) ? [storage.value.ping()] : []),
      ]);
    },
  });
});

const AuthRegistryLive = Layer.scoped(AuthRegistry, buildRegistry);

// Storage needs Env; the registry needs Env + AppsConfig + Storage. Shared layer
// references are memoized, so Env/AppsConfig are each built once.
const StorageLive = SecondaryStorageLive.pipe(Layer.provide(EnvLive));
const RegistryLive = AuthRegistryLive.pipe(
  Layer.provide(Layer.mergeAll(EnvLive, AppsConfigLive, StorageLive)),
);

/** Everything the server needs: the app allowlist plus the per-app auth registry. */
export const AppLive = Layer.merge(AppsConfigLive, RegistryLive);
