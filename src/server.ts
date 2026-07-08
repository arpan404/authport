import { Effect, Layer, ManagedRuntime, Option } from "effect";
import {
  appForCookies,
  appForRequest,
  appForSamlCallback,
  corsHeadersFor,
  type App,
  type AppsConfig as AppsConfigValue,
} from "./apps";
import { AppLive, AppsConfig, AuthRegistry, type AuthApp } from "./auth";
import { Env, EnvLive } from "./env";
import { AuthHandlerError, UnknownAppError } from "./errors";

const withCors = (response: Response, cors: Headers) => {
  const headers = new Headers(response.headers);
  cors.forEach((value, key) => headers.set(key, value));
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
};

const text = (body: string, status: number, headers?: Headers) =>
  new Response(body, headers ? { status, headers } : { status });

/** Runs the resolved app's isolated Better Auth handler, recovering to a 500. */
const runAuth = (authApp: AuthApp, request: Request) =>
  Effect.tryPromise({
    try: () => authApp.auth.handler(request),
    catch: (cause) => new AuthHandlerError({ appId: authApp.app.id, cause }),
  }).pipe(
    Effect.catchTag("AuthHandlerError", (error) =>
      Effect.logError(error.message).pipe(
        Effect.as(text("Internal Server Error", 500)),
      ),
    ),
  );

/**
 * Provider callbacks are top-level navigations from the IdP/provider, not browser
 * fetches — so CORS does not apply and there is no `x-app-key`. Social/OIDC GET
 * callbacks carry the app-prefixed cookie (routed by `appForCookies`); SAML ACS is
 * a cross-site POST with neither cookie nor key, routed by its unique providerId.
 */
const isProviderCallback = (pathname: string) =>
  pathname.startsWith("/api/auth/callback/") ||
  pathname.startsWith("/api/auth/oauth2/callback/") ||
  pathname.startsWith("/api/auth/sso/callback") ||
  pathname.startsWith("/api/auth/sso/saml2/sp/acs/") ||
  pathname.startsWith("/api/auth/sso/saml2/callback/") ||
  pathname.startsWith("/api/auth/sso/saml2/sp/slo/") ||
  pathname.startsWith("/api/auth/sso/saml2/logout/");

const resolveAuthApp = (app: App) =>
  Effect.gen(function* () {
    const registry = yield* AuthRegistry;
    return yield* registry.lookup(app.id).pipe(
      Option.match({
        onNone: () => Effect.fail(new UnknownAppError({ appId: app.id })),
        onSome: Effect.succeed,
      }),
    );
  });

/** Provider callbacks: route by cookie (OAuth) or providerId (SAML), no CORS. */
const handleProviderCallback = (request: Request, config: AppsConfigValue) =>
  Effect.gen(function* () {
    const app: Option.Option<App> = appForSamlCallback(request, config).pipe(
      Option.orElse(() => appForCookies(request, config)),
    );
    if (Option.isNone(app)) return text("Forbidden", 403);

    const authApp = yield* resolveAuthApp(app.value);
    return yield* runAuth(authApp, request);
  });

/** API requests (sign-in, session, etc.): CORS + x-app-key gate. */
const handleApiRequest = (request: Request, config: AppsConfigValue) =>
  Effect.gen(function* () {
    const cors = corsHeadersFor(request, config);
    if (Option.isNone(cors)) return text("Forbidden", 403);
    const corsHeaders = cors.value;

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const app = appForRequest(request, config);
    if (Option.isNone(app)) return text("Forbidden", 403, corsHeaders);

    const authApp = yield* resolveAuthApp(app.value);
    const response = yield* runAuth(authApp, request);
    return withCors(response, corsHeaders);
  });

const handleRequest = (request: Request) =>
  Effect.gen(function* () {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({ ok: true });
    }
    if (url.pathname !== "/api/auth" && !url.pathname.startsWith("/api/auth/")) {
      return text("Not Found", 404);
    }

    const config = yield* AppsConfig;
    return yield* isProviderCallback(url.pathname)
      ? handleProviderCallback(request, config)
      : handleApiRequest(request, config);
  }).pipe(
    // Any unexpected typed failure (e.g. UnknownAppError) becomes a logged 500.
    Effect.catchAll((error) =>
      Effect.logError(error).pipe(Effect.as(text("Internal Server Error", 500))),
    ),
  );

// The layer scope (per-app pools, Redis) lives for the runtime's lifetime.
const runtime = ManagedRuntime.make(Layer.mergeAll(AppLive, EnvLive));

// Force the registry to build now so config/env errors fail fast at startup.
const boot = Effect.gen(function* () {
  const env = yield* Env;
  const { apps } = yield* AppsConfig;
  yield* AuthRegistry;
  return { port: env.port, appIds: apps.map((app) => app.id) };
});

runtime
  .runPromise(boot)
  .then(({ port, appIds }) => {
    const server = Bun.serve({
      port,
      fetch: (request) => runtime.runPromise(handleRequest(request)),
    });
    runtime.runSync(
      Effect.log(
        `Auth service listening on ${server.url} for apps: ${appIds.join(", ")}`,
      ),
    );
  })
  .catch((error) => {
    runtime.runSync(Effect.logError(error));
    process.exit(1);
  });
