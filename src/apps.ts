import { timingSafeEqual } from "node:crypto";
import { Array as Arr, Config, Effect, Option, Schema } from "effect";
import { socialProviderList } from "better-auth/social-providers";
import { AppsConfigError } from "./errors";

const knownSocialProviders = new Set<string>(socialProviderList);

/** An external OIDC identity provider (Okta, Azure AD, Google Workspace, …). */
export type OidcProvider = {
  providerId: string;
  discoveryUrl: string;
  scopes?: string[];
};

/** An external SAML identity provider. `providerId` is globally unique across apps
 * (SAML ACS callbacks are routed by it, since they carry no app key or cookie). */
export type SamlProvider = {
  providerId: string;
  /** Email domain that routes a user to this IdP (e.g. "acme.com"). */
  domain: string;
  /** IdP entityID / issuer. */
  issuer: string;
  /** IdP single sign-on URL. */
  entryPoint: string;
  audience?: string;
  identifierFormat?: string;
  wantAssertionsSigned?: boolean;
};

export type App = {
  id: string;
  name?: string;
  url: string;
  origins: string[];
  /** Public, browser-facing identifier. Only trusted together with a matching Origin. */
  clientId?: string;
  /** Secret, server-to-server credentials. Never expose these to a browser. */
  secretKeys: string[];
  /** Postgres schema holding this app's isolated user pool. Derived from `id`. */
  schema: string;
  /** Enabled social providers (e.g. "google", "github"); credentials come from env. */
  socialProviders: string[];
  /** Enterprise SSO: external OIDC IdPs this app delegates to; credentials from env. */
  oidcProviders: OidcProvider[];
  /** Enterprise SSO: external SAML IdPs this app delegates to; cert/keys from env. */
  samlProviders: SamlProvider[];
};

export type AppsConfig = {
  apps: App[];
  trustedOrigins: string[];
};

const RawAppSchema = Schema.Struct({
  id: Schema.String,
  name: Schema.optional(Schema.String),
  url: Schema.String,
  origins: Schema.optional(Schema.Array(Schema.String)),
  clientId: Schema.optional(Schema.String),
  secretKeys: Schema.optional(Schema.Array(Schema.String)),
  socialProviders: Schema.optional(Schema.Array(Schema.String)),
  oidcProviders: Schema.optional(
    Schema.Array(
      Schema.Struct({
        providerId: Schema.String,
        discoveryUrl: Schema.String,
        scopes: Schema.optional(Schema.Array(Schema.String)),
      }),
    ),
  ),
  samlProviders: Schema.optional(
    Schema.Array(
      Schema.Struct({
        providerId: Schema.String,
        domain: Schema.String,
        issuer: Schema.String,
        entryPoint: Schema.String,
        audience: Schema.optional(Schema.String),
        identifierFormat: Schema.optional(Schema.String),
        wantAssertionsSigned: Schema.optional(Schema.Boolean),
      }),
    ),
  ),
});

type RawApp = Schema.Schema.Type<typeof RawAppSchema>;

const RawConfigSchema = Schema.Struct({
  apps: Schema.Array(RawAppSchema),
});

const fail = (message: string) => Effect.fail(new AppsConfigError({ message }));

const uniq = (items: readonly string[]) => [...new Set(items)];

// --- pure helpers -----------------------------------------------------------

/** Parses a URL's origin, returning None instead of throwing. */
const safeOrigin = (value: string | null | undefined): Option.Option<string> => {
  if (!value) return Option.none();
  try {
    return Option.some(new URL(value).origin);
  } catch {
    return Option.none();
  }
};

/** Origin of a browser request. Uses only the `Origin` header (never `Referer`)
 * so it matches the notion of origin used for CORS. */
export const requestOrigin = (request: Request): Option.Option<string> =>
  safeOrigin(request.headers.get("origin"));

/** Constant-time string comparison; the byte comparison does not short-circuit. */
const safeEqual = (a: string, b: string) => {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
};

/** Scans every secret without short-circuiting to avoid a timing side channel. */
const matchesSecretKey = (app: App, key: string) => {
  let matched = false;
  for (const secret of app.secretKeys) {
    if (safeEqual(secret, key)) matched = true;
  }
  return matched;
};

/**
 * Resolves the app authorized to make this request via the `x-app-key` header.
 * A public `clientId` is only trusted alongside a known `Origin` (browser flow);
 * a secret key is trusted on its own (server-to-server flow).
 */
export const appForRequest = (
  request: Request,
  config: AppsConfig,
): Option.Option<App> => {
  const key = request.headers.get("x-app-key");
  if (!key) return Option.none();

  const origin = requestOrigin(request);

  const byClient = Option.flatMap(origin, (o) =>
    Arr.findFirst(
      config.apps,
      (app) =>
        app.clientId !== undefined &&
        app.clientId === key &&
        app.origins.includes(o),
    ),
  );
  if (Option.isSome(byClient)) return byClient;

  return Arr.findFirst(config.apps, (app) => matchesSecretKey(app, key));
};

const stripCookiePrefix = (name: string) => name.replace(/^__(?:Secure|Host)-/, "");

/**
 * Routes a request by its app-prefixed cookies. OAuth callbacks (and other
 * top-level browser navigations) arrive as redirects from the provider without
 * an `x-app-key` header, but they still carry the app's cookies — each app uses
 * a distinct `cookiePrefix` (its schema), so the cookie name identifies the app.
 */
export const appForCookies = (
  request: Request,
  config: AppsConfig,
): Option.Option<App> => {
  const cookie = request.headers.get("cookie");
  if (!cookie) return Option.none();

  const names = cookie
    .split(";")
    .map((part) => stripCookiePrefix(part.trim().split("=")[0] ?? ""));

  return Arr.findFirst(config.apps, (app) =>
    names.some((name) => name.startsWith(`${app.schema}.`)),
  );
};

/**
 * Routes a SAML callback (ACS/SLO) by the `providerId` in its path. These are
 * cross-site POSTs from the IdP with no `x-app-key` and no cookies, so the
 * globally-unique providerId is the only routing signal.
 */
export const appForSamlCallback = (
  request: Request,
  config: AppsConfig,
): Option.Option<App> => {
  const providerId = new URL(request.url).pathname.split("/").filter(Boolean).pop();
  if (!providerId) return Option.none();
  return Arr.findFirst(config.apps, (app) =>
    app.samlProviders.some((provider) => provider.providerId === providerId),
  );
};

/**
 * CORS headers for a request. `None` means "reject" (a browser origin that is not
 * trusted); `Some(empty headers)` means "allow" a non-browser call with no Origin.
 */
export const corsHeadersFor = (
  request: Request,
  config: AppsConfig,
): Option.Option<Headers> => {
  const origin = request.headers.get("origin");
  if (!origin) return Option.some(new Headers());

  const normalized = safeOrigin(origin);
  if (
    Option.isNone(normalized) ||
    !config.trustedOrigins.includes(normalized.value)
  ) {
    return Option.none();
  }

  return Option.some(
    new Headers({
      "access-control-allow-credentials": "true",
      "access-control-allow-headers": "content-type, authorization, x-app-key",
      "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
      "access-control-allow-origin": origin,
      vary: "origin, access-control-request-headers, access-control-request-method",
    }),
  );
};

// --- config parsing (effectful, typed errors) -------------------------------

/** Derives a safe Postgres schema identifier from an app id (no injection surface). */
const toSchemaName = (id: string) => {
  const cleaned = id
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return `app_${cleaned}`;
};

const originEffect = (value: string, field: string) =>
  Option.match(safeOrigin(value), {
    onNone: () => fail(`${field} must be a valid URL`),
    onSome: (origin) => Effect.succeed(origin),
  });

const normalizeApp = (app: RawApp, index: number) =>
  Effect.gen(function* () {
    const id = app.id.trim();
    if (!id) yield* fail(`apps[${index}].id is required`);

    const url = app.url.trim();
    if (!url) yield* fail(`apps[${index}].url is required`);

    const urlOrigin = yield* originEffect(url, `apps[${index}].url`);
    const extraOrigins = yield* Effect.forEach(app.origins ?? [], (origin) =>
      originEffect(origin, `apps[${index}].origins`),
    );

    const name = app.name?.trim();
    const clientId = app.clientId?.trim();
    const secretKeys = (app.secretKeys ?? [])
      .map((key) => key.trim())
      .filter(Boolean);

    if (!clientId && secretKeys.length === 0) {
      yield* fail(`apps[${index}] must define a clientId, secretKeys, or both`);
    }

    const schema = toSchemaName(id);
    if (schema === "app_") yield* fail(`apps[${index}].id must be alphanumeric`);

    const socialProviders = uniq(
      (app.socialProviders ?? []).map((provider) => provider.trim().toLowerCase()),
    ).filter(Boolean);
    for (const provider of socialProviders) {
      if (!knownSocialProviders.has(provider)) {
        yield* fail(`apps[${index}].socialProviders has unknown provider "${provider}"`);
      }
    }

    const oidcProviders = yield* Effect.forEach(
      app.oidcProviders ?? [],
      (provider, i) =>
        Effect.gen(function* () {
          const providerId = provider.providerId.trim();
          if (!providerId) {
            yield* fail(`apps[${index}].oidcProviders[${i}].providerId is required`);
          }
          const discoveryUrl = provider.discoveryUrl.trim();
          if (Option.isNone(safeOrigin(discoveryUrl))) {
            yield* fail(
              `apps[${index}].oidcProviders[${i}].discoveryUrl must be a valid URL`,
            );
          }
          const scopes = provider.scopes ? [...provider.scopes] : undefined;
          return {
            providerId,
            discoveryUrl,
            ...(scopes ? { scopes } : {}),
          } satisfies OidcProvider;
        }),
    );
    const oidcIds = oidcProviders.map((provider) => provider.providerId);
    if (new Set(oidcIds).size !== oidcIds.length) {
      yield* fail(`apps[${index}].oidcProviders has duplicate providerId`);
    }

    const samlProviders = yield* Effect.forEach(
      app.samlProviders ?? [],
      (provider, i) =>
        Effect.gen(function* () {
          const providerId = provider.providerId.trim();
          if (!providerId) {
            yield* fail(`apps[${index}].samlProviders[${i}].providerId is required`);
          }
          const domain = provider.domain.trim();
          if (!domain) {
            yield* fail(`apps[${index}].samlProviders[${i}].domain is required`);
          }
          const issuer = provider.issuer.trim();
          if (!issuer) {
            yield* fail(`apps[${index}].samlProviders[${i}].issuer is required`);
          }
          const entryPoint = provider.entryPoint.trim();
          if (Option.isNone(safeOrigin(entryPoint))) {
            yield* fail(
              `apps[${index}].samlProviders[${i}].entryPoint must be a valid URL`,
            );
          }
          const audience = provider.audience?.trim();
          const identifierFormat = provider.identifierFormat?.trim();
          return {
            providerId,
            domain,
            issuer,
            entryPoint,
            ...(audience ? { audience } : {}),
            ...(identifierFormat ? { identifierFormat } : {}),
            ...(provider.wantAssertionsSigned !== undefined
              ? { wantAssertionsSigned: provider.wantAssertionsSigned }
              : {}),
          } satisfies SamlProvider;
        }),
    );
    const samlIds = samlProviders.map((provider) => provider.providerId);
    if (new Set(samlIds).size !== samlIds.length) {
      yield* fail(`apps[${index}].samlProviders has duplicate providerId`);
    }

    return {
      id,
      ...(name ? { name } : {}),
      url,
      origins: uniq([urlOrigin, ...extraOrigins]),
      ...(clientId ? { clientId } : {}),
      secretKeys,
      schema,
      socialProviders,
      oidcProviders,
      samlProviders,
    } satisfies App;
  });

export const parseAppsConfig = (
  source: string,
): Effect.Effect<AppsConfig, AppsConfigError> =>
  Effect.gen(function* () {
    const parsed = yield* Effect.try({
      try: () => Bun.YAML.parse(source),
      catch: () => new AppsConfigError({ message: "apps.yaml must be valid YAML" }),
    }).pipe(
      Effect.flatMap(Schema.decodeUnknown(RawConfigSchema)),
      Effect.mapError((error) => new AppsConfigError({ message: String(error) })),
    );

    const apps = yield* Effect.forEach(parsed.apps, normalizeApp);
    if (apps.length === 0) {
      yield* fail("apps.yaml must contain at least one app");
    }

    const ids = apps.map((app) => app.id);
    if (new Set(ids).size !== ids.length) {
      yield* fail("apps.yaml contains duplicate app ids");
    }

    // SAML ACS callbacks carry no app key or cookie, so they are routed by the
    // providerId in the URL path — which must therefore be globally unique.
    const samlIds = apps.flatMap((app) =>
      app.samlProviders.map((provider) => provider.providerId),
    );
    if (new Set(samlIds).size !== samlIds.length) {
      yield* fail("SAML providerId must be globally unique across apps");
    }

    return {
      apps,
      trustedOrigins: uniq(apps.flatMap((app) => app.origins)),
    } satisfies AppsConfig;
  });

/** Loads and parses apps.yaml from `APPS_CONFIG_PATH` (default "apps.yaml"). */
export const loadAppsConfig: Effect.Effect<AppsConfig, AppsConfigError> =
  Effect.gen(function* () {
    const path = yield* Config.string("APPS_CONFIG_PATH").pipe(
      Config.withDefault("apps.yaml"),
    );
    const source = yield* Effect.tryPromise({
      try: () => Bun.file(path).text(),
      catch: () => new AppsConfigError({ message: `Could not read ${path}` }),
    });
    return yield* parseAppsConfig(source);
  }).pipe(
    Effect.mapError((error) =>
      error instanceof AppsConfigError
        ? error
        : new AppsConfigError({ message: String(error) }),
    ),
  );
