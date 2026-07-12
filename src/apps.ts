import { createHash, timingSafeEqual } from "node:crypto";
import { Array as Arr, Config, Effect, Option, Schema } from "effect";
import { socialProviderList } from "better-auth/social-providers";
import { AppsConfigError } from "./errors";

const knownSocialProviders = new Set<string>(socialProviderList);
const reservedProviderIds = new Set(["credential"]);
const appIdPattern = /^(?=.{1,48}$)[a-z0-9]+(?:-[a-z0-9]+)*$/;
const providerIdPattern = /^(?=.{1,64}$)[a-z0-9]+(?:-[a-z0-9]+)*$/;

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
};

export type App = {
  id: string;
  name?: string;
  url: string;
  origins: string[];
  /** Public, browser-facing identifier. Only trusted together with a matching Origin. */
  clientId?: string;
  /** Secret, server-to-server credentials. May be plaintext or `sha256:<hex>` at rest. */
  secretKeys: string[];
  /** Verified sender address used for this app's transactional email. */
  emailFrom?: string;
  /** Opt-in shared parent domain for cross-subdomain cookies (e.g. ".example.com").
   * Only set for apps that trust their subdomain siblings; otherwise cookies stay
   * host-only on the auth origin and never reach sibling apps. */
  cookieDomain?: string;
  /** Postgres schema holding this app's isolated user pool. Derived from `id`. */
  schema: string;
  /** Enabled social providers (e.g. "google", "github"); credentials come from env. */
  socialProviders: string[];
  /** Enterprise SSO: external OIDC IdPs this app delegates to; credentials from env. */
  oidcProviders: OidcProvider[];
  /** Enterprise SSO: external SAML IdPs this app delegates to; cert/keys from env. */
  samlProviders: SamlProvider[];
  /** Providers whose verified email may link into an existing account. Empty means
   * no cross-provider linking (the safe default). Only list providers you trust not
   * to assert emails their users don't own. */
  trustedLinkProviders: string[];
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
  emailFrom: Schema.optional(Schema.String),
  cookieDomain: Schema.optional(Schema.String),
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
      }),
    ),
  ),
  accountLinking: Schema.optional(
    Schema.Struct({
      trustedProviders: Schema.optional(Schema.Array(Schema.String)),
    }),
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

const isSecureProviderUrl = (value: string) => {
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" ||
      (url.protocol === "http:" &&
        (url.hostname === "localhost" ||
          url.hostname === "127.0.0.1" ||
          url.hostname === "[::1]"))
    );
  } catch {
    return false;
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

const sha256Hex = (value: string) =>
  createHash("sha256").update(value).digest("hex");

/**
 * Matches a presented key against an app's secret keys in constant time, without
 * short-circuiting. A stored key may be plaintext or `sha256:<hex>` — the latter
 * lets apps.yaml hold only hashes at rest, so a config leak doesn't expose keys.
 */
const matchesSecretKey = (app: App, key: string) => {
  const keyHash = sha256Hex(key);
  let matched = false;
  for (const secret of app.secretKeys) {
    if (secret.startsWith("sha256:")) {
      if (safeEqual(secret.slice("sha256:".length), keyHash)) matched = true;
    } else if (safeEqual(secret, key)) {
      matched = true;
    }
  }
  return matched;
};

/**
 * Resolves the app authorized to make this request via the `x-app-key` header.
 * A public `clientId` is only trusted alongside a known `Origin` (browser flow);
 * a secret key is trusted on its own (server-to-server flow).
 *
 * NOTE: this is multi-tenant *routing* plus a CORS/allowlist gate, NOT app
 * authentication. `clientId` is public and the `Origin` check only constrains
 * real browsers; a non-browser caller can present a known clientId + Origin. The
 * actual security boundary is Better Auth (credentials, sessions, CSRF) — the
 * per-app auth endpoints are meant to be publicly reachable.
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
  const match = new URL(request.url).pathname.match(
    /^\/api\/auth\/sso\/saml2\/(?:callback|sp\/(?:acs|slo)|logout)\/([^/]+)\/?$/,
  );
  const providerId = match?.[1];
  if (!providerId) return Option.none();
  return Arr.findFirst(config.apps, (app) =>
    app.samlProviders.some((provider) => provider.providerId === providerId),
  );
};

/** Routes the public SAML SP metadata endpoint by its required providerId query. */
export const appForSamlMetadata = (
  request: Request,
  config: AppsConfig,
): Option.Option<App> => {
  const url = new URL(request.url);
  if (
    request.method !== "GET" ||
    url.pathname !== "/api/auth/sso/saml2/sp/metadata"
  ) {
    return Option.none();
  }
  const providerId = url.searchParams.get("providerId");
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
  Effect.gen(function* () {
    const origin = yield* Option.match(safeOrigin(value), {
      onNone: () => fail(`${field} must be a valid URL`),
      onSome: Effect.succeed,
    });
    const protocol = new URL(value).protocol;
    if (protocol !== "http:" && protocol !== "https:") {
      yield* fail(`${field} must use http or https`);
    }
    return origin;
  });

const normalizeApp = (app: RawApp, index: number) =>
  Effect.gen(function* () {
    const id = app.id.trim();
    if (!id) yield* fail(`apps[${index}].id is required`);
    if (!appIdPattern.test(id)) {
      yield* fail(
        `apps[${index}].id must be 1-48 lowercase letters, digits, or hyphens`,
      );
    }

    const url = app.url.trim();
    if (!url) yield* fail(`apps[${index}].url is required`);

    const urlOrigin = yield* originEffect(url, `apps[${index}].url`);
    const extraOrigins = yield* Effect.forEach(app.origins ?? [], (origin) =>
      originEffect(origin, `apps[${index}].origins`),
    );

    const name = app.name?.trim();
    const clientId = app.clientId?.trim();
    const emailFrom = app.emailFrom?.trim();
    if (emailFrom && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailFrom)) {
      yield* fail(`apps[${index}].emailFrom must be a valid email address`);
    }
    const cookieDomain = app.cookieDomain?.trim();
    if (
      cookieDomain &&
      !/^\.?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/i.test(cookieDomain)
    ) {
      yield* fail(`apps[${index}].cookieDomain is not a valid domain`);
    }
    const secretKeys = (app.secretKeys ?? [])
      .map((key) => key.trim())
      .filter(Boolean);
    for (const key of secretKeys) {
      if (key.startsWith("sha256:") && !/^sha256:[a-f0-9]{64}$/.test(key)) {
        yield* fail(
          `apps[${index}].secretKeys contains an invalid sha256 digest`,
        );
      }
    }

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
          if (!providerIdPattern.test(providerId)) {
            yield* fail(
              `apps[${index}].oidcProviders[${i}].providerId must be 1-64 lowercase letters, digits, or hyphens`,
            );
          }
          if (reservedProviderIds.has(providerId)) {
            yield* fail(
              `apps[${index}].oidcProviders[${i}].providerId is reserved`,
            );
          }
          const discoveryUrl = provider.discoveryUrl.trim();
          if (!isSecureProviderUrl(discoveryUrl)) {
            yield* fail(
              `apps[${index}].oidcProviders[${i}].discoveryUrl must use https (or loopback http)`,
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
          if (!providerIdPattern.test(providerId)) {
            yield* fail(
              `apps[${index}].samlProviders[${i}].providerId must be 1-64 lowercase letters, digits, or hyphens`,
            );
          }
          if (reservedProviderIds.has(providerId)) {
            yield* fail(
              `apps[${index}].samlProviders[${i}].providerId is reserved`,
            );
          }
          const domain = provider.domain.trim();
          if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/i.test(domain)) {
            yield* fail(
              `apps[${index}].samlProviders[${i}].domain must be a valid email domain`,
            );
          }
          const issuer = provider.issuer.trim();
          if (!issuer) {
            yield* fail(`apps[${index}].samlProviders[${i}].issuer is required`);
          }
          const entryPoint = provider.entryPoint.trim();
          if (!isSecureProviderUrl(entryPoint)) {
            yield* fail(
              `apps[${index}].samlProviders[${i}].entryPoint must use https (or loopback http)`,
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
          } satisfies SamlProvider;
        }),
    );
    const samlIds = samlProviders.map((provider) => provider.providerId);
    if (new Set(samlIds).size !== samlIds.length) {
      yield* fail(`apps[${index}].samlProviders has duplicate providerId`);
    }

    // Trusted-link providers must reference a provider actually configured on this
    // app (a typo here would silently trust nothing or the wrong provider).
    const configuredProviderIds = new Set<string>([
      ...socialProviders,
      ...oidcProviders.map((provider) => provider.providerId),
      ...samlProviders.map((provider) => provider.providerId),
    ]);
    const providerCount =
      socialProviders.length + oidcProviders.length + samlProviders.length;
    if (configuredProviderIds.size !== providerCount) {
      yield* fail(
        `apps[${index}] has a providerId collision across social, OIDC, or SAML providers`,
      );
    }
    const trustedLinkProviders = uniq(
      (app.accountLinking?.trustedProviders ?? [])
        .map((provider) => provider.trim())
        .filter(Boolean),
    );
    for (const provider of trustedLinkProviders) {
      if (!configuredProviderIds.has(provider)) {
        yield* fail(
          `apps[${index}].accountLinking.trustedProviders references "${provider}", ` +
            `which is not a configured social/oidc/saml provider on this app`,
        );
      }
    }

    return {
      id,
      ...(name ? { name } : {}),
      url,
      origins: uniq([urlOrigin, ...extraOrigins]),
      ...(clientId ? { clientId } : {}),
      ...(emailFrom ? { emailFrom } : {}),
      ...(cookieDomain ? { cookieDomain } : {}),
      secretKeys,
      schema,
      socialProviders,
      oidcProviders,
      samlProviders,
      trustedLinkProviders,
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

    const schemas = apps.map((app) => app.schema);
    if (new Set(schemas).size !== schemas.length) {
      yield* fail("apps.yaml contains app ids that resolve to the same schema");
    }

    const routeKeys = new Set<string>();
    const secretOwners = new Map<string, string>();
    const publicKeyHashes = new Set(
      apps.flatMap((app) => (app.clientId ? [sha256Hex(app.clientId)] : [])),
    );
    for (const app of apps) {
      if (app.clientId) {
        for (const origin of app.origins) {
          const routeKey = `${origin}\0${app.clientId}`;
          if (routeKeys.has(routeKey)) {
            yield* fail(
              `clientId "${app.clientId}" is ambiguous for origin "${origin}"`,
            );
          }
          routeKeys.add(routeKey);
        }
      }
      for (const secret of app.secretKeys) {
        const digest = secret.startsWith("sha256:")
          ? secret.slice("sha256:".length)
          : sha256Hex(secret);
        const owner = secretOwners.get(digest);
        if (owner) {
          yield* fail(`apps "${owner}" and "${app.id}" share a secret key`);
        }
        if (publicKeyHashes.has(digest)) {
          yield* fail(`app "${app.id}" has a secret key that is also a clientId`);
        }
        secretOwners.set(digest, app.id);
      }
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
