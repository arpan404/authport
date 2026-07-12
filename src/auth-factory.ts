import type { BetterAuthOptions } from "better-auth";
import { bearer, genericOAuth, jwt } from "better-auth/plugins";
import type { GenericOAuthConfig } from "better-auth/plugins";
import { sso } from "@better-auth/sso";
import { Config, Effect, Option, Redacted, Scope } from "effect";
import type { App } from "./apps";
import { acquirePool, createDb } from "./db";
import type { EnvValues } from "./env";
import { InsecureConfigError, ProviderCredentialsError } from "./errors";
import { makeNotifier } from "./notifications";
import { namespaceStorage, type SecondaryStorageApi } from "./redis";

/** One statically-provisioned SSO provider entry for the `sso` plugin. */
type DefaultSsoProvider = NonNullable<
  NonNullable<Parameters<typeof sso>[0]>["defaultSSO"]
>[number];

type SocialCredentials = Record<string, { clientId: string; clientSecret: string }>;

export type BuiltAuthOptions = {
  options: BetterAuthOptions;
  checkDatabase: () => Promise<void>;
};

/** Uppercased, env-safe form of an id, e.g. "authport-web" -> "AUTHPORT_WEB". */
const envToken = (value: string) =>
  value.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");

/** Reads an optional env var, returning None if unset (never fails). */
const optionalSecret = (name: string): Effect.Effect<Option.Option<string>> =>
  Config.option(Config.redacted(name)).pipe(
    Effect.map(Option.map(Redacted.value)),
    Effect.orElseSucceed(() => Option.none<string>()),
  );

/** Reads one required env var, failing with a typed ProviderCredentialsError if absent. */
const requiredSecret = (
  appId: string,
  provider: string,
  name: string,
): Effect.Effect<string, ProviderCredentialsError> =>
  Config.option(Config.redacted(name)).pipe(
    Effect.flatMap(
      Option.match({
        onNone: () =>
          Effect.fail(new ProviderCredentialsError({ appId, provider, missing: name })),
        onSome: (redacted) => Effect.succeed(Redacted.value(redacted)),
      }),
    ),
    Effect.mapError((error) =>
      error instanceof ProviderCredentialsError
        ? error
        : new ProviderCredentialsError({ appId, provider, missing: name }),
    ),
  );

/**
 * Reads each enabled provider's credentials from env, e.g. for app "authport-web"
 * and provider "google": AUTHPORT_WEB_GOOGLE_CLIENT_ID / AUTHPORT_WEB_GOOGLE_CLIENT_SECRET.
 */
const buildSocialProviders = (
  app: App,
): Effect.Effect<SocialCredentials, ProviderCredentialsError> =>
  Effect.forEach(app.socialProviders, (provider) => {
    const base = `${envToken(app.id)}_${provider.toUpperCase()}`;
    return Effect.all({
      clientId: requiredSecret(app.id, provider, `${base}_CLIENT_ID`),
      clientSecret: requiredSecret(app.id, provider, `${base}_CLIENT_SECRET`),
    }).pipe(Effect.map((creds) => [provider, creds] as const));
  }).pipe(Effect.map((entries) => Object.fromEntries(entries)));

/**
 * Builds genericOAuth config for each enterprise OIDC provider (Okta, Azure AD,
 * Google Workspace, …). Non-secret bits (providerId, discoveryUrl, scopes) come
 * from apps.yaml; credentials from env, e.g. AUTHPORT_WEB_OIDC_OKTA_CLIENT_ID/_SECRET.
 */
const buildOidcProviders = (
  app: App,
): Effect.Effect<GenericOAuthConfig[], ProviderCredentialsError> =>
  Effect.forEach(app.oidcProviders, (provider) => {
    const base = `${envToken(app.id)}_OIDC_${envToken(provider.providerId)}`;
    return Effect.all({
      clientId: requiredSecret(app.id, provider.providerId, `${base}_CLIENT_ID`),
      clientSecret: requiredSecret(app.id, provider.providerId, `${base}_CLIENT_SECRET`),
    }).pipe(
      Effect.map(
        ({ clientId, clientSecret }) =>
          ({
            providerId: provider.providerId,
            discoveryUrl: provider.discoveryUrl,
            clientId,
            clientSecret,
            ...(provider.scopes ? { scopes: provider.scopes } : {}),
          }) satisfies GenericOAuthConfig,
      ),
    );
  });

/**
 * Builds `defaultSSO` entries for each enterprise SAML IdP. Non-secret bits
 * (issuer, entryPoint, domain, …) come from apps.yaml; the IdP signing cert and
 * optional SP private key come from env, e.g. AUTHPORT_WEB_SAML_ACME_IDP_CERT /
 * AUTHPORT_WEB_SAML_ACME_SP_PRIVATE_KEY. The ACS/callback URL is derived from the
 * auth base URL so it never has to be configured by hand.
 */
const buildSamlProviders = (
  app: App,
  authUrl: string,
): Effect.Effect<DefaultSsoProvider[], ProviderCredentialsError> =>
  Effect.forEach(app.samlProviders, (provider) => {
    const base = `${envToken(app.id)}_SAML_${envToken(provider.providerId)}`;
    return Effect.all({
      cert: requiredSecret(app.id, provider.providerId, `${base}_IDP_CERT`),
      spPrivateKey: optionalSecret(`${base}_SP_PRIVATE_KEY`),
    }).pipe(
      Effect.map(({ cert, spPrivateKey }) => {
        const spEntityId =
          `${authUrl}/api/auth/sso/saml2/sp/metadata?providerId=` +
          encodeURIComponent(provider.providerId);
        return {
          domain: provider.domain,
          providerId: provider.providerId,
          samlConfig: {
            issuer: provider.issuer,
            entryPoint: provider.entryPoint,
            cert,
            callbackUrl: `${authUrl}/api/auth/sso/saml2/sp/acs/${provider.providerId}`,
            spMetadata: { entityID: spEntityId, binding: "post" },
            // Always require the IdP's assertions to be signed, and always assert
            // an AudienceRestriction (default: our SP entityID) so an assertion
            // minted for a different SP cannot be replayed here.
            wantAssertionsSigned: true,
            audience: provider.audience ?? spEntityId,
            ...(provider.identifierFormat
              ? { identifierFormat: provider.identifierFormat }
              : {}),
            ...(Option.isSome(spPrivateKey)
              ? { privateKey: spPrivateKey.value }
              : {}),
          },
        } satisfies DefaultSsoProvider;
      }),
    );
  });

/**
 * Builds the Better Auth options for a single app. Each app gets its own Postgres
 * schema (fully isolated user pool), its own cookie prefix and its own JWKS signing
 * keys, so a session or token minted for one app is meaningless to another. The
 * pool is acquired as a scoped resource, so it is released with the caller's scope.
 */
export const buildAuthOptions = (
  app: App,
  env: EnvValues,
  storage: Option.Option<SecondaryStorageApi>,
): Effect.Effect<
  BuiltAuthOptions,
  ProviderCredentialsError | InsecureConfigError,
  Scope.Scope
> =>
  Effect.gen(function* () {
    const pool = yield* acquirePool(
      Redacted.value(env.databaseUrl),
      app.schema,
      env.databasePoolMaxPerApp,
    );
    const social = yield* buildSocialProviders(app);
    const oidc = yield* buildOidcProviders(app);
    const saml = yield* buildSamlProviders(app, env.authUrl);
    const notifier = yield* Effect.try({
      try: () => makeNotifier(app, env),
      catch: (cause) =>
        cause instanceof InsecureConfigError
          ? cause
          : new InsecureConfigError({
              message: `notification setup failed for app "${app.id}"`,
            }),
    });

    const cookieDomain = app.cookieDomain;
    if (cookieDomain) {
      const authHost = new URL(env.authUrl).hostname.toLowerCase();
      const domain = cookieDomain.replace(/^\./, "").toLowerCase();
      if (authHost !== domain && !authHost.endsWith(`.${domain}`)) {
        yield* Effect.fail(
          new InsecureConfigError({
            message: `cookieDomain "${cookieDomain}" is not a parent of the auth host for app "${app.id}"`,
          }),
        );
      }
    }
    // SameSite=None is needed for cross-origin app -> auth calls (prod default).
    const crossSite = cookieDomain !== undefined || env.isProd;
    const secondaryStorage = Option.getOrUndefined(
      Option.map(storage, (value) =>
        namespaceStorage(value, `authport:${app.schema}`),
      ),
    );
    const ipAddressHeaders = Option.getOrUndefined(env.ipAddressHeaders);

    const options = {
      appName: env.appName,
      baseURL: env.authUrl,
      basePath: "/api/auth",
      secret: Redacted.value(env.secret),
      database: { db: createDb(pool), type: "postgres" },
      trustedOrigins: app.origins,
      emailAndPassword: {
        enabled: true,
        requireEmailVerification: true,
        revokeSessionsOnPasswordReset: true,
        sendResetPassword: async ({ user, url }) => {
          notifier.link(user.email, "Reset your password", url);
        },
      },
      emailVerification: {
        sendOnSignUp: true,
        sendOnSignIn: true,
        sendVerificationEmail: async ({ user, url }) => {
          notifier.link(user.email, "Verify your email", url);
        },
      },
      user: { changeEmail: { enabled: true } },
      // Cross-provider account linking is OFF unless the app explicitly lists
      // trusted providers. When enabled, linking still requires a matching email
      // (`allowDifferentEmails: false`), so a trusted provider can only link to an
      // account with the same address — never take over an arbitrary one.
      account: {
        accountLinking:
          app.trustedLinkProviders.length > 0
            ? {
                enabled: true,
                trustedProviders: app.trustedLinkProviders,
                allowDifferentEmails: false,
              }
            : { enabled: false },
      },
      // jwt(): /api/auth/jwks + /api/auth/token for stateless, cross-domain
      //   validation by app backends. bearer(): Authorization: Bearer <token>.
      //   genericOAuth(): enterprise OIDC IdP delegation. sso(): enterprise SAML
      //   IdP delegation (both added only when configured).
      plugins: [
        jwt(),
        bearer(),
        ...(oidc.length > 0 ? [genericOAuth({ config: oidc })] : []),
        ...(saml.length > 0
          ? [
              sso({
                defaultSSO: saml,
                saml: {
                  enableInResponseToValidation: true,
                  allowIdpInitiated: false,
                  requireTimestamps: true,
                  algorithms: { onDeprecated: "reject" },
                },
              }),
            ]
          : []),
      ],
      ...(Object.keys(social).length
        ? { socialProviders: social as BetterAuthOptions["socialProviders"] }
        : {}),
      ...(secondaryStorage ? { secondaryStorage } : {}),
      rateLimit: {
        enabled: true,
        window: 60,
        max: 100,
        ...(secondaryStorage ? { storage: "secondary-storage" as const } : {}),
      },
      advanced: {
        // Namespace cookies so multiple apps on the same auth domain don't clash.
        cookiePrefix: app.schema,
        // Resolve the real client IP behind a trusted proxy so rate limits are
        // per-client instead of a single shared bucket.
        ...(ipAddressHeaders ? { ipAddress: { ipAddressHeaders } } : {}),
        // Cross-subdomain cookies are opt-in PER APP. Without it, cookies stay
        // host-only on the auth origin and never leak to sibling app subdomains.
        ...(cookieDomain !== undefined
          ? { crossSubDomainCookies: { enabled: true, domain: cookieDomain } }
          : {}),
        ...(crossSite
          ? { defaultCookieAttributes: { sameSite: "none" as const, secure: true } }
          : {}),
      },
    } satisfies BetterAuthOptions;

    return {
      options,
      checkDatabase: () => pool.query("SELECT 1").then(() => undefined),
    } satisfies BuiltAuthOptions;
  });
