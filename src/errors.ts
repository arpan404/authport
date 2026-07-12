import { Data } from "effect";

/** apps.yaml could not be read, parsed, or failed validation. */
export class AppsConfigError extends Data.TaggedError("AppsConfigError")<{
  readonly message: string;
}> {}

/** A security-relevant environment misconfiguration (e.g. non-HTTPS in production). */
export class InsecureConfigError extends Data.TaggedError("InsecureConfigError")<{
  readonly message: string;
}> {}

/** An app enables a provider (social or OIDC) but its credentials are missing from env. */
export class ProviderCredentialsError extends Data.TaggedError(
  "ProviderCredentialsError",
)<{
  readonly appId: string;
  readonly provider: string;
  readonly missing: string;
}> {
  override get message() {
    return `App "${this.appId}" enables "${this.provider}" but ${this.missing} is not set`;
  }
}

/** A schema migration failed for a specific app. */
export class MigrationError extends Data.TaggedError("MigrationError")<{
  readonly appId: string;
  readonly cause: unknown;
}> {
  override get message() {
    return `Migration failed for app "${this.appId}": ${String(this.cause)}`;
  }
}

/** The underlying Better Auth handler rejected while processing a request.
 * `cause` is retained on the object but deliberately kept OUT of `message` so it
 * is never written to logs (it can contain tokens / PII). */
export class AuthHandlerError extends Data.TaggedError("AuthHandlerError")<{
  readonly appId: string;
  readonly cause: unknown;
}> {
  override get message() {
    return `Auth handler failed for app "${this.appId}"`;
  }
}

/** No isolated auth instance is registered for a resolved app id (should not happen). */
export class UnknownAppError extends Data.TaggedError("UnknownAppError")<{
  readonly appId: string;
}> {
  override get message() {
    return `No auth instance registered for app "${this.appId}"`;
  }
}
