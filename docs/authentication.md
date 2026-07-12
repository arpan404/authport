# Authentication methods

AuthPort enables the following Better Auth methods for every configured app. Add
the matching client plugins shown in the root README and continue sending the
app's public `clientId` as `x-app-key`.

| Method | Client call |
| --- | --- |
| Email/password | `signUp.email`, `signIn.email`, `changePassword` |
| Password reset link | `requestPasswordReset`, then `resetPassword` |
| Email verification | `sendVerificationEmail` |
| Username/password | `signUp.email({ username, ... })`, `signIn.username` |
| Passkey | `passkey.addPasskey`, `signIn.passkey` |
| Magic link | `signIn.magicLink` |
| Email OTP | `emailOtp.sendVerificationOtp`, `signIn.emailOtp` |
| Email OTP password reset | `emailOtp.requestPasswordReset`, `emailOtp.resetPassword` |
| Phone OTP | `phoneNumber.sendOtp`, `phoneNumber.verify` |
| Phone password reset | `phoneNumber.requestPasswordReset`, `phoneNumber.resetPassword` |
| TOTP 2FA | `twoFactor.enable`, `twoFactor.verifyTotp` |
| Email-code 2FA | `twoFactor.sendOtp`, `twoFactor.verifyOtp` |
| 2FA recovery | `twoFactor.verifyBackupCode` |
| Social OAuth | `signIn.social` |
| Generic OIDC | `signIn.oauth2` |
| Enterprise SSO | `signIn.sso` |

## Delivery

Development uses `NOTIFICATION_DELIVERY=console`, so links and codes appear in the
AuthPort process output. Never use console delivery in production.

Production uses Cloudflare Email Service and Twilio. Set the variables documented
in `.env.example`, configure an `emailFrom` address for every app, onboard each
sender domain in Cloudflare, and use a Twilio API key plus an approved sender.

## Passkeys

The WebAuthn RP ID and origin are derived from each app's `url`. Registration must
therefore happen on that exact app origin. Passkeys and their challenge cookies are
stored and namespaced per app.

## Migrations

After installing or upgrading AuthPort, apply the additive plugin schemas:

```sh
bun run auth:migrate
```

This updates every isolated app schema and does not drop existing tables or columns.
