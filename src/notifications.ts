import { Redacted } from "effect";
import type { App } from "./apps";
import type { EnvValues } from "./env";
import { InsecureConfigError } from "./errors";

type Fetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;
type ProviderConfig = Extract<EnvValues["notifications"], { mode: "providers" }>;

type Email = {
  to: string;
  subject: string;
  text: string;
  html: string;
};

const escapeHtml = (value: string) =>
  value.replace(/[&<>"']/g, (char) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
      char
    ] ?? char,
  );

export const sendCloudflareEmail = async (
  config: ProviderConfig,
  from: string,
  email: Email,
  fetcher: Fetch = fetch,
) => {
  const response = await fetcher(
    `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(config.cloudflareAccountId)}/email/sending/send`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${Redacted.value(config.cloudflareApiToken)}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        to: email.to,
        from: { address: from },
        subject: email.subject,
        text: email.text,
        html: email.html,
      }),
    },
  );
  if (!response.ok) throw new Error(`Cloudflare Email returned ${response.status}`);
};

export const sendTwilioSms = async (
  config: ProviderConfig,
  to: string,
  body: string,
  fetcher: Fetch = fetch,
) => {
  const credentials = `${config.twilioApiKey}:${Redacted.value(config.twilioApiSecret)}`;
  const response = await fetcher(
    `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(config.twilioAccountSid)}/Messages.json`,
    {
      method: "POST",
      headers: {
        authorization: `Basic ${Buffer.from(credentials).toString("base64")}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ To: to, From: config.twilioFrom, Body: body }),
    },
  );
  if (!response.ok) throw new Error(`Twilio returned ${response.status}`);
};

export const makeNotifier = (app: App, env: EnvValues) => {
  if (env.notifications.mode === "providers" && !app.emailFrom) {
    throw new InsecureConfigError({
      message: `apps.yaml app "${app.id}" requires emailFrom for provider delivery`,
    });
  }

  const label = app.name ?? app.id;
  const dispatch = (kind: "email" | "sms", task: Promise<void>) => {
    void task.catch(() => console.error(`[authport:${app.id}] ${kind} delivery failed`));
  };
  const email = (message: Email) => {
    if (env.notifications.mode === "console") {
      console.info(`[authport:${app.id}] ${message.subject}\n${message.text}`);
      return;
    }
    dispatch(
      "email",
      sendCloudflareEmail(env.notifications, app.emailFrom as string, message),
    );
  };
  const sms = (to: string, message: string) => {
    if (env.notifications.mode === "console") {
      console.info(`[authport:${app.id}] SMS to ${to}: ${message}`);
      return;
    }
    dispatch("sms", sendTwilioSms(env.notifications, to, message));
  };

  return {
    link(to: string, action: string, url: string) {
      const safeUrl = escapeHtml(url);
      email({
        to,
        subject: `${action} · ${label}`,
        text: `${action}: ${url}`,
        html: `<p>${escapeHtml(action)}</p><p><a href="${safeUrl}">${safeUrl}</a></p>`,
      });
    },
    emailOtp(to: string, action: string, otp: string) {
      email({
        to,
        subject: `${action} · ${label}`,
        text: `${action}: ${otp}`,
        html: `<p>${escapeHtml(action)}</p><p><strong>${escapeHtml(otp)}</strong></p>`,
      });
    },
    smsOtp(to: string, action: string, otp: string) {
      sms(to, `${label}: ${action}: ${otp}`);
    },
  };
};
