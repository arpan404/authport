import { expect, test } from "bun:test";
import { Redacted } from "effect";
import { sendCloudflareEmail, sendTwilioSms } from "./notifications";

const config = {
  mode: "providers" as const,
  cloudflareAccountId: "account/id",
  cloudflareApiToken: Redacted.make("email-token"),
  twilioAccountSid: "AC123",
  twilioApiKey: "SK123",
  twilioApiSecret: Redacted.make("sms-secret"),
  twilioFrom: "+15555550100",
};

test("Cloudflare email request uses the REST field names", async () => {
  let request: Request | undefined;
  await sendCloudflareEmail(
    config,
    "auth@example.com",
    { to: "user@example.com", subject: "Verify", text: "text", html: "<p>html</p>" },
    async (input, init) => {
      request = new Request(String(input), init);
      return new Response("{}", { status: 200 });
    },
  );

  expect(request?.url).toEndWith("/accounts/account%2Fid/email/sending/send");
  expect(request?.headers.get("authorization")).toBe("Bearer email-token");
  expect(await request?.json()).toEqual({
    to: "user@example.com",
    from: { address: "auth@example.com" },
    subject: "Verify",
    text: "text",
    html: "<p>html</p>",
  });
});

test("Twilio SMS request is form encoded and authenticated", async () => {
  let request: Request | undefined;
  await sendTwilioSms(config, "+15555550101", "Code: 123456", async (input, init) => {
    request = new Request(String(input), init);
    return new Response("{}", { status: 201 });
  });

  expect(request?.headers.get("authorization")).toBe(
    `Basic ${Buffer.from("SK123:sms-secret").toString("base64")}`,
  );
  expect(await request?.text()).toBe(
    "To=%2B15555550101&From=%2B15555550100&Body=Code%3A+123456",
  );
});
