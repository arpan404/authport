import { authClient } from "./authClient";

const el = <T extends HTMLElement>(id: string): T => {
  const node = document.getElementById(id);
  if (!node) throw new Error(`missing #${id}`);
  return node as T;
};

const sessionOut = el<HTMLPreElement>("session");
const emailInput = el<HTMLInputElement>("email");

// Providers redirect back here after login.
const here = () => window.location.origin + window.location.pathname;

async function refresh() {
  const { data } = await authClient.getSession();
  sessionOut.textContent = data
    ? JSON.stringify(data.user, null, 2)
    : "(signed out)";
}

// Enterprise SSO by provider id (SAML provider from apps.yaml).
el("sso-provider").onclick = () =>
  authClient.signIn.sso({ providerId: "acme-okta", callbackURL: here() });

// Enterprise SSO by email — AuthPort routes to the IdP matching the email domain.
el("sso-email").onclick = () =>
  authClient.signIn.sso({ email: emailInput.value, callbackURL: here() });

// Social login (needs the provider enabled + credentials on the AuthPort side).
el("google").onclick = () =>
  authClient.signIn.social({ provider: "google", callbackURL: here() });

el("signout").onclick = async () => {
  await authClient.signOut();
  await refresh();
};

void refresh();
