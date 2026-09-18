/**
 * MSAL Browser wrapper for the hosted Entra Collect web app.
 *
 * Auth-code + PKCE via a popup — no server, no redirect round-trip through
 * a backend, token never leaves the tab. `.default` on first login so we
 * never prompt for a scope the signed-in user has no right to consent to;
 * `requestAdminConsent()` is the explicit, separate path for getting the
 * full permission set actually granted once, by an admin, on the target
 * tenant (see docs/WEBAPP.md).
 */
import { createStandardPublicClientApplication, LogLevel } from "@azure/msal-browser";
import { CLIENT_ID, AUTHORITY, REDIRECT_URI } from "./config.js";

const GRAPH_DEFAULT_SCOPE = ["https://graph.microsoft.com/.default"];

let appPromise = null;

function getApp() {
  if (!appPromise) {
    appPromise = createStandardPublicClientApplication({
      auth: {
        clientId: CLIENT_ID,
        authority: AUTHORITY,
        redirectUri: REDIRECT_URI,
      },
      cache: {
        // sessionStorage, not localStorage: nothing about this session
        // outlives the tab. Consistent with the CLI's memory-only default.
        cacheLocation: "sessionStorage",
      },
      system: {
        loggerOptions: {
          loggerCallback: () => {},
          logLevel: LogLevel.Error,
          piiLoggingEnabled: false,
        },
      },
    });
  }
  return appPromise;
}

function assertConfigured() {
  if (!CLIENT_ID || CLIENT_ID.startsWith("REPLACE_WITH_")) {
    throw new Error(
      "No app registration configured. Edit web/src/config.js with your own " +
        "Application (client) ID — see docs/WEBAPP.md."
    );
  }
}

export async function getExistingAccount() {
  assertConfigured();
  const app = await getApp();
  const accounts = app.getAllAccounts();
  return accounts[0] || null;
}

export async function login() {
  assertConfigured();
  const app = await getApp();
  const result = await app.loginPopup({ scopes: GRAPH_DEFAULT_SCOPE });
  return result;
}

export async function acquireTokenSilent(account) {
  const app = await getApp();
  return app.acquireTokenSilent({ account, scopes: GRAPH_DEFAULT_SCOPE });
}

export async function logout(account) {
  const app = await getApp();
  await app.logoutPopup({ account });
}

/**
 * Builds the Microsoft admin-consent URL for this app registration.
 *
 * A Global Reader / Security Reader (the roles this tool targets) cannot
 * consent to admin-restricted Graph scopes (Policy.Read.All and friends).
 * Someone with Global Administrator / Privileged Role Administrator /
 * Cloud Application Administrator on the TARGET tenant opens this link
 * once; after that, any Reader-level account on that tenant can sign in
 * and actually get those scopes.
 */
export function buildAdminConsentUrl({ tenantId = "organizations" } = {}) {
  assertConfigured();
  const url = new URL(`https://login.microsoftonline.com/${tenantId}/adminconsent`);
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  return url.toString();
}
