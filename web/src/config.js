/**
 * Deployment config for the hosted Entra Collect web app.
 *
 * IMPORTANT — this is NOT the same trust model as `--auth msal` in the CLI.
 * The CLI reuses Azure CLI's own first-party public client id because a
 * *native/desktop* app gets a loopback redirect URI allowance from Azure AD.
 * A browser SPA does not: Azure AD only accepts a redirect URI that is
 * exactly pre-registered under the app's "Single-page application"
 * platform. That means this page needs its OWN app registration — there is
 * no way around that for a hosted SPA. See docs/WEBAPP.md for the exact
 * steps (five minutes, no code).
 */

/** Replace with the Application (client) ID from your own app registration. */
export const CLIENT_ID = "REPLACE_WITH_YOUR_APP_REGISTRATION_CLIENT_ID";

/**
 * Multi-tenant by default so the same registration/deployment works against
 * any customer tenant once that tenant's admin has granted consent once
 * (see the "Grant admin consent" button in the app). Set this to
 * `https://login.microsoftonline.com/<your-tenant-id>` instead if this
 * deployment only ever assesses your own organization.
 */
export const AUTHORITY = "https://login.microsoftonline.com/organizations";

/**
 * Auto-detected so the same build works unmodified wherever it's hosted
 * (GitHub Pages project page, custom domain, local dev server via
 * `npx http-server docs/webapp`). Must still match a redirect URI you
 * registered on the app — see docs/WEBAPP.md.
 */
export const REDIRECT_URI = window.location.origin + window.location.pathname;
