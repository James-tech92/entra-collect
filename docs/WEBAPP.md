# Web app (hosted, browser-only)

A static, hosted page: sign in with a button, everything runs client-side.
No server, no backend — tenant data never leaves the tab, same trust model
as the CLI's local-only design.

**Phase 1 (this)**: sign-in + Graph permission coverage check — the browser
equivalent of `node collect.js --check-permissions`. No tenant data is
collected yet.

**Not yet built**: actual collection (CA policies, users, apps, ...),
correlation (`NARR.*`), and report rendering in the page. `lib/graph.js`,
`lib/net.js` and `lib/tokens.js` are already browser-portable (no Node-only
APIs) and are the base to build that on next — see "What's next" below.

**Out of scope for this app, permanently**: Defender Advanced Hunting via
the `security.microsoft.com` portal apiproxy. That path relies on an actual
logged-in portal *browser session* (cookies, XSRF token), which a hosted
SPA cannot obtain — it isn't a missing feature, it's a different trust
boundary. `lib/hunt.js`'s Graph-tier fallback (`POST
/v1.0/security/runHuntingQuery`, needs `ThreatHunting.Read.All`) still works
here once that's built out.

---

## Why this needs its own Azure AD app registration

The CLI's `--auth msal` piggybacks on Azure CLI's own public client ID,
because a **native/desktop** app gets a loopback redirect URI allowance
from Azure AD (`http://localhost:<any port>`) — see the "MSAL" section in
[ARCHITECTURE.md](ARCHITECTURE.md).

A **browser SPA does not get that allowance**. Azure AD only accepts a
redirect URI that is *exactly* pre-registered under the app's
"Single-page application" platform — no loopback exception, no wildcard.
That means whoever hosts this page needs their own app registration with
that exact hosted URL registered. There is no way around this; it's how
the SPA auth-code + PKCE flow is specified, not a limitation of this
implementation.

## Setup (five minutes)

1. **Register the app** — [entra.microsoft.com](https://entra.microsoft.com) →
   *Identity → Applications → App registrations → New registration*.
   - Name: anything, e.g. "Entra Collect Web".
   - Supported account types: **Accounts in any organizational directory**
     (multitenant) if you'll assess other tenants; single-tenant if this is
     only ever for your own org.
   - Redirect URI: platform **Single-page application (SPA)**, URI = the
     exact URL this page will be hosted at (e.g.
     `https://<you>.github.io/entra-collect/webapp/`). No client secret —
     SPAs are public clients.
2. **Add API permissions** — *API permissions → Add a permission → Microsoft
   Graph → Delegated permissions*, add every scope in
   [`lib/scopes.js`](../lib/scopes.js)'s `REQUIRED_SCOPES` (`Policy.Read.All`,
   `Directory.Read.All`, `Application.Read.All`, `AuditLog.Read.All`,
   `Reports.Read.All`, `SecurityEvents.Read.All`, `ThreatHunting.Read.All`,
   `Vulnerability.Read.All`, `DeviceManagementConfiguration.Read.All`,
   `DeviceManagementManagedDevices.Read.All`). You do **not** need to click
   "Grant admin consent" here for your own tenant — the app's "Grant admin
   consent" button (in the page) is what a target tenant's admin uses.
3. **Configure the page** — copy the *Application (client) ID* from the
   registration's Overview page into [`web/src/config.js`](../web/src/config.js)
   (`CLIENT_ID`).
4. **Build**:
   ```bash
   npm install
   npm run build:web
   ```
   Produces `docs/webapp/app.bundle.js`. Commit it — GitHub Pages serves
   `docs/` as static files, no build step runs there (see `!docs/**` in
   `.gitignore`).
5. **Host it** — this repo already serves `docs/` via GitHub Pages
   (`docs/.nojekyll`), so `docs/webapp/index.html` is live at
   `https://<you>.github.io/entra-collect/webapp/` once Pages is enabled.
   Local dev: `npx http-server docs/webapp` (or any static file server —
   avoid `file://`, MSAL's redirect handling needs a real origin).

## Using it against a target tenant

1. First visit to a new tenant: sign in. If nothing (or too little) shows
   up in the permission matrix, that tenant hasn't consented to this app
   yet — the page shows a **"Grant admin consent"** button. A Global
   Administrator / Privileged Role Administrator / Cloud Application
   Administrator on the *target* tenant clicks it once.
2. After that one-time consent, any Reader-level account on that tenant
   (Global Reader + Security Reader, same requirement as the CLI) signs in
   and gets the scopes the app was granted.

This mirrors how any multi-tenant security SaaS onboards a customer tenant
— it's the standard pattern, not a workaround.

## What's next

Roughly in priority order, each usable on its own:

1. Port `lib/graph.js` collection calls one area at a time (Conditional
   Access first — highest signal, no MDE dependency) into `web/src`,
   writing to an in-memory structure instead of CSV files.
2. Adapt `lib/analyze.js`'s correlation rules to read that in-memory
   structure instead of `fs.readFileSync`-ing CSVs — the rules themselves
   don't need to change, only where they get their input.
3. Reuse `report.js`'s `renderHtml`/dashboard template against the
   in-memory payload instead of one read from `output_*/` — the template
   already expects exactly the shape `buildReportPayload` returns.

## Local dev loop

```bash
npm run build:web -- --watch   # esbuild rebuild on save (drop --watch for a one-shot build)
npx http-server docs/webapp
```
