#!/usr/bin/env node
/**
 * Automates the Azure AD app registration the hosted web app needs
 * (docs/WEBAPP.md's manual "five-minute setup", scripted end to end):
 * logs you into the az CLI if needed, creates a multi-tenant, public-client
 * SPA-platform app registration with the delegated Graph scopes from
 * lib/scopes.js, writes the resulting client id into web/src/config.js,
 * and attempts admin consent so the app is usable immediately.
 *
 * Every step needs someone who can create app registrations and consent to
 * the scopes below — Application Administrator, Cloud Application
 * Administrator, or Global Administrator. Global Reader / Security Reader
 * (what the app itself is used with afterwards, on whatever tenant it gets
 * pointed at later) is NOT enough for this one-time setup step.
 *
 * Permission IDs are resolved by name from the tenant's own Microsoft
 * Graph service principal rather than hardcoded — Graph permission GUIDs
 * are stable, but looking them up live means a typo or a stale ID here
 * can never silently request the wrong permission.
 *
 * Usage:
 *   node scripts/register-web-app.js <redirect-uri> [--name "Entra Collect Web"]
 *
 * Examples:
 *   node scripts/register-web-app.js http://127.0.0.1:8080/
 *   node scripts/register-web-app.js https://you.github.io/entra-collect/webapp/
 */
const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const { REQUIRED_SCOPES } = require("../lib/scopes");

const GRAPH_RESOURCE_APP_ID = "00000003-0000-0000-c000-000000000000";
const isWin = process.platform === "win32";

function az(args) {
  return execFileSync("az", args, {
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
    shell: isWin, // az on Windows is az.cmd — needs a shell to resolve
  });
}

function azRestGet(url) {
  return JSON.parse(az(["rest", "--method", "GET", "--url", url]));
}

function azRestPost(url, body) {
  return JSON.parse(
    az([
      "rest",
      "--method",
      "POST",
      "--url",
      url,
      "--body",
      JSON.stringify(body),
      "--headers",
      "Content-Type=application/json",
    ])
  );
}

function argValue(args, flag, fallback) {
  const i = args.indexOf(flag);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
}

function isLoggedIn() {
  try {
    az(["account", "show", "-o", "none"]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Runs `az login` interactively (stdio inherited: the browser/device-code
 * prompt shows in this same terminal) when no session exists yet, instead
 * of stopping and telling the operator to run it separately first.
 */
function ensureLoggedIn() {
  if (isLoggedIn()) {
    console.log("✓ Already logged in to Azure CLI.");
    return;
  }
  console.log("Not logged in to Azure CLI — running az login…\n");
  try {
    execFileSync("az", ["login"], { stdio: "inherit", shell: isWin });
  } catch (e) {
    console.error(`\n❌ az login failed or was cancelled (${String(e.message || e).slice(0, 200)}).\n`);
    process.exit(1);
  }
  if (!isLoggedIn()) {
    console.error("\n❌ Still not logged in after az login — aborting.\n");
    process.exit(1);
  }
  console.log("✓ Logged in.");
}

/** Synchronous sleep — the rest of this script is execFileSync-based, not
 * worth converting to async/await for one retry loop. */
function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Consent right after creation can 404/fail for up to ~a minute while the
 * new app object replicates through Azure AD — retried instead of treated
 * as a hard failure on the first try.
 */
function tryAdminConsent(appId, { retries = 4, delayMs = 15000 } = {}) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      az(["ad", "app", "permission", "admin-consent", "--id", appId]);
      return true;
    } catch (e) {
      if (attempt === retries) {
        console.warn(`  ⚠ admin consent did not succeed (${String(e.message || e).slice(0, 200)}).`);
        return false;
      }
      console.log(
        `  · not ready yet (attempt ${attempt}/${retries}) — likely Azure AD replication lag, retrying in ${delayMs / 1000}s…`
      );
      sleepSync(delayMs);
    }
  }
  return false;
}

/**
 * Resolves REQUIRED_SCOPES' scope names to Graph delegated-permission IDs
 * against the tenant's own servicePrincipal metadata — never hardcoded, so
 * a stale/wrong GUID can never silently request the wrong permission.
 * @param {string[]} scopeNames
 * @param {{value: string, id: string}[]} oauth2PermissionScopes
 */
function resolveScopeIds(scopeNames, oauth2PermissionScopes) {
  const byName = new Map(oauth2PermissionScopes.map((s) => [s.value, s.id]));
  const resourceAccess = [];
  const unresolved = [];
  for (const name of scopeNames) {
    const id = byName.get(name);
    if (id) resourceAccess.push({ id, type: "Scope" });
    else unresolved.push(name);
  }
  return { resourceAccess, unresolved };
}

function buildAppRegistrationBody({ appName, redirectUri, resourceAccess }) {
  return {
    displayName: appName,
    signInAudience: "AzureADMultipleOrgs",
    spa: { redirectUris: [redirectUri] },
    requiredResourceAccess: [{ resourceAppId: GRAPH_RESOURCE_APP_ID, resourceAccess }],
  };
}

function main() {
  const args = process.argv.slice(2);
  const redirectUri = args.find((a) => !a.startsWith("--") && args[args.indexOf(a) - 1] !== "--name");
  const appName = argValue(args, "--name", "Entra Collect Web");

  const wantsHelp = args.includes("--help") || args.includes("-h");
  if (!redirectUri || wantsHelp) {
    console.log(
      "Usage: node scripts/register-web-app.js <redirect-uri> [--name \"...\"]\n" +
        "Example: node scripts/register-web-app.js http://127.0.0.1:8080/"
    );
    process.exit(wantsHelp ? 0 : 1);
  }

  ensureLoggedIn();

  console.log("Resolving Microsoft Graph delegated permission IDs…");
  const uniqueScopeNames = [...new Set(REQUIRED_SCOPES.flatMap((r) => r.any))];
  let sp;
  try {
    sp = azRestGet(
      `https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '${GRAPH_RESOURCE_APP_ID}'&$select=id,oauth2PermissionScopes`
    );
  } catch (e) {
    console.error(
      `\n❌ Could not query Microsoft Graph (${String(e.message || e).slice(0, 300)}).\n` +
        "   Your account needs at least read access to the directory.\n"
    );
    process.exit(1);
  }
  const graphSp = sp.value && sp.value[0];
  if (!graphSp) {
    console.error("\n❌ Could not find the Microsoft Graph service principal in this tenant.\n");
    process.exit(1);
  }
  const { resourceAccess, unresolved } = resolveScopeIds(
    uniqueScopeNames,
    graphSp.oauth2PermissionScopes
  );
  if (unresolved.length) {
    console.warn(
      `  ⚠ could not resolve these scope names in this tenant's Graph metadata (skipped): ${unresolved.join(", ")}`
    );
  }
  console.log(`  ✓ resolved ${resourceAccess.length}/${uniqueScopeNames.length} scopes`);

  console.log(`\nCreating app registration "${appName}"…`);
  let app;
  try {
    app = azRestPost(
      "https://graph.microsoft.com/v1.0/applications",
      buildAppRegistrationBody({ appName, redirectUri, resourceAccess })
    );
  } catch (e) {
    console.error(
      `\n❌ App creation failed (${String(e.message || e).slice(0, 400)}).\n` +
        "   Most likely cause: your account lacks rights to create app registrations\n" +
        "   in this tenant (needs Application Administrator, Cloud Application\n" +
        "   Administrator, or Global Administrator — or your tenant restricts app\n" +
        "   registration to admins only).\n"
    );
    process.exit(1);
  }

  console.log("\n✓ App registered.");
  console.log(`  Application (client) ID: ${app.appId}`);
  console.log(`  Object ID:               ${app.id}`);
  console.log(`  Redirect URI:            ${redirectUri}`);

  const configPath = path.join(__dirname, "..", "web", "src", "config.js");
  try {
    let configSrc = fs.readFileSync(configPath, "utf8");
    const updated = configSrc.replace(
      /export const CLIENT_ID = ".*?";/,
      `export const CLIENT_ID = "${app.appId}";`
    );
    if (updated === configSrc) {
      console.warn(`\n  ⚠ web/src/config.js: CLIENT_ID line not found/updated — set it manually.`);
    } else {
      fs.writeFileSync(configPath, updated, "utf8");
      console.log(`  ✓ web/src/config.js updated.`);
    }
  } catch (e) {
    console.warn(`\n  ⚠ could not update web/src/config.js (${String(e.message || e).slice(0, 160)}) — set CLIENT_ID manually.`);
  }

  console.log("\nGranting admin consent for the requested scopes on this tenant…");
  const consented = tryAdminConsent(app.appId);
  const consentUrl = `https://login.microsoftonline.com/organizations/adminconsent?client_id=${app.appId}&redirect_uri=${encodeURIComponent(redirectUri)}`;

  if (consented) {
    console.log("  ✓ Consent granted — the app is usable immediately, by any Reader-level account on this tenant.");
  } else {
    console.log(
      "  Consent was not granted automatically. Either wait a minute for Azure AD\n" +
        `  replication and re-run \`az ad app permission admin-consent --id ${app.appId}\`,\n` +
        "  or open this in a browser as a Global/Application Administrator:\n" +
        `  ${consentUrl}`
    );
  }

  console.log("\nNext: npm run build:web");
}

if (require.main === module) {
  main();
}

module.exports = { resolveScopeIds, buildAppRegistrationBody };
