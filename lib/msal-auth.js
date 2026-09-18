/**
 * MSAL Node authentication — no custom app registration required.
 *
 * Uses the Azure CLI's own first-party public client ID. It is a FOCI
 * (Family of Client IDs) member: Microsoft's own multi-tenant app, already
 * consented in most tenants because `az login` / `Connect-MgGraph` already
 * run against it. Requesting `.default` here mirrors that — it returns
 * whatever Graph scopes are already granted to this app in the tenant, and
 * never triggers a new consent prompt the operator can't grant themselves.
 *
 * Interactive flow only: `acquireTokenInteractive` opens the operator's own
 * default browser and listens on a loopback redirect (authorization code +
 * PKCE, RFC 8252). Conditional Access commonly has a dedicated grant control
 * to block *device code* flow specifically — loopback interactive is treated
 * as ordinary modern auth and does not trip that control. Device code is
 * intentionally not implemented here; use `--auth device` (az) if a tenant
 * genuinely requires it.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const readline = require("readline");
const { spawn } = require("child_process");
const { PublicClientApplication, LogLevel } = require("@azure/msal-node");
const { decodeJwt, scoreToken, hasPolicyRead } = require("./tokens");
const { resolveProfileRoot } = require("./profile");

/** Azure CLI — public, multi-tenant, FOCI member. Not "our" app; Microsoft's. */
const AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";

/** `.default` = whatever's already consented for this app in this tenant. */
const DEFAULT_MSAL_SCOPES = ["https://graph.microsoft.com/.default"];

function resolveMsalCacheDir() {
  return path.join(resolveProfileRoot(), "msal");
}

function cacheFilePaths(cacheDir) {
  return {
    keyFile: path.join(cacheDir, "msal-cache.key"),
    dataFile: path.join(cacheDir, "msal-cache.enc"),
  };
}

function loadOrCreateKey(keyFile) {
  fs.mkdirSync(path.dirname(keyFile), { recursive: true });
  if (fs.existsSync(keyFile)) return fs.readFileSync(keyFile);
  const key = crypto.randomBytes(32);
  fs.writeFileSync(keyFile, key, { mode: 0o600 });
  try {
    fs.chmodSync(keyFile, 0o600);
  } catch {
    /* best-effort on platforms without POSIX perms */
  }
  return key;
}

function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]);
}

function decrypt(key, buf) {
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const enc = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}

/**
 * Local encryption at rest, not an OS credential vault (no Keychain / DPAPI /
 * Secret Service integration — those need native bindings this tool avoids).
 * It stops a token cache from sitting as plaintext in an engagement folder
 * zip or backup; it does not stop a local attacker with read access to this
 * profile directory. Same trust tier as the browser profile dir next to it.
 */
function createEncryptedCachePlugin(cacheDir) {
  const { keyFile, dataFile } = cacheFilePaths(cacheDir);
  return {
    async beforeCacheAccess(ctx) {
      if (!fs.existsSync(dataFile)) return;
      try {
        const key = loadOrCreateKey(keyFile);
        ctx.tokenCache.deserialize(decrypt(key, fs.readFileSync(dataFile)));
      } catch (e) {
        console.warn(
          `  ⚠ MSAL cache unreadable (${String(e.message || e).slice(0, 120)}) — starting fresh`
        );
      }
    },
    async afterCacheAccess(ctx) {
      if (!ctx.cacheHasChanged) return;
      try {
        const key = loadOrCreateKey(keyFile);
        fs.mkdirSync(cacheDir, { recursive: true });
        fs.writeFileSync(dataFile, encrypt(key, ctx.tokenCache.serialize()), {
          mode: 0o600,
        });
        try {
          fs.chmodSync(dataFile, 0o600);
        } catch {
          /* best-effort */
        }
      } catch (e) {
        console.warn(
          `  ⚠ could not persist MSAL cache (${String(e.message || e).slice(0, 120)})`
        );
      }
    },
  };
}

/** Wipe the persisted cache + its key. Used by `--msal-logout`. */
function clearCache(cacheDir = resolveMsalCacheDir()) {
  const { keyFile, dataFile } = cacheFilePaths(cacheDir);
  let removed = 0;
  for (const f of [dataFile, keyFile]) {
    if (fs.existsSync(f)) {
      fs.unlinkSync(f);
      removed++;
    }
  }
  return removed;
}

function openSystemBrowser(url) {
  console.log(`\n  Opening your default browser for sign-in…`);
  console.log(`  If it does not open, browse to:\n  ${url}\n`);
  return new Promise((resolve) => {
    try {
      let child;
      if (process.platform === "darwin") {
        child = spawn("open", [url], { stdio: "ignore", detached: true });
      } else if (process.platform === "win32") {
        child = spawn("cmd", ["/c", "start", '""', url], {
          stdio: "ignore",
          detached: true,
          windowsHide: true,
        });
      } else {
        child = spawn("xdg-open", [url], { stdio: "ignore", detached: true });
      }
      child.on("error", () => {
        /* URL already printed above */
      });
      child.unref();
    } catch {
      /* URL already printed above */
    }
    resolve();
  });
}

const MSAL_SUCCESS_HTML =
  "<html><body style='font-family:sans-serif;padding:2rem'>" +
  "<h2>Signed in.</h2><p>You can close this tab and go back to the terminal.</p></body></html>";
const MSAL_ERROR_HTML =
  "<html><body style='font-family:sans-serif;padding:2rem'>" +
  "<h2>Sign-in failed.</h2><p>Check the terminal for details.</p></body></html>";

function summarizeMsalResult(result, source) {
  if (!result || !result.accessToken) {
    return { ok: false, source, error: "MSAL returned no access token" };
  }
  const payload = decodeJwt(result.accessToken);
  if (!payload) return { ok: false, source, error: "MSAL returned an invalid JWT" };
  return {
    ok: true,
    source,
    token: result.accessToken,
    payload,
    account: result.account || null,
    score: scoreToken(payload),
    policyRead: hasPolicyRead(payload),
  };
}

/**
 * List cached accounts, newest activity first when MSAL exposes it
 * (`lastModificationTime` on the account entry), stable order otherwise.
 */
async function listAccounts(pca) {
  const accounts = await pca.getAllAccounts();
  return [...accounts].sort((a, b) => {
    const ta = Number(a.idTokenClaims && a.idTokenClaims.iat) || 0;
    const tb = Number(b.idTokenClaims && b.idTokenClaims.iat) || 0;
    return tb - ta;
  });
}

async function promptAccountChoice(accounts) {
  console.log("\n▶ MSAL accounts cached for this profile:\n");
  accounts.forEach((a, i) => {
    console.log(`  [${i + 1}] ${a.username}  (tenant ${a.tenantId})`);
  });
  console.log(`  [${accounts.length + 1}] Add a new account (interactive sign-in)\n`);

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) => {
    rl.question("  → choice: ", (a) => {
      rl.close();
      resolve(a.trim());
    });
  });
  const idx = Number(answer);
  if (Number.isInteger(idx) && idx >= 1 && idx <= accounts.length) {
    return { mode: "existing", account: accounts[idx - 1] };
  }
  return { mode: "new" };
}

function createMsalApp({ tenantId, persist, cacheDir = resolveMsalCacheDir() } = {}) {
  const authority = `https://login.microsoftonline.com/${tenantId || "organizations"}`;
  const config = {
    auth: { clientId: AZURE_CLI_CLIENT_ID, authority },
    system: {
      loggerOptions: {
        loggerCallback: () => {},
        logLevel: LogLevel.Error,
        piiLoggingEnabled: false,
      },
    },
  };
  if (persist) {
    config.cache = { cachePlugin: createEncryptedCachePlugin(cacheDir) };
  }
  return new PublicClientApplication(config);
}

/**
 * High-level entry point used by collect.js.
 *
 * @param {object} opts
 * @param {string|null} opts.tenantId  pin the authority when known
 * @param {boolean} opts.persist       encrypted on-disk cache (opt-in, --auth-cache)
 * @param {boolean} opts.nonInteractive  never prompt / open a browser (used for
 *   the mid-run token refresher — a silent-only failure there should not pop
 *   an unexpected browser window mid-collection)
 * @param {string|null} opts.preferredUsername  skip the picker (--msal-account)
 * @param {object|null} opts.account   reuse a specific AccountInfo (refresh path)
 * @param {string[]} opts.scopes
 */
async function acquireGraphToken(opts = {}) {
  const {
    tenantId = null,
    persist = false,
    nonInteractive = false,
    preferredUsername = null,
    account: forcedAccount = null,
    scopes = DEFAULT_MSAL_SCOPES,
  } = opts;

  let pca;
  try {
    pca = createMsalApp({ tenantId, persist });
  } catch (e) {
    return { ok: false, source: "msal", error: `could not init MSAL: ${String(e.message || e)}` };
  }

  try {
    let account = forcedAccount;

    if (!account) {
      const accounts = await listAccounts(pca);
      if (preferredUsername) {
        account =
          accounts.find(
            (a) => a.username.toLowerCase() === preferredUsername.toLowerCase()
          ) || null;
        if (!account) {
          return {
            ok: false,
            source: "msal",
            error: `no cached account matches --msal-account ${preferredUsername} (${accounts.length} cached)`,
          };
        }
      } else if (accounts.length > 0) {
        // Always offer the picker when there's a real choice to make — even
        // with a single cached account, "add a new one" must stay reachable
        // without editing flags (multi-tenant engagements, stale sessions).
        if (nonInteractive || !process.stdin.isTTY) {
          if (accounts.length === 1) {
            account = accounts[0];
          } else {
            return {
              ok: false,
              source: "msal",
              error: `${accounts.length} cached MSAL accounts and no TTY — pass --msal-account <upn>`,
            };
          }
        } else {
          const choice = await promptAccountChoice(accounts);
          account = choice.mode === "existing" ? choice.account : null;
        }
      }
    }

    if (account) {
      try {
        const silent = await pca.acquireTokenSilent({ account, scopes });
        return summarizeMsalResult(silent, "msal-cache");
      } catch (e) {
        if (nonInteractive) {
          return {
            ok: false,
            source: "msal",
            error: `silent refresh failed: ${String(e.message || e).slice(0, 200)}`,
          };
        }
        console.log(
          `  · cached MSAL account ${account.username} needs interactive re-auth (${String(e.message || e).slice(0, 120)})`
        );
      }
    }

    if (nonInteractive) {
      return { ok: false, source: "msal", error: "no usable cached account (silent-only)" };
    }

    console.log("\n▶ MSAL interactive sign-in (loopback + PKCE, Azure CLI client)…");
    const result = await pca.acquireTokenInteractive({
      scopes,
      openBrowser: openSystemBrowser,
      successTemplate: MSAL_SUCCESS_HTML,
      errorTemplate: MSAL_ERROR_HTML,
    });
    return summarizeMsalResult(result, "msal");
  } catch (e) {
    return { ok: false, source: "msal", error: String(e.message || e).slice(0, 300) };
  }
}

module.exports = {
  AZURE_CLI_CLIENT_ID,
  DEFAULT_MSAL_SCOPES,
  resolveMsalCacheDir,
  acquireGraphToken,
  clearCache,
  listAccounts,
  createMsalApp,
  // Exported for tests / advanced embedding, not part of the CLI surface.
  createEncryptedCachePlugin,
  cacheFilePaths,
};
