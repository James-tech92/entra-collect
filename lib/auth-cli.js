/**
 * Probe local Graph CLI / Azure CLI / Microsoft Graph PowerShell for a bearer token.
 * Fail-fast: hard timeouts + SIGKILL so --auth auto never stalls before browser.
 *
 * Order: az → Mg PowerShell → mgc
 */
const { spawn } = require("child_process");
const { decodeJwt, hasPolicyRead, scoreToken } = require("./tokens");
const { fetchJsonResilient } = require("./net");

const isWin = process.platform === "win32";

/** Default per-command budget (ms). Keep low so browser fallback is snappy. */
const DEFAULT_TIMEOUT_MS = 12000;

function run(cmd, args, opts = {}) {
  const timeout = opts.timeout != null ? opts.timeout : DEFAULT_TIMEOUT_MS;
  const useShell = opts.shell != null ? opts.shell : isWin;

  return new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    let child;
    try {
      child = spawn(cmd, args, {
        shell: useShell,
        windowsHide: true,
        env: { ...process.env, ...(opts.env || {}) },
        // Own process group on Unix so we can kill az→python children
        detached: !isWin && !useShell,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (e) {
      finish({
        ok: false,
        status: null,
        stdout: "",
        stderr: "",
        error: String(e.message || e),
        timedOut: false,
      });
      return;
    }

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d.toString();
    });
    child.stderr.on("data", (d) => {
      stderr += d.toString();
    });

    const killTree = () => {
      try {
        if (!isWin && child.pid) {
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            child.kill("SIGKILL");
          }
        } else if (child.pid) {
          child.kill("SIGKILL");
        }
      } catch {
        /* ignore */
      }
    };

    const timer = setTimeout(() => {
      killTree();
      finish({
        ok: false,
        status: null,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        error: `timed out after ${timeout}ms`,
        timedOut: true,
      });
    }, timeout);

    child.on("error", (e) => {
      finish({
        ok: false,
        status: null,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        error: String(e.message || e),
        timedOut: false,
      });
    });

    child.on("close", (status) => {
      finish({
        ok: status === 0,
        status,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        error: status === 0 ? null : stderr.trim().slice(0, 240) || `exit ${status}`,
        timedOut: false,
      });
    });
  });
}

async function which(bin) {
  const probe = isWin ? "where" : "which";
  const r = await run(probe, [bin], { timeout: 4000, shell: isWin });
  if (!r.ok || !r.stdout) return null;
  return r.stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)[0] || null;
}

function looksLikeJwt(s) {
  return typeof s === "string" && s.split(".").length === 3 && s.length > 40;
}

function summarizeToken(token, source) {
  const payload = decodeJwt(token);
  if (!payload) return { ok: false, source, error: "invalid JWT" };
  return {
    ok: true,
    source,
    token,
    payload,
    score: scoreToken(payload),
    policyRead: hasPolicyRead(payload),
    upn:
      payload.upn ||
      payload.unique_name ||
      payload.preferred_username ||
      null,
    tid: payload.tid || null,
    scp: payload.scp || null,
    exp: payload.exp || null,
  };
}

async function tryAzureCli() {
  console.log("  · az: probing (max ~12s)…");
  if (!(await which("az"))) {
    return { ok: false, source: "az", error: "az not found on PATH" };
  }

  // Quick session check — fail fast if az is broken / locked
  const show = await run("az", ["account", "show", "-o", "none"], {
    timeout: 8000,
  });
  if (!show.ok) {
    return {
      ok: false,
      source: "az",
      error:
        show.timedOut
          ? "az account show timed out (session lock?) — use --auth browser or az login"
          : show.stderr.slice(0, 200) ||
            show.error ||
            "az not logged in (run: az login)",
    };
  }

  let r = await run(
    "az",
    [
      "account",
      "get-access-token",
      "--resource-type",
      "ms-graph",
      "--query",
      "accessToken",
      "-o",
      "tsv",
    ],
    { timeout: 12000 }
  );
  if (!r.ok || !looksLikeJwt(r.stdout)) {
    r = await run(
      "az",
      [
        "account",
        "get-access-token",
        "--resource",
        "https://graph.microsoft.com",
        "--query",
        "accessToken",
        "-o",
        "tsv",
      ],
      { timeout: 12000 }
    );
  }
  if (!r.ok || !looksLikeJwt(r.stdout)) {
    return {
      ok: false,
      source: "az",
      error:
        r.timedOut
          ? "az get-access-token timed out"
          : r.stderr.slice(0, 240) ||
            r.error ||
            "az returned no Graph access token (run: az login)",
    };
  }
  return summarizeToken(r.stdout, "az");
}

async function tryMgGraphPowerShell() {
  console.log("  · mg-powershell: probing (max ~10s)…");
  const shell =
    (await which("pwsh")) ||
    (await which("powershell")) ||
    (await which("powershell.exe"));
  if (!shell) {
    return {
      ok: false,
      source: "mg-powershell",
      error: "pwsh/powershell not found",
    };
  }

  // Microsoft.Graph.Authentication exposes no Get-MgAccessToken cmdlet, so the
  // token is read back off the Authorization header of a real request. That
  // works across module versions; the GraphSession fallback covers older ones.
  const ps = `
$ErrorActionPreference = 'Stop'
try { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop } catch { exit 2 }
try {
  $ctx = Get-MgContext
  if (-not $ctx) { exit 3 }
} catch { exit 3 }

function Get-TokenFromRequest {
  try {
    $r = Invoke-MgGraphRequest -Method GET \`
      -Uri 'https://graph.microsoft.com/v1.0/$metadata#organization' \`
      -OutputType HttpResponseMessage -ErrorAction Stop
    $p = $r.RequestMessage.Headers.Authorization.Parameter
    if ($p -and $p.Length -gt 40) { return [string]$p }
  } catch {}
  return $null
}

function Get-TokenFromSession {
  try {
    $s = [Microsoft.Graph.PowerShell.Authentication.GraphSession]::Instance
    foreach ($prop in 'AuthContext','InMemoryTokenCache') {
      $v = $s.$prop
      if (-not $v) { continue }
      foreach ($name in 'AccessToken','Token') {
        $t = $v.$name
        if ($t -and ([string]$t).Length -gt 40) { return [string]$t }
      }
    }
  } catch {}
  return $null
}

$tok = Get-TokenFromRequest
if (-not $tok) { $tok = Get-TokenFromSession }
if ($tok) { Write-Output $tok; exit 0 }
exit 4
`.trim();

  const r = await run(shell, ["-NoProfile", "-NonInteractive", "-Command", ps], {
    timeout: 25000,
    shell: false,
  });
  const jwt = r.stdout.split(/\r?\n/).filter(looksLikeJwt).pop();
  if (!jwt) {
    return {
      ok: false,
      source: "mg-powershell",
      error: r.timedOut
        ? "PowerShell probe timed out"
        : r.status === 2
          ? "Microsoft.Graph.Authentication module not installed (Install-Module Microsoft.Graph.Authentication)"
          : r.status === 3
            ? "No Connect-MgGraph session (run Connect-MgGraph -Scopes … first)"
            : r.stderr.slice(0, 240) ||
              r.error ||
              "Could not extract Graph token from the Connect-MgGraph session",
    };
  }
  return summarizeToken(jwt, "mg-powershell");
}

/**
 * Microsoft Graph CLI (`mgc`) has no command that prints an access token, so it
 * can only be reported — never used as a token source. Detecting it is still
 * worth it: it tells the operator their session exists but is unusable here.
 */
async function tryMgc() {
  console.log("  · mgc: probing…");
  if (!(await which("mgc"))) {
    return { ok: false, source: "mgc", error: "mgc not found on PATH" };
  }
  const r = await run("mgc", ["login", "status"], { timeout: 8000 });
  const loggedIn = r.ok && !/not logged in|no.*session/i.test(r.stdout + r.stderr);
  return {
    ok: false,
    source: "mgc",
    error: loggedIn
      ? "mgc session found but the Graph CLI cannot export a bearer token — use Connect-MgGraph or az instead"
      : r.timedOut
        ? "mgc timed out"
        : r.stderr.slice(0, 200) || "mgc not logged in",
  };
}

/**
 * App-only token via client credentials.
 *
 * This is the deployment mode that makes the collector reproducible outside a
 * workstation: scopes are whatever the app registration was granted, so
 * ThreatHunting.Read.All and friends are actually available, unlike the fixed
 * scope set an `az` user token carries.
 */
async function appOnlyToken({ tenantId, clientId, clientSecret, certPath, certKeyPath }) {
  if (!tenantId || !clientId) {
    return { ok: false, source: "app", error: "tenant id and client id required" };
  }

  const body = new URLSearchParams({
    client_id: clientId,
    scope: "https://graph.microsoft.com/.default",
    grant_type: "client_credentials",
  });

  if (clientSecret) {
    body.set("client_secret", clientSecret);
  } else if (certPath && certKeyPath) {
    const assertion = buildClientAssertion({
      tenantId,
      clientId,
      certPath,
      certKeyPath,
    });
    body.set(
      "client_assertion_type",
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    );
    body.set("client_assertion", assertion);
  } else {
    return { ok: false, source: "app", error: "client secret or certificate required" };
  }

  const url = `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`;
  let json;
  try {
    json = await fetchJsonResilient(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
      timeoutMs: 30000,
    });
  } catch (e) {
    return {
      ok: false,
      source: "app",
      error: String(e.message || e).slice(0, 300),
    };
  }

  if (!json || !json.access_token) {
    return { ok: false, source: "app", error: "no access_token in response" };
  }
  return summarizeToken(json.access_token, "app");
}

/** RS256 JWT signed with the app's private key, per the AAD certificate flow. */
function buildClientAssertion({ tenantId, clientId, certPath, certKeyPath }) {
  const fs = require("fs");
  const crypto = require("crypto");

  const certPem = fs.readFileSync(certPath, "utf8");
  const keyPem = fs.readFileSync(certKeyPath, "utf8");
  const der = Buffer.from(
    certPem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""),
    "base64"
  );
  const thumbprint = crypto.createHash("sha1").update(der).digest("base64url");

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", x5t: thumbprint };
  const payload = {
    aud: `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    iss: clientId,
    sub: clientId,
    jti: crypto.randomUUID(),
    nbf: now - 60,
    exp: now + 600,
  };
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const signingInput = `${b64(header)}.${b64(payload)}`;
  const signature = crypto
    .createSign("RSA-SHA256")
    .update(signingInput)
    .sign(keyPem)
    .toString("base64url");
  return `${signingInput}.${signature}`;
}

async function probeCliGraphAuth() {
  const attempts = [];
  const providers = [tryAzureCli, tryMgGraphPowerShell, tryMgc];
  let best = null;

  for (const fn of providers) {
    let res;
    try {
      res = await fn();
    } catch (e) {
      res = {
        ok: false,
        source: fn.name || "cli",
        error: String(e.message || e),
      };
    }
    attempts.push({
      source: res.source,
      ok: !!res.ok,
      error: res.error || null,
      policyRead: res.policyRead || false,
      score: res.score || 0,
      upn: res.upn || null,
    });
    if (res.ok && (!best || res.score > best.score)) {
      best = res;
    }
    // Early exit on first strong Policy.Read token
    if (res.ok && res.policyRead) break;
  }

  return {
    ok: !!best,
    best,
    attempts,
    platform: process.platform,
  };
}

async function enrichPoolFromCli(pool) {
  console.log(
    "▶ Probing Graph CLI / Azure CLI / Mg PowerShell (fail-fast, then browser if needed)…"
  );
  const probe = await probeCliGraphAuth();
  for (const a of probe.attempts) {
    if (a.ok) {
      console.log(
        `  ✓ ${a.source}: token ok (score=${a.score} policyRead=${a.policyRead}` +
          (a.upn ? ` upn=${a.upn}` : "") +
          ")"
      );
    } else {
      const err = (a.error || "failed").replace(/\s+/g, " ").slice(0, 120);
      console.log(`  · ${a.source}: ${err}`);
    }
  }
  if (probe.best && probe.best.token) {
    pool.add(probe.best.token, { source: probe.best.source });
  } else {
    console.log("  → No CLI token — will use browser fallback.\n");
  }
  return probe;
}

/**
 * Required-scope matrix and coverage evaluation live in lib/scopes.js — it
 * has no Node-only dependency, so the browser web app (web/src) can bundle
 * it directly. Re-exported here so every existing `require("./auth-cli")`
 * call site keeps working unchanged.
 */
const { REQUIRED_SCOPES, evaluatePermissions, printPermissionMatrix } = require("./scopes");

/**
 * Interactive Azure CLI device-code login.
 * Open microsoft.com/devicelogin ON THE PHONE where the Authenticator passkey lives.
 */
async function azLoginDeviceCode(opts = {}) {
  const timeoutMs = opts.timeoutMs != null ? opts.timeoutMs : 15 * 60 * 1000;
  if (!(await which("az"))) {
    return { ok: false, error: "az not found on PATH — brew install azure-cli" };
  }

  console.log("\n╔══════════════════════════════════════════════════════════════╗");
  console.log("║  DEVICE CODE — complete login ON YOUR PHONE                  ║");
  console.log("║                                                              ║");
  console.log("║  1. az will show a code + https://microsoft.com/devicelogin  ║");
  console.log("║  2. Open that URL in Safari/Chrome ON THE PHONE              ║");
  console.log("║  3. Sign in with Authenticator passkey (native on phone)     ║");
  console.log("║  Do NOT use the Mac security-key dialog.                     ║");
  console.log("╚══════════════════════════════════════════════════════════════╝\n");

  const loginArgs = ["login", "--use-device-code"];
  if (opts.tenant) {
    loginArgs.push("--tenant", String(opts.tenant));
  }

  const login = await new Promise((resolve) => {
    let settled = false;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };

    const child = spawn("az", loginArgs, {
      shell: isWin,
      windowsHide: false,
      stdio: "inherit",
      env: process.env,
    });

    const timer = setTimeout(() => {
      try {
        child.kill("SIGTERM");
      } catch {
        /* ignore */
      }
      finish({ ok: false, error: `az login timed out after ${timeoutMs}ms` });
    }, timeoutMs);

    child.on("error", (e) => {
      finish({ ok: false, error: String(e.message || e) });
    });
    child.on("close", (status) => {
      finish(
        status === 0
          ? { ok: true }
          : { ok: false, error: `az login exited ${status}` }
      );
    });
  });

  if (!login.ok) return login;

  const token = await tryAzureCli();
  if (!token.ok) {
    return {
      ok: false,
      error:
        token.error ||
        "Logged in but could not get Graph token (az account get-access-token)",
    };
  }
  return { ok: true, token };
}

module.exports = {
  probeCliGraphAuth,
  enrichPoolFromCli,
  azLoginDeviceCode,
  appOnlyToken,
  tryAzureCli,
  tryMgGraphPowerShell,
  tryMgc,
  evaluatePermissions,
  printPermissionMatrix,
  REQUIRED_SCOPES,
  which,
  isWin,
};
