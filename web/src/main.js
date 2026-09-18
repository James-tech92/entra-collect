/**
 * Entry point for the hosted Entra Collect web app.
 *
 * Phase 1: auth + permission check (browser equivalent of
 * `collect.js --check-permissions`).
 * Phase 2 (this): first real collection slice — Conditional Access
 * policies, the highest-signal area with no MDE dependency. See
 * docs/WEBAPP.md for what's ported vs. still CLI-only.
 */
import { TokenPool, decodeJwt } from "../../lib/tokens.js";
import { evaluatePermissions } from "../../lib/scopes.js";
import { collectConditionalAccess } from "./collect-ca.js";
import { escapeHtml, renderTable } from "./table.js";
import {
  login,
  logout,
  getExistingAccount,
  acquireTokenSilent,
  buildAdminConsentUrl,
} from "./msal-browser-auth.js";
import { CLIENT_ID } from "./config.js";

const el = (id) => document.getElementById(id);

/** One pool for the whole page session — set once on sign-in, read by the
 * collection buttons. Never persisted (matches the CLI's memory-only
 * default; see lib/msal-auth.js for the opt-in encrypted cache there). */
let pool = null;

function setStatus(msg, tone = "muted") {
  const s = el("status");
  s.textContent = msg;
  s.className = "status " + tone;
}

function renderConfigWarning() {
  if (CLIENT_ID && !CLIENT_ID.startsWith("REPLACE_WITH_")) return;
  el("configWarning").hidden = false;
  el("btnLogin").disabled = true;
}

function renderIdentity(payload, account) {
  const upn =
    payload.upn || payload.unique_name || payload.preferred_username || account.username;
  el("identity").innerHTML =
    "<div><strong>" + escapeHtml(upn) + "</strong></div>" +
    "<div class=\"muted\">tenant " + escapeHtml(payload.tid || "?") + "</div>";
  el("identity").hidden = false;
}

function renderPermissionMatrix(payload) {
  const { rows, missing } = evaluatePermissions(payload, { hasPortalSession: false });
  const icon = { ok: "✓", portal: "◐", missing: "✗" };
  const toneClass = { ok: "ok", portal: "warn", missing: "bad" };

  el("matrixTable").innerHTML =
    "<table><thead><tr><th></th><th>Area</th><th>Detail</th></tr></thead><tbody>" +
    rows
      .map(
        (r) =>
          "<tr><td class=\"icon " + toneClass[r.status] + "\">" + icon[r.status] + "</td>" +
          "<td>" + escapeHtml(r.area) + "</td>" +
          "<td class=\"muted\">" +
          (r.status === "ok"
            ? escapeHtml(r.matched.join(", "))
            : "needs one of: " + escapeHtml(r.needed.join(" | "))) +
          "</td></tr>"
      )
      .join("") +
    "</tbody></table>";
  el("matrix").hidden = false;

  if (missing.length) {
    const tid = payload.tid || "organizations";
    el("consentBox").innerHTML =
      "<p>" + missing.length + " area(s) need admin consent on this tenant. " +
      "A Global Administrator / Privileged Role Administrator opens this link " +
      "<strong>once</strong> for the whole tenant — after that, any Reader-level " +
      "account (including this one) gets these scopes on sign-in:</p>" +
      "<a class=\"btn\" target=\"_blank\" rel=\"noopener\" href=\"" +
      escapeHtml(buildAdminConsentUrl({ tenantId: tid })) + "\">Grant admin consent ↗</a>";
    el("consentBox").hidden = false;
  } else {
    el("consentBox").hidden = true;
  }

  const caRow = rows.find((r) => r.area === "Conditional Access");
  el("btnCollectCa").hidden = caRow.status !== "ok";
}

async function handleCollectCa() {
  const btn = el("btnCollectCa");
  btn.disabled = true;
  const prevLabel = btn.textContent;
  el("caResult").hidden = false;
  el("caResult").innerHTML = '<p class="muted">Fetching Conditional Access policies…</p>';
  try {
    const result = await collectConditionalAccess(pool, {
      onProgress: (msg) => {
        el("caResult").innerHTML = '<p class="muted">' + escapeHtml(msg) + "</p>";
      },
    });
    el("caResult").innerHTML =
      "<h3 style=\"margin-top:0\">Conditional Access — " + result.total + " polic" +
      (result.total === 1 ? "y" : "ies") + "</h3>" +
      "<p class=\"muted\">" + result.enforced + " enforced · " + result.reportOnly +
      " report-only · " + result.namedLocationsCount + " named location(s)</p>" +
      '<div id="caTable"></div>';
    renderTable(
      el("caTable"),
      ["PolicyName", "IsEnforced", "GrantControls", "ClientAppTypes", "RiskFlags"],
      result.rows
    );
  } catch (e) {
    el("caResult").innerHTML =
      '<p class="status bad">Collection failed: ' +
      escapeHtml(e && e.message ? e.message : String(e)) + "</p>";
  } finally {
    btn.disabled = false;
    btn.textContent = prevLabel;
  }
}

async function handleSignedIn(account) {
  el("btnLogin").hidden = true;
  el("btnLogout").hidden = false;
  setStatus("Requesting a Graph token…");
  const result = await acquireTokenSilent(account);
  const payload = decodeJwt(result.accessToken);
  if (!payload) {
    setStatus("Signed in, but the returned token could not be decoded.", "bad");
    return;
  }

  pool = new TokenPool();
  pool.add(result.accessToken, { source: "msal-browser" });
  pool.onRefresh(async () => {
    const again = await acquireTokenSilent(account);
    return again.accessToken;
  }, "msal-browser");

  renderIdentity(payload, account);
  renderPermissionMatrix(payload);
  setStatus("Signed in.", "ok");
}

async function main() {
  renderConfigWarning();

  el("btnLogin").addEventListener("click", async () => {
    setStatus("Opening sign-in popup…");
    try {
      const result = await login();
      await handleSignedIn(result.account);
    } catch (e) {
      setStatus("Sign-in failed: " + (e && e.message ? e.message : String(e)), "bad");
    }
  });

  el("btnLogout").addEventListener("click", async () => {
    const account = await getExistingAccount();
    if (account) await logout(account);
    location.reload();
  });

  el("btnCollectCa").addEventListener("click", handleCollectCa);

  const existing = await getExistingAccount().catch(() => null);
  if (existing) {
    try {
      await handleSignedIn(existing);
      return;
    } catch {
      /* fall through to the login button */
    }
  }
  setStatus("Not signed in.");
}

main().catch((e) => {
  setStatus("Startup error: " + (e && e.message ? e.message : String(e)), "bad");
  console.error(e);
});
