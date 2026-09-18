/**
 * Entry point for the hosted Entra Collect web app (Phase 1: auth +
 * permission check — the browser equivalent of `collect.js --check-permissions`).
 *
 * Deliberately does not collect tenant data yet. See docs/WEBAPP.md for
 * what's built, what's next, and the app-registration prerequisite.
 */
import { decodeJwt } from "../../lib/tokens.js";
import { evaluatePermissions } from "../../lib/scopes.js";
import {
  login,
  logout,
  getExistingAccount,
  acquireTokenSilent,
  buildAdminConsentUrl,
} from "./msal-browser-auth.js";
import { CLIENT_ID } from "./config.js";

const el = (id) => document.getElementById(id);

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

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderPermissionMatrix(payload) {
  const { rows, missing } = evaluatePermissions(payload, { hasPortalSession: false });
  const icon = { ok: "✓", portal: "◐", missing: "✗" };
  const toneClass = { ok: "ok", portal: "warn", missing: "bad" };

  el("matrix").innerHTML =
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
