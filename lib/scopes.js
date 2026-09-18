/**
 * Required-scope matrix and coverage evaluation.
 *
 * Pure logic, no Node-only APIs (no fs/child_process/crypto) — shared as-is
 * between the Node CLI (lib/auth-cli.js re-exports this) and the browser
 * web app (web/src bundles this directly). Keep it that way: anything that
 * needs a Node builtin belongs in lib/auth-cli.js instead.
 */
const { scopeSet } = require("./tokens");

/**
 * What each collection area needs, so operators learn about a missing scope in
 * seconds rather than after a two-hour run that quietly produced empty CSVs.
 */
const REQUIRED_SCOPES = [
  {
    area: "Conditional Access",
    any: ["Policy.Read.All", "Policy.ReadWrite.ConditionalAccess", "Policy.Read.ConditionalAccess"],
    impact: "CA export, coverage checks and most attack-path checks",
  },
  {
    area: "Directory / users / devices",
    any: ["Directory.Read.All", "Directory.ReadWrite.All"],
    impact: "users, guests, devices, named locations, role assignments",
  },
  {
    area: "Applications",
    any: ["Application.Read.All", "Directory.Read.All"],
    impact: "app permissions, secret expiry, path-to-GA",
  },
  {
    area: "Sign-in / audit logs",
    any: ["AuditLog.Read.All"],
    impact: "device-code and legacy sign-ins, SPN sign-ins, risky users",
  },
  {
    area: "MFA registration report",
    any: ["Reports.Read.All", "AuditLog.Read.All"],
    impact: "MFA gaps, passkeys, weak-MFA narratives",
  },
  {
    area: "Secure Score / security posture",
    any: ["SecurityEvents.Read.All", "SecurityEvents.ReadWrite.All"],
    impact: "Secure Score and high-value control checks",
  },
  {
    area: "Defender Advanced Hunting",
    any: ["ThreatHunting.Read.All"],
    impact: "RMM, Shadow AI, GenAI, file-share and patch-lag hunts",
    portalAlternative: true,
  },
  {
    area: "Defender vulnerability data",
    any: ["Vulnerability.Read.All", "ThreatHunting.Read.All"],
    impact: "TVM / CVE exposure tables",
    portalAlternative: true,
  },
  {
    area: "Intune configuration",
    any: ["DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All"],
    impact: "Windows Update rings, compliance policies",
  },
];

/**
 * Compare granted scopes against REQUIRED_SCOPES.
 *
 * @param {object|object[]} payloads one JWT payload, or all of them. A browser
 *   session yields several complementary tokens (Entra, Intune, Defender), and
 *   the Graph client will happily use whichever one covers a given call — so
 *   judging coverage on the single highest-scored token under-reports it.
 * @param {boolean} hasPortalSession true when a browser session can cover the
 *   hunting areas that Graph scopes alone would miss
 */
function evaluatePermissions(payloads, { hasPortalSession = false } = {}) {
  const list = Array.isArray(payloads) ? payloads : [payloads];
  const granted = new Set();
  for (const p of list) {
    for (const s of scopeSet(p || {})) granted.add(s);
  }
  const rows = REQUIRED_SCOPES.map((req) => {
    const matched = req.any.filter((s) => granted.has(s));
    const covered = matched.length > 0;
    const viaPortal = !covered && req.portalAlternative && hasPortalSession;
    return {
      area: req.area,
      status: covered ? "ok" : viaPortal ? "portal" : "missing",
      matched,
      needed: req.any,
      impact: req.impact,
    };
  });
  return {
    rows,
    missing: rows.filter((r) => r.status === "missing"),
    viaPortal: rows.filter((r) => r.status === "portal"),
    grantedCount: granted.size,
  };
}

function printPermissionMatrix(payloads, opts = {}) {
  const { rows, missing, viaPortal } = evaluatePermissions(payloads, opts);
  const count = Array.isArray(payloads) ? payloads.length : 1;
  const icon = { ok: "✓", portal: "◐", missing: "✗" };
  console.log(
    `\n▶ Permission coverage for this session (${count} token${count > 1 ? "s" : ""} in pool)\n`
  );
  for (const r of rows) {
    const detail =
      r.status === "ok"
        ? r.matched.join(", ")
        : r.status === "portal"
          ? "via browser portal session"
          : `needs one of: ${r.needed.join(" | ")}`;
    console.log(`  ${icon[r.status]} ${r.area.padEnd(32)} ${detail}`);
  }
  if (missing.length) {
    console.log(`\n  ${missing.length} area(s) will be missing from the report:`);
    for (const r of missing) console.log(`    · ${r.area} → ${r.impact}`);
  }
  if (viaPortal.length) {
    console.log(
      `\n  ${viaPortal.length} area(s) rely on the browser portal session staying open for the whole run.`
    );
  }
  console.log("");
  return { rows, missing, viaPortal };
}

module.exports = { REQUIRED_SCOPES, evaluatePermissions, printPermissionMatrix };
