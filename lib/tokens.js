/**
 * Shared Graph / portal token pool (JWT decode + scope scoring).
 */
function decodeJwt(token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(
      Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString()
    );
  } catch {
    return null;
  }
}

function scopeSet(payload) {
  const scp = String(payload.scp || "")
    .split(/\s+/)
    .filter(Boolean);
  const roles = Array.isArray(payload.roles) ? payload.roles : [];
  return new Set([...scp, ...roles]);
}

function hasPolicyRead(payload) {
  const s = scopeSet(payload);
  return (
    s.has("Policy.Read.All") ||
    s.has("Policy.ReadWrite.All") ||
    s.has("Policy.ReadWrite.ConditionalAccess") ||
    s.has("Policy.Read.ConditionalAccess")
  );
}

function scoreToken(payload) {
  let score = 0;
  const s = scopeSet(payload);
  const aud = String(payload.aud || "");
  if (hasPolicyRead(payload)) score += 100;
  if (s.has("Policy.Read.All")) score += 20;
  if (s.has("Directory.Read.All") || s.has("Directory.ReadWrite.All")) score += 30;
  if (s.has("SecurityEvents.Read.All") || s.has("SecurityEvents.ReadWrite.All"))
    score += 20;
  if (s.has("ThreatHunting.Read.All")) score += 25;
  if (s.has("Vulnerability.Read.All")) score += 25;
  if (s.has("Application.Read.All")) score += 10;
  if (s.has("User.Read.All") || s.has("User.ReadWrite.All")) score += 5;
  if (Array.isArray(payload.wids) && payload.wids.length) score += 15;
  if (s.has("User.Read") && s.size <= 6 && !hasPolicyRead(payload)) score -= 50;
  // Portal MTP tokens (security.microsoft.com hunting UI)
  if (
    /api\.security\.microsoft\.com|api\.securitycenter\.microsoft\.com|api-[a-z]{2}\.security\.microsoft\.com/i.test(
      aud
    )
  ) {
    score += 90;
  }
  return score;
}

function isMtpAud(aud) {
  const a = String(aud || "").toLowerCase();
  return (
    a.includes("api.security.microsoft.com") ||
    a.includes("api.securitycenter.microsoft.com") ||
    /api-[a-z]{2}\.security\.microsoft\.com/.test(a)
  );
}

function describeToken(payload) {
  const scp = payload.scp || "(none)";
  const short = String(scp).length > 100 ? String(scp).slice(0, 100) + "…" : scp;
  const aud = String(payload.aud || "").slice(0, 40);
  return `score=${scoreToken(payload)} policyRead=${hasPolicyRead(payload)} aud=${aud} scp=${short}`;
}

/** Treat a token as dead slightly before `exp` so in-flight calls still land. */
const EXPIRY_SKEW_SEC = 120;

function tokenExpiresAt(payload) {
  const exp = Number(payload && payload.exp);
  return Number.isFinite(exp) ? exp : null;
}

function isTokenExpired(payload, skewSec = EXPIRY_SKEW_SEC) {
  const exp = tokenExpiresAt(payload);
  if (exp == null) return false;
  return exp - skewSec <= Math.floor(Date.now() / 1000);
}

function secondsUntilExpiry(payload) {
  const exp = tokenExpiresAt(payload);
  if (exp == null) return null;
  return exp - Math.floor(Date.now() / 1000);
}

class TokenPool {
  constructor() {
    this.byHash = new Map();
    /** Async callbacks that push fresh tokens into the pool when it runs dry. */
    this.refreshers = [];
    this.refreshing = null;
    this.lastRefreshAt = 0;
  }

  /**
   * Register a source able to mint a new token mid-run (CLI re-probe, browser
   * re-capture). Called when every pooled token has expired or returned 401.
   */
  onRefresh(fn, label) {
    if (typeof fn === "function") this.refreshers.push({ fn, label: label || "refresh" });
  }

  /**
   * Ask every registered source for a fresh token. Concurrent callers share the
   * same in-flight attempt, and attempts are throttled so a burst of 401s does
   * not trigger a burst of CLI spawns.
   */
  async refresh({ minIntervalMs = 20000 } = {}) {
    if (!this.refreshers.length) return false;
    if (this.refreshing) return this.refreshing;
    if (Date.now() - this.lastRefreshAt < minIntervalMs) return false;

    this.refreshing = (async () => {
      this.lastRefreshAt = Date.now();
      let added = false;
      for (const { fn, label } of this.refreshers) {
        try {
          const token = await fn();
          if (token && this.add(token, { source: `${label}:refresh` })) {
            console.log(`  ↻ token renewed via ${label}`);
            added = true;
          }
        } catch (e) {
          console.warn(`  ⚠ token refresh (${label}): ${String(e.message || e).slice(0, 120)}`);
        }
      }
      return added;
    })();

    try {
      return await this.refreshing;
    } finally {
      this.refreshing = null;
    }
  }

  /** Drop entries past their `exp`; returns how many were evicted. */
  pruneExpired() {
    let n = 0;
    for (const [key, entry] of this.byHash) {
      if (isTokenExpired(entry.payload)) {
        this.byHash.delete(key);
        n++;
      }
    }
    return n;
  }

  add(token, meta = {}) {
    const payload = decodeJwt(token);
    if (!payload) return null;
    const aud = String(payload.aud || "");
    const okAud =
      aud.includes("graph.microsoft.com") ||
      aud === "00000003-0000-0000-c000-000000000000" ||
      aud.includes("outlook.office365.com") ||
      aud.includes("outlook.office.com") ||
      aud.includes("manage.office.com") ||
      isMtpAud(aud);
    if (!okAud) return null;
    if (isTokenExpired(payload)) return null;
    const key = `${payload.appid || payload.azp}|${aud}|${payload.scp}|${payload.exp}|${(payload.roles || []).join(",")}`;
    if (this.byHash.has(key)) return this.byHash.get(key);
    const entry = {
      token,
      payload,
      score: scoreToken(payload),
      aud,
      source: meta.source || "unknown",
      kind: isMtpAud(aud) ? "mtp" : "graph",
    };
    this.byHash.set(key, entry);
    const src = entry.source !== "unknown" ? ` via ${entry.source}` : "";
    console.log(
      `  · captured token aud=${aud.slice(0, 50)}${src} (${describeToken(payload)})`
    );
    return entry;
  }

  list() {
    return this.listAll().filter(
      (e) =>
        String(e.aud || "").includes("graph.microsoft.com") ||
        e.aud === "00000003-0000-0000-c000-000000000000"
    );
  }

  listMtp() {
    return this.listAll().filter((e) => isMtpAud(e.aud));
  }

  /** Live tokens only — expired entries are evicted rather than re-served. */
  listAll() {
    this.pruneExpired();
    return [...this.byHash.values()].sort((a, b) => b.score - a.score);
  }

  /** Diagnostics: everything, including entries that have just expired. */
  listRaw() {
    return [...this.byHash.values()].sort((a, b) => b.score - a.score);
  }

  best() {
    return this.list()[0] || null;
  }

  bestPolicy() {
    return this.list().find((e) => hasPolicyRead(e.payload)) || null;
  }

  bestMtp() {
    return this.listMtp()[0] || null;
  }

  bestForAudience(substr) {
    return (
      this.listAll().find((e) =>
        String(e.aud || "").toLowerCase().includes(String(substr).toLowerCase())
      ) || null
    );
  }

  hasMtp() {
    return this.listMtp().length > 0;
  }
}

module.exports = {
  TokenPool,
  decodeJwt,
  scopeSet,
  hasPolicyRead,
  scoreToken,
  describeToken,
  isMtpAud,
  isTokenExpired,
  secondsUntilExpiry,
  tokenExpiresAt,
  EXPIRY_SKEW_SEC,
};
