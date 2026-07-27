/**
 * Resilient HTTP layer shared by every Graph / portal caller.
 *
 * Collection runs last 1-3 hours on customer networks (VPN, proxy, laptop
 * sleep). Without retries a single blip permanently loses an artifact, so every
 * request here is bounded by a timeout and retried on conditions that are
 * plausibly transient.
 */

const DEFAULT_TIMEOUT_MS = 60000;
const DEFAULT_RETRIES = 3;
const MAX_BACKOFF_MS = 30000;

/** Node fetch surfaces DNS/TLS/socket problems as an opaque TypeError. */
const TRANSIENT_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EPIPE",
  "ETIMEDOUT",
  "ECONNABORTED",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENETDOWN",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_BODY_TIMEOUT",
  "UND_ERR_SOCKET",
]);

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function errorCode(e) {
  return String((e && (e.code || (e.cause && e.cause.code))) || "");
}

function isTransientError(e) {
  if (!e) return false;
  if (e.name === "AbortError" || e.name === "TimeoutError") return true;
  if (TRANSIENT_CODES.has(errorCode(e))) return true;
  const msg = String(e.message || "").toLowerCase();
  return (
    msg.includes("fetch failed") ||
    msg.includes("terminated") ||
    msg.includes("socket hang up") ||
    msg.includes("network") ||
    msg.includes("timeout")
  );
}

function isTransientStatus(status) {
  return status === 408 || status === 429 || (status >= 500 && status <= 599);
}

function backoffMs(attempt, retryAfterSec) {
  if (retryAfterSec != null && Number.isFinite(retryAfterSec)) {
    return Math.min(Math.max(retryAfterSec, 1), 60) * 1000;
  }
  const base = Math.min(1000 * 2 ** (attempt - 1), MAX_BACKOFF_MS);
  return base + Math.floor(Math.random() * 400);
}

function parseRetryAfter(res) {
  const raw = res && res.headers && res.headers.get("Retry-After");
  if (!raw) return null;
  const n = Number(raw);
  if (Number.isFinite(n)) return n;
  const at = Date.parse(raw);
  return Number.isFinite(at) ? Math.max(0, (at - Date.now()) / 1000) : null;
}

function httpError(status, url, text) {
  const err = new Error(`HTTP ${status} ${url}\n${String(text).slice(0, 400)}`);
  err.status = status;
  err.url = url;
  err.body = text;
  return err;
}

/**
 * Fetch with a hard timeout and bounded retries.
 *
 * Retries transient network failures, 408/429/5xx. Never retries 4xx (other
 * than 408/429) — those are caller errors and would only waste the budget.
 *
 * @param {object} [opts.onRetry] called as (attempt, reason, waitMs) for logging
 * @returns {Promise<Response>} the successful Response (body unread)
 */
async function fetchResilient(url, opts = {}) {
  const {
    method = "GET",
    headers = {},
    body = null,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    retries = DEFAULT_RETRIES,
    onRetry = null,
    signal = null,
  } = opts;

  let lastErr = null;

  for (let attempt = 1; attempt <= retries + 1; attempt++) {
    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const reqSignal = signal
      ? AbortSignal.any([signal, timeoutSignal])
      : timeoutSignal;

    let res;
    try {
      res = await fetch(url, { method, headers, body, signal: reqSignal });
    } catch (e) {
      lastErr = e;
      // An externally requested abort is a decision, not a glitch.
      if (signal && signal.aborted) throw e;
      if (attempt > retries || !isTransientError(e)) {
        const wrapped = new Error(
          `${e.name === "TimeoutError" ? `timeout after ${timeoutMs}ms` : e.message} — ${url}`
        );
        wrapped.cause = e;
        wrapped.transient = isTransientError(e);
        throw wrapped;
      }
      const wait = backoffMs(attempt);
      if (onRetry) onRetry(attempt, e.message || String(e), wait);
      await sleep(wait);
      continue;
    }

    if (res.ok) return res;

    if (isTransientStatus(res.status) && attempt <= retries) {
      const wait = backoffMs(attempt, parseRetryAfter(res));
      // Drain so the socket returns to the pool instead of leaking.
      await res.text().catch(() => {});
      if (onRetry) onRetry(attempt, `HTTP ${res.status}`, wait);
      await sleep(wait);
      continue;
    }

    const text = await res.text().catch(() => "");
    throw httpError(res.status, url, text);
  }

  throw lastErr || new Error(`Request failed after ${retries + 1} attempts: ${url}`);
}

/** fetchResilient + JSON decode, tolerating empty bodies. */
async function fetchJsonResilient(url, opts = {}) {
  const res = await fetchResilient(url, opts);
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`Invalid JSON from ${url}: ${String(e.message).slice(0, 120)}`);
  }
}

module.exports = {
  fetchResilient,
  fetchJsonResilient,
  isTransientError,
  isTransientStatus,
  sleep,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_RETRIES,
};
