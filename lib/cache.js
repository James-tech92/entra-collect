/**
 * File-backed response cache, used to make `--resume` cheap.
 *
 * A full collection is 1-3 hours of API calls; when a handful of steps fail
 * near the end there is no reason to re-pay for the ones that worked. Caching
 * at the transport layer rather than the step layer keeps every side effect in
 * the pipeline (CSV writes, findings, summary fields) intact on a resumed run —
 * only the network round-trip is skipped.
 */
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const CACHE_DIR = ".cache";

function keyOf(kind, value) {
  const h = crypto.createHash("sha1").update(String(value)).digest("hex").slice(0, 32);
  return `${kind}_${h}`;
}

/**
 * @param {string} outDir
 * @param {object} [opts]
 * @param {boolean} [opts.read]  serve hits from disk (resume mode)
 * @param {boolean} [opts.write] persist responses for a future resume
 */
function createCache(outDir, opts = {}) {
  const dir = path.join(outDir, CACHE_DIR);
  const read = !!opts.read;
  const write = opts.write !== false;
  const stats = { hits: 0, misses: 0, writes: 0 };

  if (write) {
    try {
      fs.mkdirSync(dir, { recursive: true });
    } catch {
      /* cache is an optimisation, never fatal */
    }
  }

  function pathFor(key) {
    return path.join(dir, `${key}.json`);
  }

  function get(kind, value) {
    if (!read) return undefined;
    try {
      const raw = fs.readFileSync(pathFor(keyOf(kind, value)), "utf8");
      stats.hits++;
      return JSON.parse(raw).data;
    } catch {
      stats.misses++;
      return undefined;
    }
  }

  function set(kind, value, data) {
    if (!write || data === undefined) return;
    try {
      fs.writeFileSync(
        pathFor(keyOf(kind, value)),
        JSON.stringify({ kind, at: new Date().toISOString(), data }),
        "utf8"
      );
      stats.writes++;
    } catch {
      /* ignore */
    }
  }

  /** Drop a cached entry so a resumed run re-fetches it (used after failures). */
  function invalidate(kind, value) {
    try {
      fs.unlinkSync(pathFor(keyOf(kind, value)));
    } catch {
      /* ignore */
    }
  }

  function summarize() {
    return { ...stats, enabled: read || write, dir };
  }

  return { get, set, invalidate, read, write, stats, summarize };
}

/** No-op cache so callers never need to null-check. */
function nullCache() {
  return {
    get: () => undefined,
    set: () => {},
    invalidate: () => {},
    read: false,
    write: false,
    stats: { hits: 0, misses: 0, writes: 0 },
    summarize: () => ({ enabled: false, hits: 0, misses: 0, writes: 0 }),
  };
}

module.exports = { createCache, nullCache, CACHE_DIR };
