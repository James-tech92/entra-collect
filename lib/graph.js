/** Graph client over a TokenPool */
const GRAPH = "https://graph.microsoft.com/v1.0";
const GRAPH_BETA = "https://graph.microsoft.com/beta";
const { runHuntingQuery } = require("./hunt");
const { fetchJsonResilient } = require("./net");
// From cache-null.js, not cache.js: the latter needs fs/path/crypto (the
// real file-backed --resume cache), which would drag Node builtins into
// the browser bundle for a dependency this module only uses as a default.
const { nullCache } = require("./cache-null");

/** Graph tolerates fairly long waits; keep it under the per-step budget. */
const GRAPH_TIMEOUT_MS = 90000;

function shortUrl(url) {
  return String(url).replace(/^https:\/\/graph\.microsoft\.com/, "").slice(0, 80);
}

async function fetchOnce(token, url, { method = "GET", body = null } = {}) {
  const headers = {
    Authorization: `Bearer ${token}`,
    ConsistencyLevel: "eventual",
    "Accept-Language": "en-US",
  };
  if (body) headers["Content-Type"] = "application/json";

  return fetchJsonResilient(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    timeoutMs: GRAPH_TIMEOUT_MS,
    onRetry: (attempt, reason, waitMs) => {
      console.warn(
        `  ↻ graph retry ${attempt} in ${Math.round(waitMs / 1000)}s (${String(reason).slice(0, 80)}) ${shortUrl(url)}`
      );
    },
  });
}

async function graphFetch(token, url, { all = false, maxPages = 200 } = {}) {
  if (!all) return fetchOnce(token, url);

  const items = [];
  let next = url;
  let pages = 0;
  while (next) {
    pages++;
    if (pages > maxPages) {
      console.warn(
        `  ⚠ pagination capped at ${maxPages} pages (${items.length} items) for ${url.split("?")[0]}`
      );
      // Flagged so callers can report "partial" instead of a confident count.
      items.truncated = true;
      items.truncatedAtPages = maxPages;
      return items;
    }
    const data = await fetchOnce(token, next);
    if (data && Array.isArray(data.value)) items.push(...data.value);
    else return data;
    next = (data && data["@odata.nextLink"]) || null;
  }
  return items;
}

function isAuthError(e) {
  return e && (e.status === 401 || e.status === 403);
}

function createGraph(pool, opts = {}) {
  const cache = opts.cache || nullCache();

  /**
   * Try every pooled token, then — if all of them were rejected as
   * unauthenticated — ask the pool to mint a fresh one and try once more.
   * Long runs outlive the ~60-75 min lifetime of a Graph token, so without this
   * every step after the first hour fails.
   */
  async function attempt(url, opts, exec) {
    const tokens = pool.list();
    if (!tokens.length) return { exhausted: true, lastErr: null };
    let lastErr = null;
    let sawExpiredAuth = false;
    for (const entry of tokens) {
      try {
        return { value: await exec(entry.token, url, opts) };
      } catch (e) {
        lastErr = e;
        if (!isAuthError(e)) throw e;
        if (e.status === 401) sawExpiredAuth = true;
      }
    }
    return { exhausted: sawExpiredAuth, lastErr };
  }

  async function withPool(url, opts = {}, exec = graphFetch) {
    let r = await attempt(url, opts, exec);
    if ("value" in r) return r.value;

    if (r.exhausted && (await pool.refresh())) {
      r = await attempt(url, opts, exec);
      if ("value" in r) return r.value;
    }

    throw r.lastErr || new Error("No Graph tokens in pool");
  }

  /** Serve from cache on a resumed run; otherwise fetch and record. */
  async function cached(kind, cacheKey, run) {
    const hit = cache.get(kind, cacheKey);
    if (hit !== undefined) return hit;
    const value = await run();
    cache.set(kind, cacheKey, value);
    return value;
  }

  async function hunt(query, huntOpts = {}) {
    const key = `${huntOpts.timespan || ""}|${query}`;
    return cached("hunt", key, () => runHuntingQuery(pool, query, huntOpts));
  }

  return {
    GRAPH,
    GRAPH_BETA,
    pool,
    cache,
    get: (url) => cached("get", url, () => withPool(url, { all: false })),
    getAll: (url, maxPages) =>
      cached("getAll", url, () =>
        withPool(url, { all: true, maxPages: maxPages || 200 })
      ),
    post: async (url, body) => {
      // Hunting: portal apiproxy (browser) OR Graph ThreatHunting OR legacy MTP Bearer
      if (/\/security\/runHuntingQuery/i.test(String(url || ""))) {
        const result = await hunt(body && body.Query, {
          timespan: body && body.Timespan,
        });
        // Callers expect Graph-shaped { results }
        return {
          results: result.results || [],
          schema: result.schema,
          stats: result.stats,
          _backend: result.backend,
        };
      }
      return cached(`post:${url}`, JSON.stringify(body || {}), () =>
        withPool(url, {}, (token, u) => fetchOnce(token, u, { method: "POST", body }))
      );
    },
    runHuntingQuery: hunt,
  };
}

module.exports = { createGraph, GRAPH, GRAPH_BETA };
