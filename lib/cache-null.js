/**
 * No-op cache so callers never need to null-check.
 *
 * Split out of lib/cache.js (which needs fs/path/crypto for the real
 * file-backed --resume cache) so lib/graph.js's default cache dependency
 * stays Node-free and bundleable for the browser web app.
 */
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

module.exports = { nullCache };
