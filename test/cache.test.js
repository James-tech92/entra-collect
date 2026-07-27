const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { createCache } = require("../lib/cache");
const { createGraph } = require("../lib/graph");
const { TokenPool } = require("../lib/tokens");

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "entra-cache-"));
}

function poolWithToken() {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const pool = new TokenPool();
  pool.add(
    `${b64({ alg: "none" })}.${b64({
      aud: "https://graph.microsoft.com",
      appid: "a",
      scp: "Directory.Read.All",
      exp: Math.floor(Date.now() / 1000) + 3600,
    })}.sig`
  );
  return pool;
}

function stubFetch(handler) {
  const original = global.fetch;
  global.fetch = handler;
  return () => {
    global.fetch = original;
  };
}

test("a fresh run records responses; a resumed run replays them without network", async () => {
  const dir = tmpDir();
  let networkCalls = 0;

  const respond = async () => {
    networkCalls++;
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      text: async () => JSON.stringify({ value: [{ id: "user-1" }] }),
    };
  };

  let restore = stubFetch(respond);
  try {
    const graph = createGraph(poolWithToken(), {
      cache: createCache(dir, { read: false, write: true }),
    });
    const a = await graph.getAll("https://graph.microsoft.com/v1.0/users");
    assert.deepEqual(a, [{ id: "user-1" }]);
    assert.equal(networkCalls, 1);
  } finally {
    restore();
  }

  restore = stubFetch(async () => {
    throw new Error("resume must not hit the network for a cached call");
  });
  try {
    const graph = createGraph(poolWithToken(), {
      cache: createCache(dir, { read: true, write: true }),
    });
    const b = await graph.getAll("https://graph.microsoft.com/v1.0/users");
    assert.deepEqual(b, [{ id: "user-1" }]);
  } finally {
    restore();
  }
});

test("a resumed run still fetches calls that were never cached", async () => {
  const dir = tmpDir();
  let networkCalls = 0;
  const restore = stubFetch(async () => {
    networkCalls++;
    return {
      ok: true,
      status: 200,
      headers: { get: () => null },
      text: async () => JSON.stringify({ value: [] }),
    };
  });
  try {
    const graph = createGraph(poolWithToken(), {
      cache: createCache(dir, { read: true, write: true }),
    });
    await graph.getAll("https://graph.microsoft.com/v1.0/devices");
    assert.equal(networkCalls, 1, "cache miss must fall through to the network");
  } finally {
    restore();
  }
});
