const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const {
  resolveMsalCacheDir,
  createEncryptedCachePlugin,
  cacheFilePaths,
  clearCache,
} = require("../lib/msal-auth");

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "entra-msal-"));
}

/** Minimal stand-in for MSAL's TokenCacheContext. */
function fakeContext(initialSerialized) {
  let serialized = initialSerialized;
  return {
    cacheHasChanged: true,
    tokenCache: {
      serialize: () => serialized,
      deserialize: (raw) => {
        serialized = raw;
      },
    },
  };
}

test("resolveMsalCacheDir respects ENTRA_COLLECT_PROFILE_DIR", () => {
  const dir = tmpDir();
  const prev = process.env.ENTRA_COLLECT_PROFILE_DIR;
  process.env.ENTRA_COLLECT_PROFILE_DIR = dir;
  try {
    assert.strictEqual(resolveMsalCacheDir(), path.join(dir, "msal"));
  } finally {
    if (prev == null) delete process.env.ENTRA_COLLECT_PROFILE_DIR;
    else process.env.ENTRA_COLLECT_PROFILE_DIR = prev;
  }
});

test("encrypted cache plugin round-trips the serialized cache and is not plaintext on disk", async () => {
  const cacheDir = tmpDir();
  const plugin = createEncryptedCachePlugin(cacheDir);
  const secretPayload = JSON.stringify({
    Account: { "some-home-id": { username: "alice@contoso.com" } },
  });

  const writeCtx = fakeContext(secretPayload);
  await plugin.afterCacheAccess(writeCtx);

  const { dataFile, keyFile } = cacheFilePaths(cacheDir);
  assert.ok(fs.existsSync(dataFile), "cache file should exist after a write");
  assert.ok(fs.existsSync(keyFile), "key file should exist after a write");

  const onDisk = fs.readFileSync(dataFile);
  assert.ok(
    !onDisk.toString("latin1").includes("alice@contoso.com"),
    "the UPN must not appear in plaintext in the cache file"
  );

  const readCtx = fakeContext(null);
  await plugin.beforeCacheAccess(readCtx);
  assert.strictEqual(readCtx.tokenCache.serialize(), secretPayload);
});

test("beforeCacheAccess on a missing cache file is a silent no-op", async () => {
  const cacheDir = tmpDir();
  const plugin = createEncryptedCachePlugin(cacheDir);
  const ctx = fakeContext(null);
  await plugin.beforeCacheAccess(ctx);
  assert.strictEqual(ctx.tokenCache.serialize(), null);
});

test("beforeCacheAccess on a corrupted cache file warns and starts fresh instead of throwing", async () => {
  const cacheDir = tmpDir();
  const plugin = createEncryptedCachePlugin(cacheDir);
  await plugin.afterCacheAccess(fakeContext("{}"));

  const { dataFile } = cacheFilePaths(cacheDir);
  fs.writeFileSync(dataFile, Buffer.from("not a valid ciphertext"));

  const ctx = fakeContext("untouched");
  await assert.doesNotReject(() => plugin.beforeCacheAccess(ctx));
  assert.strictEqual(ctx.tokenCache.serialize(), "untouched");
});

test("clearCache removes both the data file and the key file", async () => {
  const cacheDir = tmpDir();
  const plugin = createEncryptedCachePlugin(cacheDir);
  await plugin.afterCacheAccess(fakeContext("{}"));

  const { dataFile, keyFile } = cacheFilePaths(cacheDir);
  assert.ok(fs.existsSync(dataFile));
  assert.ok(fs.existsSync(keyFile));

  const removed = clearCache(cacheDir);
  assert.strictEqual(removed, 2);
  assert.ok(!fs.existsSync(dataFile));
  assert.ok(!fs.existsSync(keyFile));
});
