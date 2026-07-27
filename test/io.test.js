const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { createIo, readManifest, STATUS } = require("../lib/io");

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "entra-io-"));
}

test("an empty CSV from a failed step is recorded as failed, not empty", () => {
  const dir = tmpDir();
  const io = createIo(dir);

  io.saveCsv("ok.csv", [{ a: 1 }]);
  io.saveCsv("clean.csv", []);
  io.saveCsv("broken.csv", [], { status: STATUS.FAILED });

  const m = readManifest(dir);
  assert.equal(m.artifacts["ok.csv"].status, STATUS.OK);
  assert.equal(m.artifacts["clean.csv"].status, STATUS.EMPTY);
  assert.equal(
    m.artifacts["broken.csv"].status,
    STATUS.FAILED,
    "a report must be able to tell an outage from a clean tenant"
  );
});

test("soft() retries transient failures and records the outcome", async () => {
  const dir = tmpDir();
  const io = createIo(dir);

  let attempts = 0;
  const value = await io.soft(
    "flaky",
    async () => {
      attempts++;
      if (attempts === 1) {
        const e = new TypeError("fetch failed");
        e.cause = { code: "ECONNRESET" };
        throw e;
      }
      return "recovered";
    },
    { retryDelayMs: 1 }
  );

  assert.equal(value, "recovered");
  assert.equal(attempts, 2);
  assert.equal(readManifest(dir).steps.flaky.status, STATUS.OK);
  assert.equal(fs.existsSync(path.join(dir, "ERROR_flaky.json")), false);
});

test("soft() does not retry a deterministic 403 and records the failure", async () => {
  const dir = tmpDir();
  const io = createIo(dir);

  let attempts = 0;
  const value = await io.soft("forbidden", async () => {
    attempts++;
    const e = new Error("HTTP 403 Forbidden");
    e.status = 403;
    throw e;
  });

  assert.equal(value, null);
  assert.equal(attempts, 1);
  const m = readManifest(dir);
  assert.equal(m.steps.forbidden.status, STATUS.FAILED);
  assert.equal(m.steps.forbidden.httpStatus, 403);
  assert.ok(fs.existsSync(path.join(dir, "ERROR_forbidden.json")));
});

test("a step that succeeds on resume clears the stale error file", async () => {
  const dir = tmpDir();
  const first = createIo(dir);
  await first.soft("step", async () => {
    throw new Error("boom");
  });
  assert.ok(fs.existsSync(path.join(dir, "ERROR_step.json")));

  const second = createIo(dir, { previousManifest: readManifest(dir) });
  await second.soft("step", async () => "fine");
  assert.equal(fs.existsSync(path.join(dir, "ERROR_step.json")), false);
});

test("post-processing passes must not clobber the collection manifest", () => {
  const dir = tmpDir();
  const collector = createIo(dir);
  collector.saveCsv("data.csv", [{ a: 1 }]);
  collector.finish();

  const analyzer = createIo(dir, { manifest: false });
  analyzer.saveCsv("00_Expert_Findings.csv", [{ b: 2 }]);

  const m = readManifest(dir);
  assert.ok(m.artifacts["data.csv"], "collector record survives");
  assert.equal(m.artifacts["00_Expert_Findings.csv"], undefined);
});
