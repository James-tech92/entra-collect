const test = require("node:test");
const assert = require("node:assert");
const { fetchResilient, isTransientError } = require("../lib/net");

/** Swap global fetch for a scripted sequence, restoring it afterwards. */
function withFetch(sequence, fn) {
  const original = global.fetch;
  let calls = 0;
  global.fetch = async () => {
    const step = sequence[Math.min(calls, sequence.length - 1)];
    calls++;
    if (step instanceof Error) throw step;
    return step;
  };
  return fn(() => calls).finally(() => {
    global.fetch = original;
  });
}

function res(status, body = "{}") {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
    text: async () => body,
  };
}

function networkError() {
  const e = new TypeError("fetch failed");
  e.cause = { code: "ECONNRESET" };
  return e;
}

test("classifies Node's opaque network failure as transient", () => {
  assert.equal(isTransientError(networkError()), true);
  assert.equal(isTransientError(new Error("Bad Request")), false);
});

test("retries a transient network error and then succeeds", async () => {
  await withFetch([networkError(), networkError(), res(200)], async (calls) => {
    const r = await fetchResilient("https://example.test/a", { retries: 3 });
    assert.equal(r.status, 200);
    assert.equal(calls(), 3);
  });
});

test("retries 5xx but never a 403", async () => {
  await withFetch([res(503), res(200)], async (calls) => {
    await fetchResilient("https://example.test/b", { retries: 2 });
    assert.equal(calls(), 2);
  });

  await withFetch([res(403, "Forbidden")], async (calls) => {
    await assert.rejects(
      () => fetchResilient("https://example.test/c", { retries: 3 }),
      (e) => e.status === 403
    );
    assert.equal(calls(), 1, "403 must not consume the retry budget");
  });
});

test("gives up after the retry budget and reports the cause", async () => {
  await withFetch([networkError()], async (calls) => {
    await assert.rejects(
      () => fetchResilient("https://example.test/d", { retries: 2 }),
      /fetch failed/
    );
    assert.equal(calls(), 3);
  });
});
