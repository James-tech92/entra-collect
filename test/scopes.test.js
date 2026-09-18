const test = require("node:test");
const assert = require("node:assert");
const { REQUIRED_SCOPES, evaluatePermissions } = require("../lib/scopes");

test("evaluatePermissions marks an area ok when any of its required scopes is granted", () => {
  const { rows, missing } = evaluatePermissions({ scp: "Policy.Read.All" });
  const ca = rows.find((r) => r.area === "Conditional Access");
  assert.strictEqual(ca.status, "ok");
  assert.ok(!missing.includes(ca));
});

test("evaluatePermissions marks everything missing on a bare token", () => {
  const { rows, missing } = evaluatePermissions({ scp: "User.Read" });
  assert.strictEqual(missing.length, REQUIRED_SCOPES.length);
  assert.ok(rows.every((r) => r.status === "missing"));
});

test("evaluatePermissions falls back to 'portal' for portal-eligible areas when a browser session is open", () => {
  const { rows } = evaluatePermissions({ scp: "" }, { hasPortalSession: true });
  const hunting = rows.find((r) => r.area === "Defender Advanced Hunting");
  assert.strictEqual(hunting.status, "portal");
});

test("evaluatePermissions unions scopes across multiple pooled tokens", () => {
  const { rows } = evaluatePermissions([
    { scp: "Policy.Read.All" },
    { scp: "Directory.Read.All" },
  ]);
  assert.ok(rows.every((r) => r.area !== "Conditional Access" || r.status === "ok"));
  const dir = rows.find((r) => r.area === "Directory / users / devices");
  assert.strictEqual(dir.status, "ok");
});
