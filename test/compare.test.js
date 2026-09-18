const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { buildComparison, writeComparison } = require("../compare");

function tmpOutputDir(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return dir;
}

function writeFindingsCsv(dir, rows) {
  const header = "Severity,Area,Detail";
  const lines = [header, ...rows.map((r) => `${r.Severity},${r.Area},"${r.Detail}"`)];
  fs.writeFileSync(path.join(dir, "00_Findings.csv"), lines.join("\n") + "\n");
}

test("buildComparison splits raw findings into new / resolved / persisting", () => {
  const beforeDir = tmpOutputDir("entra-cmp-before-");
  const afterDir = tmpOutputDir("entra-cmp-after-");

  writeFindingsCsv(beforeDir, [
    { Severity: "High", Area: "Apps", Detail: "App LegacyIntegration has RoleManagement.ReadWrite.Directory" },
    { Severity: "Medium", Area: "MFA", Detail: "12 users without MFA registered" },
    { Severity: "Low", Area: "Devices", Detail: "5 stale joined devices found" },
  ]);
  writeFindingsCsv(afterDir, [
    { Severity: "Medium", Area: "MFA", Detail: "12 users without MFA registered" },
    { Severity: "Low", Area: "Devices", Detail: "5 stale joined devices found" },
    { Severity: "Critical", Area: "Apps", Detail: "App ShadowIT-Sync has RoleManagement.ReadWrite.Directory" },
  ]);

  const data = buildComparison(beforeDir, afterDir);
  assert.strictEqual(data.findings.resolvedCount, 1);
  assert.strictEqual(data.findings.newCount, 1);
  assert.strictEqual(data.findings.persistingCount, 2);
  assert.strictEqual(data.findings.resolved[0].Detail, "App LegacyIntegration has RoleManagement.ReadWrite.Directory");
  assert.strictEqual(data.findings.added[0].Detail, "App ShadowIT-Sync has RoleManagement.ReadWrite.Directory");
});

test("buildComparison reports zero deltas for two identical runs", () => {
  const beforeDir = tmpOutputDir("entra-cmp-same-a-");
  const afterDir = tmpOutputDir("entra-cmp-same-b-");
  const rows = [{ Severity: "Low", Area: "Devices", Detail: "5 stale joined devices found" }];
  writeFindingsCsv(beforeDir, rows);
  writeFindingsCsv(afterDir, rows);

  const data = buildComparison(beforeDir, afterDir);
  assert.strictEqual(data.findings.resolvedCount, 0);
  assert.strictEqual(data.findings.newCount, 0);
  assert.strictEqual(data.findings.persistingCount, 1);
  assert.strictEqual(data.score.delta, 0);
});

test("writeComparison writes a self-contained HTML file with the embedded payload", () => {
  const beforeDir = tmpOutputDir("entra-cmp-write-a-");
  const afterDir = tmpOutputDir("entra-cmp-write-b-");
  writeFindingsCsv(beforeDir, [{ Severity: "High", Area: "Apps", Detail: "x" }]);
  writeFindingsCsv(afterDir, []);

  const outPath = path.join(os.tmpdir(), `entra-cmp-${Date.now()}.html`);
  const { data } = writeComparison(beforeDir, afterDir, outPath);
  const html = fs.readFileSync(outPath, "utf8");

  assert.ok(html.startsWith("<!DOCTYPE html>"));
  assert.ok(html.includes('id="comparison-data"'));
  assert.strictEqual(data.findings.resolvedCount, 1);
  fs.unlinkSync(outPath);
});
