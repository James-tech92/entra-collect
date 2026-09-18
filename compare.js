#!/usr/bin/env node
/**
 * Entra Collect — compare two collection runs (score, findings delta).
 *
 * Built on top of report.js's buildReportPayload, so the same expert
 * narratives / findings / checklist a single-run report shows are what gets
 * diffed here — no separate data pipeline to keep in sync.
 *
 * Usage:
 *   node compare.js --help
 *   node compare.js <before_output_dir> <after_output_dir>
 *   node compare.js                        # two most recent output_* dirs
 */
const fs = require("fs");
const path = require("path");
const { buildReportPayload } = require("./report");

function listDataDirs(base) {
  return fs
    .readdirSync(base)
    .filter((d) => d.startsWith("output_") && fs.statSync(path.join(base, d)).isDirectory())
    .filter((d) => {
      try {
        return fs.readdirSync(path.join(base, d)).some((f) => /\.(csv|json)$/i.test(f));
      } catch {
        return false;
      }
    })
    .sort();
}

function argValue(argv, flag, fallback) {
  const i = argv.indexOf(flag);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
}

function printHelp() {
  console.log(`Entra Collect — compare two runs

Score + findings delta between two output_* folders (e.g. before/after a
remediation pass). Does not re-collect or re-analyze beyond what report.js
already computes for each folder.

Usage:
  node compare.js [before_dir] [after_dir]
  node compare.js                        # two most recent output_* under this folder
  node compare.js --out FILE.html        # custom output path
  node compare.js --help

Output:
  00_Comparison_<before>_vs_<after>.html   (self-contained, opens in a browser)
`);
}

/** Stable across runs — narratives carry a rule Id (NARR.*), not a row index. */
function narrativeKey(n) {
  return n.Id;
}

/**
 * Raw inventory findings have no stable id. Area + Severity + Detail is a
 * best-effort key: stable when nothing changed, but a Detail string that
 * embeds a shifting count or timestamp will read as "resolved + new" rather
 * than "persisting". Good enough for a delta view, not a perfect diff.
 */
function findingKey(f) {
  return [f.Area || "", f.Severity || "", f.Detail || ""].join("");
}

function diffByKey(beforeList, afterList, keyFn) {
  const beforeMap = new Map((beforeList || []).map((x) => [keyFn(x), x]));
  const afterMap = new Map((afterList || []).map((x) => [keyFn(x), x]));
  const resolved = [];
  const persisting = [];
  const added = [];
  for (const [k, v] of beforeMap) {
    if (afterMap.has(k)) persisting.push(v);
    else resolved.push(v);
  }
  for (const [k, v] of afterMap) {
    if (!beforeMap.has(k)) added.push(v);
  }
  return { resolved, persisting, added };
}

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

function sevDelta(before, after) {
  return SEVERITIES.map((s) => ({
    severity: s,
    before: (before && before[s]) || 0,
    after: (after && after[s]) || 0,
    delta: ((after && after[s]) || 0) - ((before && before[s]) || 0),
  }));
}

function checklistCount(list) {
  const c = { pass: 0, fail: 0, partial: 0 };
  for (const r of list || []) {
    const s = String(r.Status || "").toLowerCase();
    if (s.includes("pass")) c.pass++;
    else if (s.includes("fail")) c.fail++;
    else if (s.includes("partial")) c.partial++;
  }
  return c;
}

function pickNarr(n) {
  return { Id: n.Id, Severity: n.Severity, Priority: n.Priority, Title: n.Title };
}

function pickFinding(f) {
  return { Area: f.Area, Severity: f.Severity, Detail: f.Detail };
}

function buildComparison(beforeDir, afterDir) {
  const before = buildReportPayload(beforeDir);
  const after = buildReportPayload(afterDir);

  const narrDiff = diffByKey(before.narratives, after.narratives, narrativeKey);
  const findingsDiff = diffByKey(before.findings, after.findings, findingKey);

  return {
    meta: {
      generatedAt: new Date().toISOString(),
      before: path.basename(beforeDir),
      after: path.basename(afterDir),
      tool: "Entra Collect",
    },
    score: {
      before: before.score,
      after: after.score,
      delta: (after.score || 0) - (before.score || 0),
    },
    sevDelta: sevDelta(before.sevCount, after.sevCount),
    narratives: {
      resolvedCount: narrDiff.resolved.length,
      newCount: narrDiff.added.length,
      persistingCount: narrDiff.persisting.length,
      resolved: narrDiff.resolved.map(pickNarr),
      added: narrDiff.added.map(pickNarr),
    },
    findings: {
      resolvedCount: findingsDiff.resolved.length,
      newCount: findingsDiff.added.length,
      persistingCount: findingsDiff.persisting.length,
      resolved: findingsDiff.resolved.slice(0, 500).map(pickFinding),
      added: findingsDiff.added.slice(0, 500).map(pickFinding),
    },
    checklist: {
      before: checklistCount(before.attackChecklist),
      after: checklistCount(after.attackChecklist),
    },
  };
}

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderJsonPayload(data) {
  return JSON.stringify(data).replace(/</g, "\\u003c");
}

function sevTone(s) {
  const t = String(s || "").toLowerCase();
  if (t === "critical" || t === "high") return "bad";
  if (t === "medium") return "warn";
  return "ok";
}

function deltaSpan(n) {
  if (n > 0) return '<span class="delta-up">+' + n + "</span>";
  if (n < 0) return '<span class="delta-down">' + n + "</span>";
  return '<span class="delta-flat">0</span>';
}

function narrRows(list, cls) {
  if (!list.length) return '<p class="muted">None.</p>';
  return (
    '<table><thead><tr><th>Severity</th><th>Priority</th><th>Id</th><th>Title</th></tr></thead><tbody>' +
    list
      .map(
        (n) =>
          '<tr class="' +
          cls +
          '"><td><span class="badge tone-' +
          sevTone(n.Severity) +
          '">' +
          escapeHtml(n.Severity) +
          "</span></td><td>" +
          escapeHtml(n.Priority || "") +
          "</td><td><code>" +
          escapeHtml(n.Id) +
          "</code></td><td>" +
          escapeHtml(n.Title) +
          "</td></tr>"
      )
      .join("") +
    "</tbody></table>"
  );
}

function findingRows(list, cls) {
  if (!list.length) return '<p class="muted">None.</p>';
  return (
    '<table><thead><tr><th>Severity</th><th>Area</th><th>Detail</th></tr></thead><tbody>' +
    list
      .map(
        (f) =>
          '<tr class="' +
          cls +
          '"><td><span class="badge tone-' +
          sevTone(f.Severity) +
          '">' +
          escapeHtml(f.Severity) +
          "</span></td><td>" +
          escapeHtml(f.Area) +
          "</td><td>" +
          escapeHtml(f.Detail) +
          "</td></tr>"
      )
      .join("") +
    "</tbody></table>"
  );
}

function renderComparisonHtml(data) {
  const json = renderJsonPayload(data);
  const scoreDelta = data.score.delta;
  const scoreClass = scoreDelta > 0 ? "delta-up" : scoreDelta < 0 ? "delta-down" : "delta-flat";
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Entra Collect — Comparison</title>
<style>
:root { --bg:#0a0f1a; --card:#141c2b; --border:#243044; --text:#e8eef7; --muted:#8b9bb4;
  --ok:#22c55e; --warn:#f59e0b; --bad:#ef4444; --accent:#2dd4bf; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,sans-serif; padding:2rem; }
h1 { font-size:1.4rem; margin:0 0 .25rem; }
h2 { font-size:1.05rem; margin:1.75rem 0 .6rem; }
.sub { color:var(--muted); margin-bottom:1.5rem; font-size:.9rem; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:.75rem; margin-bottom:1.5rem; }
.card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:1rem; }
.stat-label { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.06em; margin-bottom:.35rem; }
.stat-value { font-size:1.6rem; font-weight:700; }
table { width:100%; border-collapse:collapse; font-size:.85rem; margin-bottom:1rem; }
th,td { text-align:left; padding:.5rem .6rem; border-bottom:1px solid var(--border); vertical-align:top; }
th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.05em; }
.muted { color:var(--muted); }
code { font-size:.8em; color:var(--accent); }
.badge { display:inline-block; padding:.15rem .5rem; border-radius:999px; font-size:11px; font-weight:600; }
.badge.tone-bad { background:rgba(239,68,68,.15); color:var(--bad); }
.badge.tone-warn { background:rgba(245,158,11,.15); color:var(--warn); }
.badge.tone-ok { background:rgba(34,197,94,.15); color:var(--ok); }
.delta-up { color:var(--bad); font-weight:700; }
.delta-down { color:var(--ok); font-weight:700; }
.delta-flat { color:var(--muted); font-weight:700; }
.tabs { display:flex; gap:.4rem; margin-bottom:.6rem; }
.tabs button { background:var(--card); border:1px solid var(--border); color:var(--text); padding:.4rem .8rem;
  border-radius:8px; cursor:pointer; font-size:.85rem; }
.tabs button.active { background:var(--accent); color:#04211d; border-color:var(--accent); }
.panel { display:none; }
.panel.active { display:block; }
</style>
</head>
<body>
<h1>Entra Collect — Run comparison</h1>
<div class="sub" id="sub"></div>

<div class="grid">
  <div class="card">
    <div class="stat-label">Posture score</div>
    <div class="stat-value">${escapeHtml(data.score.before)} &rarr; ${escapeHtml(data.score.after)}
      <span class="${scoreClass}" style="font-size:1rem">(${scoreDelta > 0 ? "+" : ""}${escapeHtml(scoreDelta)})</span></div>
  </div>
  <div class="card">
    <div class="stat-label">Expert findings — new</div>
    <div class="stat-value delta-up">+${escapeHtml(data.narratives.newCount)}</div>
  </div>
  <div class="card">
    <div class="stat-label">Expert findings — resolved</div>
    <div class="stat-value delta-down">-${escapeHtml(data.narratives.resolvedCount)}</div>
  </div>
  <div class="card">
    <div class="stat-label">Expert findings — persisting</div>
    <div class="stat-value">${escapeHtml(data.narratives.persistingCount)}</div>
  </div>
</div>

<h2>Severity mix</h2>
<table><thead><tr><th>Severity</th><th>Before</th><th>After</th><th>Delta</th></tr></thead><tbody>
${data.sevDelta
  .map(
    (r) =>
      "<tr><td><span class=\"badge tone-" +
      sevTone(r.severity) +
      "\">" +
      escapeHtml(r.severity) +
      "</span></td><td>" +
      escapeHtml(r.before) +
      "</td><td>" +
      escapeHtml(r.after) +
      "</td><td>" +
      deltaSpan(r.delta) +
      "</td></tr>"
  )
  .join("")}
</tbody></table>

<h2>Attack-path checklist</h2>
<table><thead><tr><th></th><th>Pass</th><th>Partial</th><th>Fail</th></tr></thead><tbody>
<tr><td class="muted">Before</td><td>${escapeHtml(data.checklist.before.pass)}</td><td>${escapeHtml(data.checklist.before.partial)}</td><td>${escapeHtml(data.checklist.before.fail)}</td></tr>
<tr><td class="muted">After</td><td>${escapeHtml(data.checklist.after.pass)}</td><td>${escapeHtml(data.checklist.after.partial)}</td><td>${escapeHtml(data.checklist.after.fail)}</td></tr>
</tbody></table>

<h2>Expert findings (NARR.*)</h2>
<div class="tabs" id="narrTabs">
  <button data-t="narr-new" class="active">New (${escapeHtml(data.narratives.newCount)})</button>
  <button data-t="narr-resolved">Resolved (${escapeHtml(data.narratives.resolvedCount)})</button>
</div>
<div class="panel active" id="narr-new">${narrRows(data.narratives.added, "row-new")}</div>
<div class="panel" id="narr-resolved">${narrRows(data.narratives.resolved, "row-resolved")}</div>

<h2>Raw inventory findings (best-effort match on Area + Severity + Detail)</h2>
<div class="tabs" id="findTabs">
  <button data-t="find-new" class="active">New (${escapeHtml(data.findings.newCount)})</button>
  <button data-t="find-resolved">Resolved (${escapeHtml(data.findings.resolvedCount)})</button>
</div>
<div class="panel active" id="find-new">${findingRows(data.findings.added, "row-new")}</div>
<div class="panel" id="find-resolved">${findingRows(data.findings.resolved, "row-resolved")}</div>
<p class="muted" style="font-size:.8rem">Persisting (unchanged both runs): ${escapeHtml(data.findings.persistingCount)} inventory finding(s). Matched on Area + Severity + Detail text — a Detail that embeds a shifting count or timestamp will show as resolved + new instead of persisting.</p>

<script id="comparison-data" type="application/json">${json}</script>
<script>
(function () {
  var D = JSON.parse(document.getElementById("comparison-data").textContent);
  document.getElementById("sub").textContent =
    "Before: " + D.meta.before + "   \\u2192   After: " + D.meta.after + "   \\u00b7   generated " + D.meta.generatedAt;
  document.querySelectorAll(".tabs").forEach(function (group) {
    group.querySelectorAll("button").forEach(function (btn) {
      btn.addEventListener("click", function () {
        group.querySelectorAll("button").forEach(function (b) { b.classList.remove("active"); });
        btn.classList.add("active");
        var target = btn.getAttribute("data-t");
        group.parentElement.querySelectorAll(".panel").forEach(function (p) {
          p.classList.toggle("active", p.id === target);
        });
      });
    });
  });
})();
</script>
</body>
</html>`;
}

function writeComparison(beforeDir, afterDir, outPath) {
  const data = buildComparison(beforeDir, afterDir);
  fs.writeFileSync(outPath, renderComparisonHtml(data), "utf8");
  return { outPath, data };
}

function main(argv) {
  if (argv.includes("--help") || argv.includes("-h")) {
    printHelp();
    process.exit(0);
  }
  const base = path.resolve(__dirname);
  const positional = argv.filter((a, i) => !a.startsWith("--") && argv[i - 1] !== "--out");
  let beforeDir, afterDir;
  if (positional.length >= 2) {
    beforeDir = path.resolve(positional[0]);
    afterDir = path.resolve(positional[1]);
  } else {
    const dirs = listDataDirs(base);
    if (dirs.length < 2) {
      console.error(
        "Need at least two output_* folders with data to compare.\n" +
          "  Usage: node compare.js <before_dir> <after_dir>"
      );
      process.exit(1);
    }
    beforeDir = path.join(base, dirs[dirs.length - 2]);
    afterDir = path.join(base, dirs[dirs.length - 1]);
  }
  if (!fs.existsSync(beforeDir) || !fs.existsSync(afterDir)) {
    console.error(
      `One of the two output directories does not exist:\n  ${beforeDir}\n  ${afterDir}`
    );
    process.exit(1);
  }

  console.log(
    `Entra Collect — comparing ${path.basename(beforeDir)} → ${path.basename(afterDir)}`
  );
  const outArg = argValue(argv, "--out", "");
  const outPath = outArg
    ? path.resolve(outArg)
    : path.join(
        base,
        `00_Comparison_${path.basename(beforeDir)}_vs_${path.basename(afterDir)}.html`
      );
  const { data } = writeComparison(beforeDir, afterDir, outPath);
  console.log(`✓ Comparison written: ${outPath}`);
  console.log(
    `  Score: ${data.score.before} -> ${data.score.after} (${data.score.delta >= 0 ? "+" : ""}${data.score.delta})`
  );
  console.log(
    `  Expert findings (NARR.*): +${data.narratives.newCount} new · -${data.narratives.resolvedCount} resolved · ${data.narratives.persistingCount} persisting`
  );
  console.log(
    `  Raw inventory findings:   +${data.findings.newCount} new · -${data.findings.resolvedCount} resolved · ${data.findings.persistingCount} persisting`
  );
  return outPath;
}

if (require.main === module) {
  main(process.argv.slice(2));
}

module.exports = { buildComparison, renderComparisonHtml, writeComparison, main };
