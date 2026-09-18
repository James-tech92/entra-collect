/**
 * Renders 00_REPORT.html in a real browser, clicks through every tab, and
 * asserts the dashboard actually built for each one. The report is ~100%
 * client-side, so a syntax error in the embedded script — or one that only
 * triggers once a specific tab mounts (e.g. a virtualized table) — produces
 * a blank page or an empty tab that no server-side test would catch.
 *
 * Also runs an axe-core accessibility scan per tab. Findings are always
 * printed; they only fail the run with --strict-a11y. Default is report-only
 * so introducing this scan doesn't turn pre-existing UI debt into a sudden
 * CI blocker — pass --strict-a11y once that debt is triaged.
 *
 *   node test/render-check.js <output_dir> [--strict-a11y]
 */
const path = require("path");
const fs = require("fs");
const { chromium } = require("playwright");

/** Below this, a tab is probably broken/empty rather than legitimately sparse. */
const MIN_TAB_TEXT_LENGTH = 60;

/**
 * Some sandboxes pre-stage a Chromium build at a fixed path without
 * registering it as a Playwright "channel" (see the repo's web-sandbox
 * README). Try it before giving up — cheap, and a no-op everywhere else.
 */
function resolveExecutablePath() {
  const candidates = [process.env.PLAYWRIGHT_CHROMIUM_PATH, "/opt/pw-browsers/chromium"].filter(
    Boolean
  );
  for (const p of candidates) {
    try {
      if (fs.existsSync(p)) return p;
    } catch {
      /* ignore */
    }
  }
  return null;
}

async function launchBrowser() {
  const attempts = [
    () => chromium.launch(),
    () => chromium.launch({ channel: "msedge" }),
    () => chromium.launch({ channel: "chrome" }),
    () => chromium.launch({ channel: "chromium" }),
  ];
  const exe = resolveExecutablePath();
  if (exe) attempts.unshift(() => chromium.launch({ executablePath: exe }));
  for (const attempt of attempts) {
    try {
      return await attempt();
    } catch {
      /* try the next one */
    }
  }
  return null;
}

function loadAxeSource() {
  try {
    return fs.readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
  } catch {
    console.warn("\n⚠ axe-core not found — skipping accessibility scan (npm install).");
    return null;
  }
}

async function main() {
  const argv = process.argv.slice(2);
  const dir = argv.find((a) => !a.startsWith("--"));
  const strictA11y = argv.includes("--strict-a11y");
  if (!dir) {
    console.error("usage: node test/render-check.js <output_dir> [--strict-a11y]");
    process.exit(2);
  }
  const file = "file://" + path.resolve(dir, "00_REPORT.html");

  const browser = await launchBrowser();
  if (!browser) {
    console.error(
      "No Chromium-family browser available. Run: npm run setup:browser (or install Edge/Chrome)."
    );
    process.exit(2);
  }
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e.message)));
  page.on("console", (m) => {
    // A failed subresource fetch (e.g. Google Fonts on an air-gapped /
    // proxy-filtered network — exactly the deployment this report is built
    // to survive, per ARCHITECTURE.md) is a Chromium network-layer message,
    // not an exception in the report's own script. Counting it as a JS
    // error would fail this check on the very networks it's meant to work
    // on, and axe-core's layout probing can re-trigger it on every tab.
    if (m.type() === "error" && !/Failed to load resource/i.test(m.text())) {
      errors.push(m.text());
    }
  });

  await page.goto(file, { waitUntil: "load" });
  await page.waitForTimeout(1200);
  const initialErrorCount = errors.length;

  const text = await page.evaluate(() => document.body.innerText);
  const callout = await page.evaluate(() => {
    // textContent, not innerText: this banner lives inside a <details> that
    // is collapsed by default (see "Coverage / collection notes"), and a
    // collapsed native <details>' content has no innerText even though it's
    // very much present in the markup — which is what this check verifies.
    const el = [...document.querySelectorAll(".callout")].find((e) =>
      /Incomplete collection/.test(e.textContent)
    );
    return el ? el.textContent.trim() : null;
  });
  const exclFindings = (text.match(/not role-assignable/g) || []).length;

  console.log("JS errors on initial load:", initialErrorCount ? errors.slice() : "none");
  console.log("\n--- incomplete-collection callout ---");
  console.log(callout || "(absent)");
  console.log("\n'not role-assignable' occurrences in page:", exclFindings);

  const axeSource = loadAxeSource();
  if (axeSource) await page.addScriptTag({ content: axeSource });

  const sections = await page.$$eval("#nav button[data-section]", (bs) =>
    bs.map((b) => b.dataset.section)
  );

  console.log(`\n--- per-tab checks (${sections.length} tabs) ---`);
  const tabResults = [];
  const a11yTotals = { critical: 0, serious: 0, moderate: 0, minor: 0 };

  for (const section of sections) {
    const errorsBefore = errors.length;
    await page.click(`#nav button[data-section="${section}"]`);
    await page.waitForTimeout(250);

    const state = await page.evaluate((sec) => {
      const el = document.getElementById("sec-" + sec);
      return {
        activeMatches: !!el && el.classList.contains("active"),
        textLength: el ? el.innerText.length : 0,
      };
    }, section);

    const violations = { critical: 0, serious: 0, moderate: 0, minor: 0 };
    if (axeSource) {
      try {
        const found = await page.evaluate(async () => {
          const r = await window.axe.run(document, { resultTypes: ["violations"] });
          return r.violations.map((v) => ({ impact: v.impact, nodes: v.nodes.length }));
        });
        for (const v of found) {
          if (violations[v.impact] != null) violations[v.impact] += v.nodes;
        }
      } catch (e) {
        console.warn(`  ⚠ axe run failed on ${section}: ${String(e.message || e).slice(0, 120)}`);
      }
    }
    for (const k of Object.keys(a11yTotals)) a11yTotals[k] += violations[k];

    const newErrors = errors.length - errorsBefore;
    const rendered = state.activeMatches && state.textLength >= MIN_TAB_TEXT_LENGTH;
    const ok = rendered && newErrors === 0;
    tabResults.push({ section, ...state, newErrors, violations, ok });

    console.log(
      `  ${ok ? "✓" : "✗"} ${section.padEnd(12)} text=${String(state.textLength).padStart(6)}  ` +
        `newJsErrors=${newErrors}  a11y(critical=${violations.critical} serious=${violations.serious} ` +
        `moderate=${violations.moderate} minor=${violations.minor})`
    );
  }

  const shot = path.resolve(dir, "render-check.png");
  await page.screenshot({ path: shot, fullPage: false });
  console.log("\nscreenshot:", shot);

  await browser.close();

  const legacyOk = initialErrorCount === 0 && !!callout && text.length > 2000;
  const tabsOk = tabResults.every((t) => t.ok);
  const a11yBlockingCount = a11yTotals.critical + a11yTotals.serious;

  console.log(
    `\nAccessibility (axe-core) across ${sections.length} tab(s): ` +
      `${a11yTotals.critical} critical, ${a11yTotals.serious} serious, ` +
      `${a11yTotals.moderate} moderate, ${a11yTotals.minor} minor` +
      (axeSource
        ? strictA11y
          ? " (blocking — --strict-a11y)"
          : " (report-only — pass --strict-a11y to enforce)"
        : " (scan skipped)")
  );

  const ok = legacyOk && tabsOk && (!strictA11y || a11yBlockingCount === 0);

  console.log("\n" + (ok ? "✓ dashboard rendered" : "✗ render problem"));
  if (!ok) {
    if (!legacyOk) console.log("  - initial-load check failed (JS errors, missing callout, or too little content)");
    if (!tabsOk) console.log("  - one or more tabs failed to render (see per-tab checks above)");
    if (strictA11y && a11yBlockingCount > 0)
      console.log(`  - ${a11yBlockingCount} critical/serious accessibility violation(s) (--strict-a11y)`);
  }
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
