/**
 * Renders 00_REPORT.html in a real browser and asserts the dashboard actually
 * built. The report is ~100% client-side, so a syntax error in the embedded
 * script produces a blank page that no server-side test would catch.
 *
 *   node test/render-check.js <output_dir>
 */
const path = require("path");
const { chromium } = require("playwright");

async function main() {
  const dir = process.argv[2];
  if (!dir) {
    console.error("usage: node test/render-check.js <output_dir>");
    process.exit(2);
  }
  const file = "file://" + path.resolve(dir, "00_REPORT.html");

  // Playwright's own Chromium is an optional install here, so fall back to any
  // Chromium-family browser already on the machine.
  let browser;
  for (const channel of [undefined, "msedge", "chrome", "chromium"]) {
    try {
      browser = await chromium.launch(channel ? { channel } : {});
      break;
    } catch {
      /* try the next one */
    }
  }
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
    if (m.type() === "error") errors.push(m.text());
  });

  await page.goto(file, { waitUntil: "load" });
  await page.waitForTimeout(1200);

  const text = await page.evaluate(() => document.body.innerText);
  const callout = await page.evaluate(() => {
    const el = [...document.querySelectorAll(".callout")].find((e) =>
      /Incomplete collection/.test(e.innerText)
    );
    return el ? el.innerText : null;
  });
  const exclFindings = (text.match(/not role-assignable/g) || []).length;

  console.log("JS errors:", errors.length ? errors : "none");
  console.log("\n--- incomplete-collection callout ---");
  console.log(callout || "(absent)");
  console.log("\n'not role-assignable' occurrences in page:", exclFindings);

  const shot = path.resolve(dir, "render-check.png");
  await page.screenshot({ path: shot, fullPage: false });
  console.log("screenshot:", shot);

  await browser.close();

  const ok = errors.length === 0 && callout && text.length > 2000;
  console.log("\n" + (ok ? "✓ dashboard rendered" : "✗ render problem"));
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
