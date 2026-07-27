/**
 * Microsoft Secure Score helpers.
 *
 * Important: secureScoreControlProfiles lists hundreds of controls (including
 * products the tenant is not scored on). The live tenant score only includes
 * controlScores[] on /security/secureScores — typically ~70 rows. Always prefer
 * that in-scope set for gaps / categories / report UI.
 */

function stripHtml(s) {
  return String(s || "")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&ldquo;|&rdquo;|&#8220;|&#8221;/gi, '"')
    .replace(/&lsquo;|&rsquo;|&#8216;|&#8217;/gi, "'")
    .replace(/&#(\d+);/g, (_, n) => {
      const c = Number(n);
      return Number.isFinite(c) ? String.fromCharCode(c) : "";
    })
    .replace(/&[a-z]+;/gi, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

/**
 * Merge live controlScores with control profiles → in-scope control rows.
 * @param {object|null} latestScore 10_secure_score_latest.json entity
 * @param {object[]|null} profiles 10_secure_score_control_profiles.json array
 */
function buildInScopeControls(latestScore, profiles) {
  const scoreEntity = Array.isArray(latestScore)
    ? latestScore[0]
    : latestScore && latestScore.value
      ? latestScore.value[0]
      : latestScore;
  const scores = (scoreEntity && scoreEntity.controlScores) || [];
  if (!scores.length) return [];

  const profList = Array.isArray(profiles)
    ? profiles
    : (profiles && profiles.value) || [];
  const byId = new Map();
  const byTitle = new Map();
  for (const p of profList) {
    if (p.id) byId.set(String(p.id).toLowerCase(), p);
    if (p.title) byTitle.set(String(p.title).toLowerCase(), p);
  }

  return scores.map((c) => {
    const name = c.controlName || "";
    const cat = c.controlCategory || "Other";
    const score = num(c.score);
    const pct = num(c.scoreInPercentage);
    const p =
      byId.get(String(name).toLowerCase()) ||
      byTitle.get(String(c.description || "").toLowerCase()) ||
      null;
    let maxScore = num(p && p.maxScore);
    if (maxScore <= 0 && pct > 0) {
      maxScore = Math.round((score / (pct / 100)) * 100) / 100;
    }
    if (maxScore <= 0) maxScore = score;
    const gap = Math.round(Math.max(0, maxScore - score) * 100) / 100;
    const status =
      gap <= 0.05 || pct >= 99.5
        ? "Complete"
        : score > 0
          ? "Partial"
          : "Open";
    return {
      ControlId: name,
      Title: (p && p.title) || c.description || name,
      Category: cat,
      Service: (p && p.service) || cat,
      CurrentScore: Math.round(score * 100) / 100,
      MaxScore: Math.round(maxScore * 100) / 100,
      GapPoints: gap,
      Pct: Math.round(pct * 10) / 10,
      Status: status,
      UserImpact: (p && p.userImpact) || "",
      Tier: (p && p.tier) || "",
      Threats: Array.isArray(p && p.threats) ? p.threats.join(", ") : "",
      Remediation: stripHtml((p && p.remediation) || "").slice(0, 400),
    };
  });
}

function buildCategoryRollup(controls) {
  const by = new Map();
  for (const c of controls || []) {
    const cat = c.Category || "Other";
    if (!by.has(cat)) {
      by.set(cat, {
        Category: cat,
        Score: 0,
        Max: 0,
        Gap: 0,
        Open: 0,
        Partial: 0,
        Complete: 0,
        Total: 0,
      });
    }
    const row = by.get(cat);
    row.Score += num(c.CurrentScore);
    row.Max += num(c.MaxScore);
    row.Gap += num(c.GapPoints);
    row.Total += 1;
    if (c.Status === "Open") row.Open += 1;
    else if (c.Status === "Partial") row.Partial += 1;
    else row.Complete += 1;
  }
  return [...by.values()]
    .map((r) => ({
      ...r,
      Score: Math.round(r.Score * 100) / 100,
      Max: Math.round(r.Max * 100) / 100,
      Gap: Math.round(r.Gap * 100) / 100,
    }))
    .sort((a, b) => b.Gap - a.Gap || a.Category.localeCompare(b.Category));
}

/**
 * Report/analyzer payload: prefer in-scope controls; fall back carefully.
 */
function buildSecureScoreExplorer(controls) {
  const rows = (controls || [])
    .map((r) => ({
      ControlId: r.ControlId || r.Id || "",
      Title: r.Title || r.Id || "",
      Category: r.Category || r.Service || "Other",
      Service: r.Service || "",
      CurrentScore: num(r.CurrentScore),
      MaxScore: num(r.MaxScore),
      GapPoints: num(
        r.GapPoints != null
          ? r.GapPoints
          : num(r.MaxScore) - num(r.CurrentScore)
      ),
      Pct: num(r.Pct),
      Status:
        r.Status ||
        (num(r.MaxScore) - num(r.CurrentScore) <= 0.05
          ? "Complete"
          : num(r.CurrentScore) > 0
            ? "Partial"
            : "Open"),
      UserImpact: r.UserImpact
        ? r.UserImpact.charAt(0).toUpperCase() +
          r.UserImpact.slice(1).toLowerCase()
        : "",
      Tier: r.Tier || "",
      Threats: r.Threats || "",
      Remediation: stripHtml(r.Remediation || "").slice(0, 400),
    }))
    .filter((r) => r.MaxScore > 0 || r.CurrentScore > 0);

  const open = rows
    .filter((r) => r.Status !== "Complete" && r.GapPoints > 0.05)
    .sort((a, b) => b.GapPoints - a.GapPoints);

  const categories = buildCategoryRollup(rows);
  return {
    controls: rows,
    openControls: open,
    categories,
    openCount: open.length,
    openPoints: Math.round(open.reduce((s, r) => s + r.GapPoints, 0) * 100) / 100,
    controlCount: rows.length,
  };
}

module.exports = {
  stripHtml,
  buildInScopeControls,
  buildCategoryRollup,
  buildSecureScoreExplorer,
};
