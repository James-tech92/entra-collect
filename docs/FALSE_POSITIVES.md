# False positives & dismissal rules

Lessons from real tenant collections (Advanced Hunting / TVM / process telemetry).

## LogMeIn / GoTo Meeting (not RMM)

**Symptom:** TVM vendor `logmein` + software `live` or `gotomeeting_v9` on Macs → early High “RMM” findings.

**Reality:** LogMeIn rebranded to GoTo. Meeting / Live collaboration apps still appear under vendor `logmein`. They are **not** LogMeIn Rescue / Central / Pro.

**Collector behaviour (`lib/endpoints.js`):**

- RMM family `LogMeIn` matches only Rescue / Central / Pro / GoToAssist / GoToMyPC / Hamachi / Resolve / Ignition.
- `isRmmMeetingFalsePositive()` dismisses `live` / `gotomeeting_*` under vendor logmein.
- Dismissed rows → `30_RMM_Dismissed_Artefacts.csv` (Info finding), **not** High RMM prevalence.

**Extra validation used in investigations:**

- No Rescue/Central process events over 30d.
- No RMM C2 network to logmein/gotoassist.
- Optional: old `LogMeIn Installer` only under personal Google Drive sync paths = archive artefact.

## TeamViewer QuickSupport (iOS)

May be a support app, not a full RMM host. Still surfaces as low-prevalence RMM — review context (owner, process, prevalence) before treating as foothold.

## AI agent noise

Broad patterns (e.g. `copilot`, Edge WebView helpers) can inflate `31_AI_Agents_*`. Prefer family summaries over raw process rows; enterprise Copilot ≠ shadow Claude/Perplexity/LM Studio.

## Guest MFA detection (fixed)

**Bug:** Graph CA policies for guests often use `conditions.users.includeGuestsOrExternalUsers` (object), **not** `includeUsers: ["Guests"]`.

**Effect:** False High “No guest MFA CA” while `[CA20] … Guests … Require MFA` existed.

**Fix:** `lib/attackpath.js` `includesGuestsExplicit()` reads `includeGuestsOrExternalUsers.guestOrExternalUserTypes`.

## Stale SUMMARY.md

Post-process (dismiss RMM, backfill TVM, re-analyze) can leave `00_SUMMARY.md` Findings out of date. `analyzeOutputDir` now refreshes the Findings + Expert posture section from current CSVs. Prefer `00_Expert_Findings.json` / `00_REPORT.html` as source of truth.

## General rule

Elevate endpoint findings only when **inventory + process/network** (or high prevalence corporate RMM) agree. Vendor string alone is insufficient.
