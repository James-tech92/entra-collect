/**
 * Tenant-agnostic RMM hit classification.
 * Goal: keep real remote-access agents in the signal path, and mark common
 * inventory noise (mobile BYOD clients, outbound viewers, QuickSupport add-ons)
 * so analyzer / collector can de-prioritize them across tenants.
 */

const NOISE_CLASSES = new Set(["mobile", "viewer", "adhoc", "meeting"]);

function blobOf(parts) {
  return parts
    .filter(Boolean)
    .map((p) => String(p))
    .join(" ")
    .toLowerCase()
    .replace(/[\\/]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Classify a single RMM inventory / process hit.
 * @returns {{ class: string, signal: boolean, weight: number, note: string }}
 */
function classifyRmmHit(input = {}) {
  const family = String(input.family || input.Family || "");
  const evidence = String(
    input.evidence ||
      input.EvidenceTrace ||
      input.Evidence ||
      input.evidenceTrace ||
      ""
  );
  const software =
    input.softwareName ||
    input.SoftwareName ||
    // TVM lines look like: "TVM inventory: vendor / software_name 1.2.3"
    (evidence.match(/tvm inventory:\s*[^/]+\/\s*(\S+)/i) || [])[1] ||
    "";
  const vendor =
    input.vendor ||
    input.SoftwareVendor ||
    (evidence.match(/tvm inventory:\s*([^/]+)\//i) || [])[1] ||
    "";
  const deviceName = String(input.deviceName || input.DeviceName || "");
  const os = String(input.osPlatform || input.OSPlatform || "");
  // Prefer software/evidence for role detection — family labels like
  // "UltraVNC" / "RealVNC" must not flip a *_viewer package into "server".
  const softBlob = blobOf([vendor, software, evidence, deviceName, os]);
  const fam = family.toLowerCase();

  // Collaboration under LogMeIn/GoTo brand (already dismissed in collector).
  if (
    /\b(gotomeeting|goto_meeting|gotowebinar|goto webinar|goto training|goto_opener|logmein live)\b/.test(
      softBlob
    )
  ) {
    return {
      class: "meeting",
      signal: false,
      weight: 0,
      note: "Meeting / collaboration artefact — not remote-admin RMM",
    };
  }

  // Mobile / BYOD clients — very common, rarely a Windows foothold story.
  if (
    /\b(android|iphone|ipad|_ios\b|for_android|for_ios|teamviewer_for_android|anydesk_for_android)\b/.test(
      softBlob
    ) ||
    /_android\b/i.test(deviceName)
  ) {
    return {
      class: "mobile",
      signal: false,
      weight: 0,
      note: "Mobile/BYOD remote-access client",
    };
  }

  // Outbound viewers (user connects TO something) ≠ host agent foothold.
  const looksViewer =
    /\b(vnc[_\s-]?viewer|realvnc[_\s-]?viewer|rvnc[_\s-]?viewer|tightvnc[_\s-]?viewer|ultravnc[_\s-]?viewer|viewer\.exe)\b/.test(
      softBlob
    );
  const looksServer =
    /\b(vnc[_\s-]?server|winvnc|winvnc4|tvnserver|streamer|remoting_host|datto_rmm|screenconnect)\b/.test(
      softBlob
    ) ||
    (/\bultravnc\b/.test(softBlob) && !looksViewer);
  if (looksViewer && !looksServer) {
    return {
      class: "viewer",
      signal: false,
      weight: 0,
      note: "Outbound remote viewer client (not a host agent)",
    };
  }
  // Family RealVNC with no server token → treat ambiguous inventory as viewer-leaning noise.
  if (/^realvnc$/i.test(family) && !looksServer) {
    return {
      class: "viewer",
      signal: false,
      weight: 0,
      note: "RealVNC inventory without server/host component — treat as viewer unless proven otherwise",
    };
  }

  // Ad-hoc support helpers / browser add-ons — not persistent fleet RMM.
  if (
    /\b(quicksupport|teamviewer\s*qs|tvqs|complemento_universal|universal[_\s-]?add-?on|add-?on)\b/.test(
      softBlob
    )
  ) {
    return {
      class: "adhoc",
      signal: false,
      weight: 1,
      note: "Ad-hoc QuickSupport / add-on (not full persistent agent)",
    };
  }

  // Explicit high-signal host/agent components (MSP + consumer remote access).
  if (
    /\b(streamer|screenconnect|connectwise|centrastage|datto_rmm|datto rmm|ninjarmm|ninja rmm|meshagent|mesh central|rustdesk|atera|kaseya|labtech|ltagent|bomgar|beyondtrust|remoting_host|chrome.?remote.?desktop|action1|pulseway|dwagent|level-windows|gotomypc|logmeinrescue|logmein.?central|logmein.?pro|supremo|remotepc)\b/.test(
      softBlob
    )
  ) {
    return {
      class: "agent",
      signal: true,
      weight: 3,
      note: "Remote-access agent / host component",
    };
  }

  // Desktop AnyDesk / TeamViewer full product (not android / quicksupport — already filtered).
  if (
    /\banydesk\b/.test(softBlob) ||
    (/\bteamviewer\b/.test(softBlob) &&
      !/quicksupport|add-?on|complemento/.test(softBlob))
  ) {
    return {
      class: "agent",
      signal: true,
      weight: 2,
      note: "Desktop remote-access software (full client/host)",
    };
  }

  // UltraVNC / TightVNC host-side (viewer already returned above).
  if (/\b(ultravnc|tightvnc|winvnc|uvnc)\b/.test(softBlob) && !looksViewer) {
    return {
      class: "agent",
      signal: true,
      weight: 3,
      note: "VNC host / UltraVNC-style remote admin",
    };
  }

  // Family defaults for known MSP stacks when software string is sparse.
  if (
    /^(splashtop|datto|ninjarmm|atera|kaseya|screenconnect|connectwise|rustdesk|meshcentral|action1|pulseway|levelrmm|beyondtrust|logmein|chromeremotedesktop|supremo|remotepc|dwservice)$/i.test(
      fam
    )
  ) {
    return {
      class: "agent",
      signal: true,
      weight: 3,
      note: `Family default — ${family} treated as agent/host tooling`,
    };
  }
  if (/^(anydesk|teamviewer|ultravnc|tightvnc)$/i.test(fam) && !looksViewer) {
    return {
      class: "agent",
      signal: true,
      weight: 2,
      note: `Family default — ${family} desktop remote access`,
    };
  }

  return {
    class: "unknown",
    signal: true,
    weight: 2,
    note: "Unclassified remote tool — review as potential agent",
  };
}

function isNoiseClass(cls) {
  return NOISE_CLASSES.has(String(cls || "").toLowerCase());
}

/**
 * Enrich asset rows with RiskClass / Signal / RiskNote.
 * Prefer existing columns when a fresh collect already wrote them.
 * When EvidenceTrace has multiple lines, keep the strongest (highest weight / signal).
 */
function enrichRmmAssets(assets = []) {
  return (assets || []).map((a) => {
    if (a.RiskClass && a.Signal != null && String(a.Signal).length) {
      return {
        ...a,
        RiskClass: a.RiskClass,
        Signal: /^(1|true|yes|y)$/i.test(String(a.Signal)),
        RiskNote: a.RiskNote || "",
      };
    }
    const traces = String(a.EvidenceTrace || a.Evidence || "")
      .split(/\s*\|\|\s*/)
      .map((t) => t.trim())
      .filter(Boolean);
    const candidates = (traces.length ? traces : [""]).map((evidence) =>
      classifyRmmHit({ ...a, evidence, EvidenceTrace: evidence, Evidence: evidence })
    );
    candidates.sort(
      (x, y) =>
        Number(y.signal) - Number(x.signal) ||
        Number(y.weight) - Number(x.weight)
    );
    const c = candidates[0];
    return {
      ...a,
      RiskClass: c.class,
      Signal: c.signal,
      RiskNote: c.note,
    };
  });
}

/**
 * Roll up family stats from enriched assets.
 * @returns {Map<string, object>}
 */
function summarizeRmmByFamily(enrichedAssets = []) {
  const byFam = new Map();
  for (const a of enrichedAssets) {
    const fam = a.Family || "?";
    if (!byFam.has(fam)) {
      byFam.set(fam, {
        Family: fam,
        Devices: 0,
        AgentDevices: 0,
        NoiseDevices: 0,
        MobileDevices: 0,
        ViewerDevices: 0,
        AdhocDevices: 0,
        UnknownDevices: 0,
        agentSamples: [],
        noiseSamples: [],
      });
    }
    const s = byFam.get(fam);
    s.Devices += 1;
    if (a.Signal) {
      s.AgentDevices += 1;
      if (s.agentSamples.length < 12) {
        s.agentSamples.push(a);
      }
    } else {
      s.NoiseDevices += 1;
      if (a.RiskClass === "mobile") s.MobileDevices += 1;
      else if (a.RiskClass === "viewer") s.ViewerDevices += 1;
      else if (a.RiskClass === "adhoc") s.AdhocDevices += 1;
      if (s.noiseSamples.length < 6) s.noiseSamples.push(a);
    }
    if (a.RiskClass === "unknown") s.UnknownDevices += 1;
  }
  return byFam;
}

function formatAssetLine(a) {
  const host = a.DeviceName || a.DeviceId || "?";
  const owner =
    a.Owners ||
    a.OwnersUPN ||
    a.LoggedOnUsers ||
    a.ProcessAccount ||
    "(owner unknown)";
  const trace =
    a.EvidenceTrace ||
    a.Evidence ||
    [a.Source, a.Evidence].filter(Boolean).join(": ");
  const tag = a.RiskClass ? `[${a.RiskClass}]` : "";
  return `${a.Family || "?"}${tag}: ${host} → ${owner} · ${trace}`;
}

module.exports = {
  classifyRmmHit,
  enrichRmmAssets,
  summarizeRmmByFamily,
  isNoiseClass,
  formatAssetLine,
  NOISE_CLASSES,
};
