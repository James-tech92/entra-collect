/**
 * Discover Defender Advanced Hunting (and related) schema, then adapt checks.
 *
 * Tables like DeviceInfo / AADSignInEventsBeta only exist when the tenant
 * streams MDE / Identity data into Defender XDR. Without them (or without
 * ThreatHunting.Read.All), hunts must fall back to Graph Entra logs / Intune.
 */
const { portalHuntReady } = require("./hunt");

const { soft, STATUS } = require("./io");

/** Tables we care about for this collector, grouped by capability. */
const HUNTING_TABLE_CATALOG = [
  // Devices / MDE
  { name: "DeviceInfo", category: "device", checks: ["windowsInventory", "patch", "rmm"] },
  { name: "DeviceProcessEvents", category: "device", checks: ["rmm", "ai"] },
  { name: "DeviceFileEvents", category: "device", checks: ["ai"] },
  { name: "DeviceNetworkEvents", category: "device", checks: ["ai"] },
  { name: "DeviceTvmSoftwareInventory", category: "device", checks: ["rmm", "ai"] },
  { name: "DeviceTvmSoftwareVulnerabilities", category: "device", checks: ["vulns", "patch"] },
  // Identity in Defender XDR
  { name: "AADSignInEventsBeta", category: "identity", checks: ["deviceCode", "legacy", "failures", "singleFactor", "tooling"] },
  {
    name: "IdentityLogonEvents",
    category: "identity",
    checks: ["deviceCode", "failures", "identityIntel"],
  },
  { name: "IdentityInfo", category: "identity", checks: ["identityIntel"] },
  { name: "IdentityAccountInfo", category: "identity", checks: ["identityIntel"] },
  // Sometimes exposed when LAW/Sentinel is linked into hunting (rare)
  { name: "SigninLogs", category: "identityLaw", checks: ["deviceCode", "legacy", "failures", "singleFactor", "tooling"] },
  { name: "AADNonInteractiveUserSignInLogs", category: "identityLaw", checks: ["deviceCode"] },
  { name: "AuditLogs", category: "identityLaw", checks: ["audit"] },
  // Email / Cloud apps / Alerts
  { name: "EmailEvents", category: "email", checks: ["antiSpam", "forwarding"] },
  { name: "CloudAppEvents", category: "cloud", checks: ["audit", "cloudGenAi", "fileSharing"] },
  { name: "AlertInfo", category: "alert", checks: ["alerts"] },
  { name: "AlertEvidence", category: "alert", checks: ["alerts"] },
  // Exposure management graph — available with or without MDE device tables
  { name: "ExposureGraphNodes", category: "exposure", checks: ["exposureGraph"] },
  { name: "ExposureGraphEdges", category: "exposure", checks: ["exposureGraph"] },
];

function classifyHuntError(err) {
  const msg = String((err && err.message) || err || "");
  const status = err && err.status;
  if (status === 403 || /Forbidden|Missing application scopes|ThreatHunting/i.test(msg)) {
    return "forbidden";
  }
  if (status === 401 || /Unauthorized/i.test(msg)) {
    return "unauthorized";
  }
  if (/Failed to resolve table or column expression named/i.test(msg)) {
    const m = msg.match(/named '([^']+)'/i);
    return { code: "table_missing", table: m ? m[1] : null };
  }
  if (/Semantic error|Query execution has failed|BadRequest|HTTP 400/i.test(msg)) {
    return "query_error";
  }
  return "other";
}

function createEmptySchema() {
  return {
    discoveredAt: new Date().toISOString(),
    canHunt: false,
    huntApiStatus: "unknown",
    huntApiDetail: "",
    tables: {}, // name -> { available, hasRows, error, category }
    availableTables: [],
    missingTables: [],
    capabilities: {},
    identitySource: null, // AADSignInEventsBeta | SigninLogs | IdentityLogonEvents | graph | none
    graphSignIns: null, // { available, detail }
    notes: [],
    has(name) {
      return !!(this.tables[name] && this.tables[name].available);
    },
    hasAny(...names) {
      return names.some((n) => this.has(n));
    },
    hasAll(...names) {
      return names.every((n) => this.has(n));
    },
  };
}

/**
 * Probe Graph Entra sign-in logs (default identity store — no LAW needed).
 */
async function probeGraphSignIns(graph, schema) {
  try {
    const url = `${graph.GRAPH_BETA}/auditLogs/signIns?$top=1&$orderby=createdDateTime desc`;
    await graph.get(url);
    schema.graphSignIns = { available: true, detail: "beta auditLogs/signIns OK" };
  } catch (e1) {
    try {
      const url = `${graph.GRAPH}/auditLogs/signIns?$top=1&$orderby=createdDateTime desc`;
      await graph.get(url);
      schema.graphSignIns = { available: true, detail: "v1.0 auditLogs/signIns OK" };
    } catch (e2) {
      schema.graphSignIns = {
        available: false,
        detail: String(e2.message || e2).split("\n")[0],
      };
    }
  }
}

/**
 * Probe a single Advanced Hunting table with `| take 1`.
 * Returns { available, hasRows, error, classification }.
 */
async function probeTable(graph, tableName) {
  try {
    const res = await graph.post(`${graph.GRAPH}/security/runHuntingQuery`, {
      Query: `${tableName}\n| take 1`,
    });
    const rows = (res && res.results) || [];
    return {
      available: true,
      hasRows: rows.length > 0,
      error: null,
      classification: "ok",
      sampleColumns: rows[0] ? Object.keys(rows[0]) : [],
    };
  } catch (e) {
    const classification = classifyHuntError(e);
    const code = typeof classification === "object" ? classification.code : classification;
    return {
      available: false,
      hasRows: false,
      error: String(e.message || e).slice(0, 400),
      classification: code,
      missingTable:
        typeof classification === "object" ? classification.table : null,
    };
  }
}

function deriveCapabilities(schema) {
  const c = {
    // MDE endpoint surface — when false, adaptive intel (alerts / exposure /
    // IdentityLogon / CloudApp) carries the security signal instead.
    mdeEndpoint: schema.has("DeviceInfo"),
    windowsInventory: schema.has("DeviceInfo"),
    patch: schema.has("DeviceInfo"),
    rmm:
      schema.has("DeviceTvmSoftwareInventory") ||
      schema.has("DeviceProcessEvents"),
    ai:
      schema.has("DeviceProcessEvents") ||
      schema.has("DeviceTvmSoftwareInventory") ||
      schema.has("DeviceFileEvents") ||
      schema.has("DeviceNetworkEvents"),
    vulns: schema.has("DeviceTvmSoftwareVulnerabilities"),
    cloudGenAi: schema.hasAny("CloudAppEvents", "DeviceNetworkEvents"),
    fileSharing: schema.hasAny("CloudAppEvents", "DeviceNetworkEvents"),
    deviceCodeHunt: schema.hasAny(
      "AADSignInEventsBeta",
      "SigninLogs",
      "IdentityLogonEvents",
      "AADNonInteractiveUserSignInLogs"
    ),
    legacyHunt: schema.hasAny("AADSignInEventsBeta", "SigninLogs"),
    // IdentityLogonEvents exposes ActionType / FailureReason — enough for
    // failed-logon bursts even when AADSignInEventsBeta is absent.
    failuresHunt: schema.hasAny(
      "AADSignInEventsBeta",
      "SigninLogs",
      "IdentityLogonEvents"
    ),
    singleFactorHunt: schema.hasAny("AADSignInEventsBeta", "SigninLogs"),
    toolingHunt: schema.hasAny(
      "AADSignInEventsBeta",
      "SigninLogs",
      "IdentityLogonEvents"
    ),
    auditHunt: schema.hasAny("CloudAppEvents", "AuditLogs"),
    antiSpam: schema.has("EmailEvents"),
    forwarding: schema.has("EmailEvents"),
    alerts: schema.hasAny("AlertInfo", "AlertEvidence"),
    exposureGraph: schema.hasAny("ExposureGraphNodes", "ExposureGraphEdges"),
    identityIntel: schema.hasAny(
      "IdentityLogonEvents",
      "IdentityInfo",
      "IdentityAccountInfo"
    ),
    graphIdentity: !!(schema.graphSignIns && schema.graphSignIns.available),
  };
  // Adaptive path: anything we can still hunt when Device* tables are gone.
  c.adaptiveIntel =
    c.alerts || c.exposureGraph || c.identityIntel || c.auditHunt || c.cloudGenAi;
  schema.capabilities = c;

  if (schema.has("AADSignInEventsBeta")) schema.identitySource = "AADSignInEventsBeta";
  else if (schema.has("SigninLogs")) schema.identitySource = "SigninLogs";
  else if (schema.has("IdentityLogonEvents")) schema.identitySource = "IdentityLogonEvents";
  else if (c.graphIdentity) schema.identitySource = "graph";
  else schema.identitySource = "none";
}

function pushSchemaFindings(schema, findings) {
  if (!schema.canHunt) {
    findings.push({
      Severity: "Info",
      Area: "HuntingSchema",
      Detail:
        `Advanced Hunting API unavailable (${schema.huntApiStatus}: ${schema.huntApiDetail || "n/a"}). ` +
        `Identity checks use Graph Entra sign-ins when possible; device/RMM/AI/patch hunts skipped. ` +
        `See 19_Hunting_Schema.json.`,
    });
  } else {
    const avail = schema.availableTables.join(", ") || "(none)";
    findings.push({
      Severity: "Info",
      Area: "HuntingSchema",
      Detail: `Hunting API OK. Tables available: ${avail}. Identity source for hunts: ${schema.identitySource}. See 19_Hunting_Schema.json.`,
    });
  }

  if (!schema.capabilities.windowsInventory && schema.canHunt) {
    const fallbacks = [];
    if (schema.capabilities.alerts) fallbacks.push("AlertInfo");
    if (schema.capabilities.exposureGraph) fallbacks.push("ExposureGraph");
    if (schema.capabilities.identityIntel) fallbacks.push("IdentityLogon/Info");
    if (schema.capabilities.auditHunt) fallbacks.push("CloudAppEvents");
    findings.push({
      Severity: fallbacks.length ? "Info" : "Medium",
      Area: "HuntingSchema",
      Detail:
        "DeviceInfo not in hunting schema — no MDE Advanced Hunting device data (or not onboarded). " +
        "RMM/AI/patch/TVM hunts skipped; Entra devices (09_*) and Intune still apply. " +
        (fallbacks.length
          ? `Adaptive intel will use: ${fallbacks.join(", ")} → see 36_*/37_*/38_*.`
          : "No Alert/Exposure/Identity hunting tables either — security signal limited to Graph."),
    });
  }
  if (schema.capabilities.adaptiveIntel && schema.canHunt) {
    findings.push({
      Severity: "Info",
      Area: "HuntingSchema",
      Detail:
        `Adaptive intel path active (mdeEndpoint=${!!schema.capabilities.mdeEndpoint}). ` +
        "Collects Defender alerts, exposure-graph critical assets and IdentityLogon signals when those tables exist — with or without MDE device tables.",
    });
  }
  if (!schema.capabilities.deviceCodeHunt && schema.canHunt) {
    findings.push({
      Severity: "Info",
      Area: "HuntingSchema",
      Detail:
        "No AADSignInEventsBeta/SigninLogs in hunting — identity hunts rely on Graph auditLogs/signIns (Entra default retention).",
    });
  }
  if (schema.graphSignIns && !schema.graphSignIns.available) {
    findings.push({
      Severity: "High",
      Area: "HuntingSchema",
      Detail: `Graph Entra sign-in logs unavailable: ${schema.graphSignIns.detail}`,
    });
  }
}

/**
 * Main entry: probe Graph + Hunting schema, save report, return schema object.
 */
async function discoverHuntingSchema(graph, io, findings) {
  console.log("── Hunting / log schema discovery");
  const schema = createEmptySchema();

  await probeGraphSignIns(graph, schema);
  console.log(
    `  · Graph sign-ins: ${
      schema.graphSignIns.available ? "available" : "unavailable"
    } (${schema.graphSignIns.detail})`
  );

  // First: can we call runHuntingQuery at all?
  // Use DeviceInfo as canary; classify 403 vs missing table.
  console.log("  · Probing Advanced Hunting API (portal apiproxy / Graph / MTP)…");
  if (portalHuntReady()) {
    console.log("  · Portal apiproxy hunting: ready");
  } else if (graph.pool && graph.pool.hasMtp && graph.pool.hasMtp()) {
    console.log(
      `  · MTP portal token(s): ${graph.pool.listMtp().length} (legacy Bearer path)`
    );
  } else {
    console.log(
      "  · No portal hunting session yet — Graph ThreatHunting.Read.All or browser hunting page required"
    );
  }
  const canary = await probeTable(graph, "DeviceInfo");

  if (canary.classification === "forbidden" || canary.classification === "unauthorized") {
    schema.canHunt = false;
    schema.huntApiStatus = canary.classification;
    schema.huntApiDetail = (canary.error || "").split("\n")[0];
    schema.tables.DeviceInfo = {
      available: false,
      hasRows: false,
      category: "device",
      error: canary.error,
      classification: canary.classification,
    };
    schema.notes.push(
      "Hunting API denied — need either (1) browser session on security.microsoft.com Advanced Hunting " +
        "(portal apiproxy; Security Reader), or (2) Graph ThreatHunting.Read.All admin consent. " +
        "Re-run collect with --auth browser --cdp after opening the hunting page."
    );
    console.log(`  · Hunting API: ${schema.huntApiStatus} — skipping table probes`);
  } else {
    schema.canHunt = true;
    schema.huntApiStatus = "ok";
    schema.huntApiDetail = canary.available
      ? "runHuntingQuery accepted (DeviceInfo present)"
      : "runHuntingQuery accepted (DeviceInfo missing — probing others)";

    // Record canary result
    schema.tables.DeviceInfo = {
      available: canary.available,
      hasRows: canary.hasRows,
      category: "device",
      error: canary.error,
      classification: canary.classification,
      sampleColumns: canary.sampleColumns || [],
    };

    // Probe remaining catalog tables (skip DeviceInfo already done)
    for (const entry of HUNTING_TABLE_CATALOG) {
      if (entry.name === "DeviceInfo") continue;
      process.stdout.write(`  · Probe ${entry.name}… `);
      const result = await probeTable(graph, entry.name);

      // If we suddenly get forbidden mid-way, stop
      if (result.classification === "forbidden" || result.classification === "unauthorized") {
        console.log(result.classification);
        schema.canHunt = false;
        schema.huntApiStatus = result.classification;
        schema.huntApiDetail = (result.error || "").split("\n")[0];
        schema.tables[entry.name] = {
          available: false,
          hasRows: false,
          category: entry.category,
          error: result.error,
          classification: result.classification,
        };
        schema.notes.push(`Stopped probing after ${entry.name}: ${result.classification}`);
        break;
      }

      schema.tables[entry.name] = {
        available: result.available,
        hasRows: result.hasRows,
        category: entry.category,
        error: result.error,
        classification: result.classification,
        sampleColumns: result.sampleColumns || [],
      };
      console.log(result.available ? (result.hasRows ? "OK (rows)" : "OK (empty)") : "missing");
    }

    // Optional: try to enumerate all tables if hunting works (best-effort, capped)
    if (schema.canHunt) {
      const listed = await soft(
        "hunt_schema_list_tables",
        () =>
          graph.post(`${graph.GRAPH}/security/runHuntingQuery`, {
            Query: `
search *
| distinct $table
| sort by $table asc
`.trim(),
          }),
        io
      );
      if (listed && listed.results && listed.results.length) {
        const names = listed.results
          .map((r) => r.$table || r.table || r.TableName || Object.values(r)[0])
          .filter(Boolean)
          .map(String);
        schema.discoveredViaSearch = names;
        for (const n of names) {
          if (!schema.tables[n]) {
            schema.tables[n] = {
              available: true,
              hasRows: true,
              category: "discovered",
              error: null,
              classification: "ok",
              via: "search_distinct",
            };
          } else {
            schema.tables[n].available = true;
          }
        }
        console.log(`  · search * discovered ${names.length} tables`);
      } else {
        schema.notes.push(
          "Could not list all tables via `search * | distinct $table` (permission, cost, or empty). Relied on catalog probes."
        );
      }
    }
  }

  schema.availableTables = Object.keys(schema.tables)
    .filter((n) => schema.tables[n].available)
    .sort();
  schema.missingTables = HUNTING_TABLE_CATALOG.map((t) => t.name).filter(
    (n) => !schema.has(n)
  );

  deriveCapabilities(schema);
  pushSchemaFindings(schema, findings);

  // Serializable copy (strip methods)
  const report = {
    discoveredAt: schema.discoveredAt,
    canHunt: schema.canHunt,
    huntApiStatus: schema.huntApiStatus,
    huntApiDetail: schema.huntApiDetail,
    graphSignIns: schema.graphSignIns,
    identitySource: schema.identitySource,
    capabilities: schema.capabilities,
    availableTables: schema.availableTables,
    missingCatalogTables: schema.missingTables,
    tables: schema.tables,
    discoveredViaSearch: schema.discoveredViaSearch || null,
    notes: schema.notes,
    logLocations: {
      entraSignInsDefault:
        "entra.microsoft.com → Monitoring → Sign-in logs (Graph auditLogs/signIns) — no Log Analytics required",
      logAnalytics:
        "Only if Entra Diagnostic settings → workspace; then SigninLogs/AuditLogs in Azure Logs / Sentinel",
      defenderHunting:
        "security.microsoft.com → Hunting — Device*/AADSignInEventsBeta only with MDE/XDR data streams",
    },
  };
  io.saveJson("19_Hunting_Schema.json", report);
  io.saveCsv(
    "19_Hunting_Schema_Tables.csv",
    Object.entries(schema.tables).map(([name, t]) => ({
      Table: name,
      Available: t.available,
      HasRows: t.hasRows,
      Category: t.category,
      Classification: t.classification || "",
      Error: (t.error || "").slice(0, 200),
    }))
  );

  console.log(
    `  · Schema: canHunt=${schema.canHunt} identity=${schema.identitySource} tables=${schema.availableTables.length}`
  );
  return schema;
}

/**
 * Prefer identity table for hunting queries.
 * Returns { table, dialect: 'aad'|'signinlogs'|'identitylogon'|null }
 */
function pickIdentityDialect(schema) {
  if (schema.has("AADSignInEventsBeta")) {
    return { table: "AADSignInEventsBeta", dialect: "aad" };
  }
  if (schema.has("SigninLogs")) {
    return { table: "SigninLogs", dialect: "signinlogs" };
  }
  if (schema.has("IdentityLogonEvents")) {
    return { table: "IdentityLogonEvents", dialect: "identitylogon" };
  }
  return { table: null, dialect: null };
}

/** Build device-code KQL for the available identity dialect. */
function kqlDeviceCode(days, dialect) {
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where AuthenticationProtocol =~ "Device Code" or AuthenticationProtocol =~ "deviceCode" or AuthenticationProtocol has "deviceCode" or ClientApp has "Device Code"
| project Timestamp, AccountUpn, Application, IPAddress, Country, City, ErrorCode, ResourceDisplayName, DeviceName, CorrelationId, AuthenticationProtocol, ClientApp
| top 2000 by Timestamp desc
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where AuthenticationProtocol =~ "deviceCode" or AuthenticationProtocol has "deviceCode" or ClientAppUsed has "Device Code" or tostring(AuthenticationDetails) has "deviceCode"
| project Timestamp=TimeGenerated, AccountUpn=UserPrincipalName, Application=AppDisplayName, IPAddress, Country=tostring(Location), City="", ErrorCode=ResultType, ResourceDisplayName, DeviceName="", CorrelationId, AuthenticationProtocol, ClientApp=ClientAppUsed
| top 2000 by Timestamp desc
`.trim();
  }
  if (dialect === "identitylogon") {
    return `
IdentityLogonEvents
| where Timestamp > ago(${days}d)
| where Protocol has "DeviceCode" or Protocol has "deviceCode" or LogonType has "Device"
| project Timestamp, AccountUpn, Application=Application, IPAddress, Country="", City="", ErrorCode=tostring(ActionType), ResourceDisplayName="", DeviceName, CorrelationId="", AuthenticationProtocol=Protocol, ClientApp=LogonType
| top 2000 by Timestamp desc
`.trim();
  }
  return null;
}

function kqlLegacySuccess(days, dialect) {
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where ClientApp has_any ("Exchange ActiveSync", "Other clients", "IMAP", "POP", "Authenticated SMTP", "MAPI")
| where ErrorCode == 0
| summarize SignIns=count(), Apps=make_set(Application), Ips=make_set(IPAddress) by AccountUpn, ClientApp
| top 200 by SignIns desc
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where ResultType == 0
| where ClientAppUsed has_any ("Exchange ActiveSync", "Other clients", "IMAP", "POP", "Authenticated SMTP", "MAPI")
| summarize SignIns=count(), Apps=make_set(AppDisplayName), Ips=make_set(IPAddress) by AccountUpn=UserPrincipalName, ClientApp=ClientAppUsed
| top 200 by SignIns desc
`.trim();
  }
  return null;
}

function kqlFailuresByIp(days, dialect) {
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where ErrorCode != 0
| summarize Failures=count(), Users=dcount(AccountUpn), SampleUsers=make_set(AccountUpn, 8) by IPAddress, Country, ErrorCode
| sort by Failures desc
| take 50
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where ResultType != 0
| summarize Failures=count(), Users=dcount(UserPrincipalName), SampleUsers=make_set(UserPrincipalName, 8) by IPAddress, Country=tostring(ResultDescription), ErrorCode=ResultType
| sort by Failures desc
| take 50
`.trim();
  }
  if (dialect === "identitylogon") {
    // IdentityLogonEvents has no ErrorCode; failures show up in ActionType /
    // FailureReason. Best-effort when AADSignInEventsBeta is missing.
    return `
IdentityLogonEvents
| where Timestamp > ago(${days}d)
| where ActionType has_any ("Failed", "LogonFailed", "LogonFailure") or isnotempty(FailureReason)
| summarize Failures=count(), Users=dcount(AccountUpn), SampleUsers=make_set(AccountUpn, 8), SampleReasons=make_set(FailureReason, 6) by IPAddress, ActionType
| sort by Failures desc
| take 50
`.trim();
  }
  return null;
}

function kqlSingleFactor(days, dialect) {
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where ErrorCode == 0
| where isnotempty(AccountUpn)
| where AuthenticationRequirement != "multiFactorAuthentication"
| where LogonType != "AppOnly"
| summarize SignIns=count(), Apps=make_set(Application), Countries=make_set(Country) by AccountUpn
| top 200 by SignIns desc
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where ResultType == 0
| where isnotempty(UserPrincipalName)
| where AuthenticationRequirement != "multiFactorAuthentication"
| summarize SignIns=count(), Apps=make_set(AppDisplayName), Countries=make_set(tostring(Location)) by AccountUpn=UserPrincipalName
| top 200 by SignIns desc
`.trim();
  }
  return null;
}

function kqlAdminTooling(days, dialect) {
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where ErrorCode == 0
| where Application has_any ("Azure Active Directory PowerShell", "Microsoft Azure CLI", "Microsoft Azure PowerShell", "Microsoft Graph Command Line Tools", "AADInternals", "Graph Explorer")
| summarize SignIns=count(), Users=make_set(AccountUpn, 12), Ips=make_set(IPAddress, 12) by Application
| sort by SignIns desc
| take 50
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where ResultType == 0
| where AppDisplayName has_any ("Azure Active Directory PowerShell", "Microsoft Azure CLI", "Microsoft Azure PowerShell", "Microsoft Graph Command Line Tools", "AADInternals", "Graph Explorer")
| summarize SignIns=count(), Users=make_set(UserPrincipalName, 12), Ips=make_set(IPAddress, 12) by Application=AppDisplayName
| sort by SignIns desc
| take 50
`.trim();
  }
  if (dialect === "identitylogon") {
    return `
IdentityLogonEvents
| where Timestamp > ago(${days}d)
| where Application has_any ("Azure Active Directory PowerShell", "Microsoft Azure CLI", "Microsoft Azure PowerShell", "Microsoft Graph Command Line Tools", "AADInternals", "Graph Explorer", "Azure Portal")
   or Protocol has_any ("OAuth", "OpenID")
| summarize SignIns=count(), Users=make_set(AccountUpn, 12), Ips=make_set(IPAddress, 12) by Application, Protocol
| sort by SignIns desc
| take 50
`.trim();
  }
  return null;
}

function kqlDeviceCodeBlocked(days, dialect) {
  if (dialect === "aad") {
    return `
AADSignInEventsBeta
| where Timestamp > ago(${days}d)
| where AuthenticationProtocol =~ "Device Code" or AuthenticationProtocol has "deviceCode"
| where ErrorCode != 0
| summarize Blocked=count(), Users=dcount(AccountUpn) by ErrorCode, Application
| top 30 by Blocked desc
`.trim();
  }
  if (dialect === "signinlogs") {
    return `
SigninLogs
| where TimeGenerated > ago(${days}d)
| where AuthenticationProtocol =~ "deviceCode" or AuthenticationProtocol has "deviceCode"
| where ResultType != 0
| summarize Blocked=count(), Users=dcount(UserPrincipalName) by ErrorCode=ResultType, Application=AppDisplayName
| top 30 by Blocked desc
`.trim();
  }
  return null;
}

/**
 * Build AI-agent union only from tables that exist.
 */
function kqlAiAgents(patternsJson, schema) {
  const branches = [];
  if (schema.has("DeviceTvmSoftwareInventory")) {
    branches.push(`(
  DeviceTvmSoftwareInventory
  | where tostring(SoftwareName) has_any (patterns) or tostring(SoftwareVendor) has_any (patterns)
  | project DeviceId, DeviceName, Signal=strcat(SoftwareVendor, " / ", SoftwareName, " ", SoftwareVersion), Source="TvmSoftwareInventory"
)`);
  }
  if (schema.has("DeviceProcessEvents")) {
    branches.push(`(
  DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName has_any (patterns) or FolderPath has_any (patterns) or ProcessCommandLine has_any (patterns)
  | summarize LastSeen=max(Timestamp), Events=count() by DeviceId, DeviceName, FileName, FolderPath, ProcessCommandLine
  | project DeviceId, DeviceName, Signal=strcat(FolderPath, "\\\\", FileName, " :: ", substring(ProcessCommandLine, 0, 120)), Source="DeviceProcessEvents"
)`);
  }
  if (schema.has("DeviceFileEvents")) {
    branches.push(`(
  DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FileName has_any (patterns) or FolderPath has_any (patterns)
  | summarize LastSeen=max(Timestamp), Events=count() by DeviceId, DeviceName, FileName, FolderPath, ActionType
  | project DeviceId, DeviceName, Signal=strcat(ActionType, " ", FolderPath, "\\\\", FileName), Source="DeviceFileEvents"
)`);
  }
  if (schema.has("DeviceNetworkEvents")) {
    branches.push(`(
  DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any (patterns) or InitiatingProcessFileName has_any (patterns) or InitiatingProcessFolderPath has_any (patterns)
  | summarize LastSeen=max(Timestamp), Events=count() by DeviceId, DeviceName, RemoteUrl, InitiatingProcessFileName
  | project DeviceId, DeviceName, Signal=strcat(InitiatingProcessFileName, " -> ", RemoteUrl), Source="DeviceNetworkEvents"
)`);
  }
  if (!branches.length) return null;

  return `
let patterns = dynamic(${patternsJson});
union
${branches.join(",\n")}
| extend Family = case(
    Signal has_any ("claude", "anthropic"), "Claude",
    Signal has_any ("hermes"), "Hermes",
    Signal has_any ("openclaw", "open-claw"), "OpenClaw",
    Signal has_any ("perplexity"), "Perplexity",
    Signal has_any ("comet"), "CometBrowser",
    Signal has_any ("chatgpt", "openai"), "ChatGPT",
    Signal has_any ("cursor"), "Cursor",
    Signal has_any ("copilot"), "GitHubCopilot",
    Signal has_any ("ollama"), "Ollama",
    Signal has_any ("lm studio", "lmstudio"), "LMStudio",
    Signal has_any ("windsurf", "codeium"), "Windsurf",
    Signal has_any ("tabnine"), "Tabnine",
    Signal has_any ("aider"), "Aider",
    Signal has_any ("cody"), "Cody",
    "OtherAI"
  )
| summarize Devices=dcount(DeviceId), Events=count(), SampleDevices=make_set(DeviceName, 8), SampleSignals=make_set(Signal, 8) by Family, Source
| sort by Devices desc
| take 200
`.trim();
}

function skipReason(schema, capability) {
  if (!schema.canHunt) {
    return `Hunting API unavailable (${schema.huntApiStatus})`;
  }
  if (!schema.capabilities[capability]) {
    return `Required tables missing for ${capability} (see 19_Hunting_Schema.json)`;
  }
  return null;
}

module.exports = {
  HUNTING_TABLE_CATALOG,
  discoverHuntingSchema,
  pickIdentityDialect,
  kqlDeviceCode,
  kqlLegacySuccess,
  kqlFailuresByIp,
  kqlSingleFactor,
  kqlAdminTooling,
  kqlDeviceCodeBlocked,
  kqlAiAgents,
  skipReason,
  classifyHuntError,
};
