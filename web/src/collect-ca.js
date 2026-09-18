/**
 * Conditional Access collection — first collection slice ported to the web
 * app (highest signal, no MDE dependency). Mirrors the shape of the
 * `02_CA_Audit.csv` rows lib/collection.js writes, minus the CapAnalyzer
 * bundle and device-code-specific split, which can follow later.
 */
import { createGraph } from "../../lib/graph.js";
import { createResolver } from "../../lib/resolve.js";

export async function collectConditionalAccess(pool, { onProgress } = {}) {
  const graph = createGraph(pool);
  const progress = onProgress || (() => {});

  progress("Role definitions…");
  const roleDefs = await graph.getAll(`${graph.GRAPH}/roleManagement/directory/roleDefinitions`);
  const roleDefMap = {};
  for (const d of roleDefs || []) roleDefMap[d.id] = d.displayName;

  const resolver = createResolver(graph, roleDefMap);

  progress("Named locations…");
  const namedLocs = await graph.getAll(
    `${graph.GRAPH}/identity/conditionalAccess/namedLocations`
  );
  const locMap = {};
  for (const l of namedLocs || []) locMap[l.id] = l.displayName;
  resolver.setLocationMap(locMap);

  progress("Conditional Access policies (resolving object names…)");
  const policies = await graph.getAll(`${graph.GRAPH}/identity/conditionalAccess/policies`);

  const rows = [];
  for (const p of policies || []) {
    const u = (p.conditions && p.conditions.users) || {};
    const a = (p.conditions && p.conditions.applications) || {};
    const loc = (p.conditions && p.conditions.locations) || {};
    const grant = (p.grantControls && p.grantControls.builtInControls) || [];
    const clients = (p.conditions && p.conditions.clientAppTypes) || [];
    const authFlows =
      p.conditions && p.conditions.authenticationFlows && p.conditions.authenticationFlows.transferMethods;

    const isEnforced = p.state === "enabled";
    const isReportOnly = p.state === "enabledForReportingButNotEnforced";
    const riskFlags = [];
    if (isReportOnly) riskFlags.push("NOT ENFORCED (report-only)");
    if (
      p.grantControls &&
      p.grantControls.operator === "OR" &&
      grant.includes("compliantDevice") &&
      grant.includes("mfa")
    ) {
      riskFlags.push("OR grant: MFA alone can bypass compliant device");
    }

    rows.push({
      PolicyName: p.displayName,
      State: p.state,
      IsEnforced: isEnforced ? "Yes" : isReportOnly ? "Report-only" : "Disabled",
      GrantControls: grant.join(", "),
      GrantOperator: (p.grantControls && p.grantControls.operator) || "",
      IncludeUsers: (await resolver.resolveList(u.includeUsers || [])).join(" | "),
      ExcludeUsers: (await resolver.resolveList(u.excludeUsers || [])).join(" | "),
      IncludeGroups: (await resolver.resolveList(u.includeGroups || [])).join(" | "),
      ExcludeGroups: (await resolver.resolveList(u.excludeGroups || [])).join(" | "),
      IncludeRoles: (await resolver.resolveList(u.includeRoles || [])).join(" | "),
      ExcludeRoles: (await resolver.resolveList(u.excludeRoles || [])).join(" | "),
      IncludeApps: (await resolver.resolveList(a.includeApplications || [])).join(" | "),
      ExcludeApps: (await resolver.resolveList(a.excludeApplications || [])).join(" | "),
      IncludeLocations: (await resolver.resolveList(loc.includeLocations || [])).join(" | "),
      ExcludeLocations: (await resolver.resolveList(loc.excludeLocations || [])).join(" | "),
      ClientAppTypes: clients.join(", "),
      AuthFlows: authFlows || "",
      SignInRisk: ((p.conditions && p.conditions.signInRiskLevels) || []).join(", "),
      UserRisk: ((p.conditions && p.conditions.userRiskLevels) || []).join(", "),
      RiskFlags: riskFlags.join(" | "),
    });
  }

  return {
    rows,
    total: rows.length,
    enforced: rows.filter((r) => r.IsEnforced === "Yes").length,
    reportOnly: rows.filter((r) => r.IsEnforced === "Report-only").length,
    namedLocationsCount: (namedLocs || []).length,
  };
}
