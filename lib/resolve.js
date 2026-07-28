/**
 * Resolve Entra object IDs → display names (users, groups, roles, apps, locations).
 * Also caches typed principal records for CapAnalyzer offline What-If packs.
 */
const WELL_KNOWN = {
  All: "All",
  None: "None",
  GuestsOrExternalUsers: "Guests or external users",
  AllTrusted: "All trusted locations",
  AllCompliantDevices: "All compliant devices",
  Office365: "Office 365",
  MicrosoftAdminPortals: "Microsoft Admin Portals",
  "00000003-0000-0ff1-ce00-000000000000": "Office 365 SharePoint Online",
};

const GUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function createResolver(graph, roleDefMap = {}) {
  const cache = new Map();
  /** @type {Map<string, object>} */
  const principalRecords = new Map();

  function rememberPrincipal(id, record) {
    if (!id || !record) return;
    const key = String(id);
    const prev = principalRecords.get(key) || {};
    principalRecords.set(key, { ...prev, ...record, id: key });
  }

  async function resolveOne(id) {
    if (id === null || id === undefined || id === "") return "";
    const key = String(id);
    if (WELL_KNOWN[key]) return WELL_KNOWN[key];
    if (roleDefMap[key]) {
      rememberPrincipal(key, {
        type: "role",
        displayName: roleDefMap[key],
      });
      return roleDefMap[key];
    }
    if (cache.has(key)) return cache.get(key);

    let label = key;
    try {
      const obj = await graph.get(`${graph.GRAPH}/directoryObjects/${key}`);
      const type = (obj["@odata.type"] || "").split(".").pop();
      if (type === "user") {
        label = `${obj.displayName || "?"} <${obj.userPrincipalName || obj.mail || key}>`;
        rememberPrincipal(key, {
          type: "user",
          displayName: obj.displayName || "",
          userPrincipalName: obj.userPrincipalName || obj.mail || "",
          userType: obj.userType || "",
          accountEnabled: obj.accountEnabled,
        });
      } else if (type === "group") {
        label = `Group: ${obj.displayName || key}`;
        rememberPrincipal(key, {
          type: "group",
          displayName: obj.displayName || "",
          securityEnabled: obj.securityEnabled,
          isAssignableToRole: obj.isAssignableToRole,
        });
      } else if (type === "servicePrincipal") {
        label = `App: ${obj.displayName || key}${obj.appId ? ` (${obj.appId})` : ""}`;
        rememberPrincipal(key, {
          type: "application",
          displayName: obj.displayName || "",
          appId: obj.appId || "",
          servicePrincipalId: obj.id || key,
        });
        if (obj.appId) {
          rememberPrincipal(obj.appId, {
            type: "application",
            displayName: obj.displayName || "",
            appId: obj.appId,
            servicePrincipalId: obj.id || key,
          });
        }
      } else {
        label = `${obj.displayName || key} [${type}]`;
        rememberPrincipal(key, {
          type: type || "directoryObject",
          displayName: obj.displayName || "",
        });
      }
    } catch {
      // Try as appId on service principal
      try {
        const sps = await graph.getAll(
          `${graph.GRAPH}/servicePrincipals?$filter=appId eq '${key}'&$select=displayName,appId,id`
        );
        if (sps && sps[0]) {
          label = `App: ${sps[0].displayName} (${key})`;
          rememberPrincipal(key, {
            type: "application",
            displayName: sps[0].displayName || "",
            appId: sps[0].appId || key,
            servicePrincipalId: sps[0].id || "",
          });
        }
      } catch {
        /* keep id */
      }
    }
    cache.set(key, label);
    return label;
  }

  async function resolveMany(ids) {
    if (!ids || !ids.length) return "";
    const parts = [];
    for (const id of ids) {
      parts.push(await resolveOne(id));
    }
    return parts.join(" | ");
  }

  function setRoleMap(map) {
    Object.assign(roleDefMap, map);
    for (const [id, name] of Object.entries(map)) {
      rememberPrincipal(id, { type: "role", displayName: name });
    }
  }

  function setLocationMap(map) {
    for (const [id, name] of Object.entries(map)) {
      cache.set(id, `Location: ${name}`);
      WELL_KNOWN[id] = `Location: ${name}`;
      rememberPrincipal(id, { type: "location", displayName: name });
    }
  }

  function getResolutions() {
    const out = {};
    for (const [id, label] of cache.entries()) {
      out[id] = label;
    }
    for (const [id, label] of Object.entries(WELL_KNOWN)) {
      if (!out[id]) out[id] = label;
    }
    for (const [id, label] of Object.entries(roleDefMap)) {
      if (!out[id]) out[id] = label;
    }
    return out;
  }

  /** Resolve list → array of labels (same order). */
  async function resolveList(ids) {
    if (!ids || !ids.length) return [];
    const out = [];
    for (const id of ids) out.push(await resolveOne(id));
    return out;
  }

  function getPrincipalRecords() {
    return Object.fromEntries(principalRecords.entries());
  }

  return {
    resolveOne,
    resolveMany,
    resolveList,
    setRoleMap,
    setLocationMap,
    getResolutions,
    getPrincipalRecords,
    cache,
    principalRecords,
    isGuid: (id) => GUID_RE.test(String(id || "")),
  };
}

module.exports = { createResolver, WELL_KNOWN, GUID_RE };
