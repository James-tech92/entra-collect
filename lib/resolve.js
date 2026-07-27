/**
 * Resolve Entra object IDs → display names (users, groups, roles, apps, locations).
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

function createResolver(graph, roleDefMap = {}) {
  const cache = new Map();

  async function resolveOne(id) {
    if (id === null || id === undefined || id === "") return "";
    const key = String(id);
    if (WELL_KNOWN[key]) return WELL_KNOWN[key];
    if (roleDefMap[key]) return roleDefMap[key];
    if (cache.has(key)) return cache.get(key);

    let label = key;
    try {
      const obj = await graph.get(
        `${graph.GRAPH}/directoryObjects/${key}`
      );
      const type = (obj["@odata.type"] || "").split(".").pop();
      if (type === "user") {
        label = `${obj.displayName || "?"} <${obj.userPrincipalName || obj.mail || key}>`;
      } else if (type === "group") {
        label = `Group: ${obj.displayName || key}`;
      } else if (type === "servicePrincipal") {
        label = `App: ${obj.displayName || key}${obj.appId ? ` (${obj.appId})` : ""}`;
      } else {
        label = `${obj.displayName || key} [${type}]`;
      }
    } catch {
      // Try as appId on service principal
      try {
        const sps = await graph.getAll(
          `${graph.GRAPH}/servicePrincipals?$filter=appId eq '${key}'&$select=displayName,appId`
        );
        if (sps && sps[0]) {
          label = `App: ${sps[0].displayName} (${key})`;
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
  }

  function setLocationMap(map) {
    for (const [id, name] of Object.entries(map)) {
      cache.set(id, `Location: ${name}`);
      WELL_KNOWN[id] = `Location: ${name}`;
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

  return {
    resolveOne,
    resolveMany,
    resolveList,
    setRoleMap,
    setLocationMap,
    getResolutions,
    cache,
  };
}

module.exports = { createResolver, WELL_KNOWN };
