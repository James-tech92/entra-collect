/**
 * Where throw-away browser profiles and auth caches live.
 *
 * Kept OUT of the tool directory on purpose: this location stores the
 * customer's portal session cookies (browser profiles) and, optionally, an
 * encrypted MSAL token cache — both belong next to the OS's own credential
 * storage, not inside a folder that ends up in every zip, clone and backup
 * of the engagement repo.
 */
const path = require("path");
const os = require("os");

function resolveProfileRoot() {
  if (process.env.ENTRA_COLLECT_PROFILE_DIR) {
    return process.env.ENTRA_COLLECT_PROFILE_DIR;
  }
  const base =
    process.platform === "win32"
      ? process.env.LOCALAPPDATA || os.tmpdir()
      : process.platform === "darwin"
        ? path.join(os.homedir(), "Library", "Application Support")
        : process.env.XDG_STATE_HOME || path.join(os.homedir(), ".local", "state");
  return path.join(base, "entra-collect", "profiles");
}

function resolveUserDataDir(name) {
  return path.join(resolveProfileRoot(), name);
}

module.exports = { resolveProfileRoot, resolveUserDataDir };
