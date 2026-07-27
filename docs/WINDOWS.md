# Running natively on Windows

The collector is **already Node.js + Playwright** — it runs on Windows without Wine/WSL. Collection logic (`lib/*`) is path-safe (`path.join`). What matters is the environment and auth mode.

## Prerequisites (Windows)

| Component | Why |
|---|---|
| **Node.js 18+** (LTS) | Runtime |
| **Git** (optional) | Clone / updates |
| `npm install` in `entra-collect` | Dependencies |
| `npm run setup:browser` | Only for `--browser chromium`; Edge is used by default and needs nothing |
| Desktop session | Headed browsers need an interactive Windows session (RDP OK) |

```bat
cd entra-collect
npm install
collect.cmd
```

Or:

```powershell
cd entra-collect
npm install
node collect.js --check-permissions
node collect.js --auth auto --inactive-days 90 --device-stale-months 3
```

`--browser` defaults to `auto`, which picks Edge on Windows.

## Auth modes (`--auth`)

| Mode | Behavior |
|---|---|
| **`auto` (default)** | Probe CLI Graph tokens first (`az` → Microsoft Graph PowerShell). If a usable token with **Policy.Read** / CA probe OK → **no browser**. Otherwise spawn a portal login. |
| **`cli`** | CLI only — fail if no token (no browser). |
| **`browser`** | Force Playwright portal session (previous default behaviour). |
| **`app`** | Client credentials — no interactive session, suitable for scheduled tasks. |

```bat
REM Prefer Azure CLI / MgGraph when consented; else browser
node collect.js --auth auto

REM Strict CLI (after az login or Connect-MgGraph)
node collect.js --auth cli

REM Always browser (no CLI consent needed)
node collect.js --auth browser
```

### Preparing CLI Graph access

When admin consent is available for one of:

1. **Azure CLI** (recommended on Windows jump hosts)
   ```bat
   az login
   az account get-access-token --resource-type ms-graph --query accessToken -o tsv
   ```
2. **Microsoft Graph PowerShell**
   ```powershell
   Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
   Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","User.Read.All","AuditLog.Read.All","IdentityRiskEvent.Read.All","SecurityEvents.Read.All","ThreatHunting.Read.All"
   ```
3. **App registration** (best for scheduled or unattended runs)
   ```bat
   node collect.js --auth app --tenant TENANT --client-id APP --client-secret %ENTRA_CLIENT_SECRET%
   ```

`mgc` (Microsoft Graph CLI) is detected but **cannot be used as a token source** —
it has no command that exports a bearer token.

Note on `az`: its Graph token carries the Azure CLI first-party scope set, which
does **not** include `ThreatHunting.Read.All`. All Defender hunts (RMM, Shadow AI,
GenAI, TVM, patch lag) are unavailable in that mode. Use `Connect-MgGraph` with
the scopes above, an app registration, or the browser path.

If the CLI token lacks `Policy.Read.*`, `--auth auto` falls back to the browser so
CA collection still works. Run `node collect.js --check-permissions` first to see
exactly which areas your session covers.

## Windows-specific notes

| Topic | Detail |
|---|---|
| Paths with spaces | Supported (`path.join`); quote paths in `.cmd` |
| Press Enter after MFA | Works in `cmd.exe` and PowerShell |
| Headless | `--headless` possible but MFA usually needs headed |
| Antivirus | May quarantine Playwright Chromium — allowlist if install fails |
| Corporate proxy | Set `HTTPS_PROXY` / `HTTP_PROXY` for Node + Playwright |
| Execution policy | `collect.cmd` uses `node` only — no PowerShell script signing required |
| Line endings | Prefer LF in git; Node tolerates CRLF |

## CDP + Edge (passkey / Authenticator) — recommended on Windows

Same pattern as macOS `login-edge.sh`: a **dedicated** Edge profile so `--remote-debugging-port` works on Edge 136+.

```bat
cd entra-collect
login-edge.cmd
REM optional: login-edge.cmd 9223 https://security.microsoft.com

REM After sign-in in that Edge window:
node collect.js --auth browser --cdp http://127.0.0.1:9222
```

| Topic | Detail |
|---|---|
| Profile | `%LOCALAPPDATA%\entra-collect\profiles\msedge-cdp` — deliberately **outside** the tool folder, since it holds live tenant session cookies. Override with `ENTRA_COLLECT_PROFILE_DIR`. |
| MFA | Windows Hello, Authenticator push, or QR — depends on device Bluetooth / phone |
| Portal hunting | Attach keeps Security portal session → Advanced Hunting apiproxy |
| Antivirus | May prompt on Playwright / Edge flags — allowlist if needed |

Without CDP, `node collect.js --auth browser` still works via Playwright-launched Edge/Chromium (`--browser msedge`).

## What is *not* required for Windows

- WSL / Docker
- Graph PowerShell for the **browser** path (portal tokens)
- Admin rights on the workstation (user install of Node + Playwright is enough)

## Smoke-test CLI probe only

```bat
node -e "console.log(JSON.stringify(require('./lib/auth-cli').probeCliGraphAuth(),null,2))"
```

Shows which providers are available and whether a Graph JWT was obtained (token value not printed in summary beyond metadata).

## Smoke-test `login-edge.cmd` (CDP)

On a Windows desktop with Edge installed:

```bat
cd entra-collect
login-edge.cmd
curl -s http://127.0.0.1:9222/json/version
REM Expect JSON with "Browser" / "webSocketDebuggerUrl"
node collect.js --auth browser --cdp http://127.0.0.1:9222 --no-wait-enter
```

If port 9222 already answers CDP, `login-edge.cmd` exits 0 and prints the collect command (does not start a second Edge). Profile dir: `%LOCALAPPDATA%\entra-collect\profiles\msedge-cdp`.

## Smoke-test the test suite

```bat
npm test
```

Covers the retry layer, token expiry/renewal, the artifact manifest and the
resume cache. No network or tenant access required.

## Architecture reminder

See [ARCHITECTURE.md](ARCHITECTURE.md). Short version:

```
--auth auto
    │
    ├─ az / MgGraph / mgc  ──token──▶ TokenPool ──▶ runCollection
    │
    └─ browser / login-edge.cmd --cdp ──▶ TokenPool + portal hunting ──▶ runCollection
```

Collection and reporting are auth-agnostic. Docs index: [FALSE_POSITIVES.md](FALSE_POSITIVES.md), [ANALYZER.md](ANALYZER.md).
