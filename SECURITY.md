# Security Policy

## Authorized use only

Entra Collect is intended for **authorized** security assessments of Microsoft Entra ID / Microsoft 365 tenants you own or have written permission to test. Misuse against third-party tenants is prohibited.

## Handling of secrets and session data

- Collection may capture **portal session tokens** in memory and write **tenant inventory** under `output_*/`.
- Treat every `output_*` folder as **highly confidential** customer data (UPNs, role assignments, CA policies, hunting evidence).
- Browser CDP profiles (`%LOCALAPPDATA%\entra-collect`, `~/Library/Application Support/entra-collect`, etc.) hold **live cookies** — keep them outside engagement archives and never commit them.
- Do not commit `.env`, certificates, or `*.local.json`.
- Raw bearer tokens are not written to `00_token_info.json` by design; still protect the machine running the tool.

## Reporting vulnerabilities

If you find a security issue in Entra Collect itself (token handling, unsafe defaults, injection in report generation, etc.), please open a **private** GitHub security advisory on the repository, or contact the maintainer via GitHub.

Please do **not** open a public issue that includes customer tenant data, tokens, or cookies.
