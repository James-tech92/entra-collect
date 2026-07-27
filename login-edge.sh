#!/usr/bin/env bash
# Kept for muscle memory — login-browser.sh supersedes this and also works on
# Linux. Forces Edge to preserve the previous behaviour.
set -euo pipefail
exec "$(cd "$(dirname "$0")" && pwd)/login-browser.sh" "${1:-9222}" "${2:-https://entra.microsoft.com}" msedge
