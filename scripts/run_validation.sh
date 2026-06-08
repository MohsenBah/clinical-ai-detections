#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOGTEST_BIN="${LOGTEST_BIN:-/var/ossec/bin/wazuh-logtest}"

cd "${REPO_ROOT}"

if [[ "${1:-}" == "--wazuh" ]] || [[ -x "${LOGTEST_BIN}" ]]; then
  echo "Running validation with wazuh-logtest (${LOGTEST_BIN})..."
  python3 "${SCRIPT_DIR}/validate_rules.py" --wazuh --logtest-bin "${LOGTEST_BIN}"
else
  echo "Running offline validation (no wazuh-logtest found)..."
  python3 "${SCRIPT_DIR}/validate_rules.py" --offline
fi
