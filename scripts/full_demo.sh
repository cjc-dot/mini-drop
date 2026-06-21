#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MINIDROP_RUNTIME=${MINIDROP_RUNTIME:-"$HOME/mini-drop-runtime"}
PYTHON=${PYTHON:-python3}
API_HOST=${API_HOST:-127.0.0.1}
API_PORT=${API_PORT:-8000}
SERVER_URL="http://${API_HOST}:${API_PORT}"
DEMO_RUN_AGENT=${DEMO_RUN_AGENT:-0}
DURATION=${DURATION:-5}
FREQUENCY=${FREQUENCY:-99}
AGENT_ID=${AGENT_ID:-docker-agent}
POLL_INTERVAL=${POLL_INTERVAL:-1}
LEASE_SECONDS=${LEASE_SECONDS:-60}
DIFF_OUTPUT=${DIFF_OUTPUT:-"${MINIDROP_RUNTIME}/profiles/ebpf-demo-latency-diff.json"}
BASELINE_DELAY_US=${BASELINE_DELAY_US:-50}
CURRENT_DELAY_US=${CURRENT_DELAY_US:-2000}
PYTHONPATH=${PYTHONPATH:-"${ROOT_DIR}/analysis:${ROOT_DIR}/drop:${ROOT_DIR}/apiserver"}
export MINIDROP_RUNTIME PYTHONPATH

health_check() {
  curl -fsS "${SERVER_URL}/api/health" >/dev/null 2>&1
}

require_external_agent() {
  local online_count
  online_count=$(
    curl -fsS "${SERVER_URL}/api/agents" \
      | "${PYTHON}" -c 'import json, sys; agents=json.load(sys.stdin); print(sum(1 for agent in agents if agent.get("status") == "ONLINE"))'
  )
  if [[ "${online_count}" -le 0 ]]; then
    echo "No ONLINE Agent is visible from API server."
    echo "Start Docker Compose first: make compose-up"
    echo "Then rerun: make demo"
    exit 1
  fi
}

echo "[1/5] Checking API server"
if ! health_check; then
  echo "API server is not running at ${SERVER_URL}."
  echo "For final delivery flow, start Docker Compose first: make compose-up"
  echo "For local fallback, run: DEMO_RUN_AGENT=1 make demo"
  exit 1
fi

if [[ "${DEMO_RUN_AGENT}" == "0" ]]; then
  echo "[2/5] Checking external Agent"
  require_external_agent
else
  echo "[2/5] Local Agent fallback enabled"
fi

echo "[3/5] Running perf end-to-end demo"
E2E_RUN_AGENT="${DEMO_RUN_AGENT}" \
  DURATION="${DURATION}" \
  FREQUENCY="${FREQUENCY}" \
  AGENT_ID="${AGENT_ID}" \
  POLL_INTERVAL="${POLL_INTERVAL}" \
  LEASE_SECONDS="${LEASE_SECONDS}" \
  bash "${ROOT_DIR}/scripts/e2e_demo.sh"

echo "[4/5] Running eBPF IO latency demo"
EBPF_DEMO_RUN_AGENT="${DEMO_RUN_AGENT}" \
  DURATION="${DURATION}" \
  FREQUENCY="${FREQUENCY}" \
  AGENT_ID="${AGENT_ID}" \
  POLL_INTERVAL="${POLL_INTERVAL}" \
  LEASE_SECONDS="${LEASE_SECONDS}" \
  DIFF_OUTPUT="${DIFF_OUTPUT}" \
  BASELINE_DELAY_US="${BASELINE_DELAY_US}" \
  CURRENT_DELAY_US="${CURRENT_DELAY_US}" \
  bash "${ROOT_DIR}/scripts/ebpf_demo.sh"

echo "[5/5] Mini-Drop full demo passed"
echo "Web: ${SERVER_URL}/ui"
