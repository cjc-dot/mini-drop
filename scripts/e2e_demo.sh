#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
MINIDROP_RUNTIME=${MINIDROP_RUNTIME:-"$HOME/mini-drop-runtime"}
PYTHON=${PYTHON:-python3}
API_HOST=${API_HOST:-127.0.0.1}
API_PORT=${API_PORT:-8000}
SERVER_URL="http://${API_HOST}:${API_PORT}"
DURATION=${DURATION:-5}
FREQUENCY=${FREQUENCY:-99}
COLLECTOR=${COLLECTOR:-perf}
AGENT_ID=${AGENT_ID:-demo-agent}
E2E_RUN_AGENT=${E2E_RUN_AGENT:-1}
POLL_INTERVAL=${POLL_INTERVAL:-1}
LEASE_SECONDS=${LEASE_SECONDS:-60}
PYTHONPATH=${PYTHONPATH:-"${ROOT_DIR}/analysis:${ROOT_DIR}/drop:${ROOT_DIR}/apiserver"}
export MINIDROP_RUNTIME PYTHONPATH

API_PID=""
WORKLOAD_PID=""

cleanup() {
  if [[ -n "${WORKLOAD_PID}" ]] && kill -0 "${WORKLOAD_PID}" >/dev/null 2>&1; then
    kill "${WORKLOAD_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${API_PID}" ]] && kill -0 "${API_PID}" >/dev/null 2>&1; then
    kill "${API_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

json_get() {
  local expr=$1
  "${PYTHON}" -c 'import json, sys; data=json.load(sys.stdin); print(eval(sys.argv[1], {}, {"data": data}))' "${expr}"
}

health_check() {
  curl -fsS "${SERVER_URL}/api/health" >/dev/null 2>&1
}

job_status() {
  curl -fsS "${SERVER_URL}/api/jobs/${JOB_ID}" | json_get 'data["status"]'
}

wait_for_done() {
  local status
  for _ in $(seq 1 180); do
    status=$(job_status)
    case "${status}" in
      DONE)
        return 0
        ;;
      FAILED)
        echo "job ${JOB_ID} failed"
        curl -fsS "${SERVER_URL}/api/jobs/${JOB_ID}" || true
        return 1
        ;;
    esac
    sleep 1
  done
  echo "timed out waiting for job ${JOB_ID}"
  curl -fsS "${SERVER_URL}/api/jobs/${JOB_ID}" || true
  return 1
}

verify_artifact() {
  local artifact_name=$1
  local output_file="${MINIDROP_RUNTIME}/tmp/e2e_${JOB_ID}_${artifact_name}"
  local http_code
  http_code=$(
    curl -fsS \
      -o "${output_file}" \
      -w "%{http_code}" \
      "${SERVER_URL}/api/jobs/${JOB_ID}/artifacts/${artifact_name}"
  )
  if [[ "${http_code}" != "200" || ! -s "${output_file}" ]]; then
    echo "artifact ${artifact_name} is not available through API"
    return 1
  fi
}

mkdir -p "${MINIDROP_RUNTIME}/logs"
mkdir -p "${MINIDROP_RUNTIME}/profiles"
mkdir -p "${MINIDROP_RUNTIME}/jobs"
mkdir -p "${MINIDROP_RUNTIME}/tmp"

echo "[1/6] Checking API server at ${SERVER_URL}"
if health_check; then
  echo "API server is already running"
else
  echo "Starting API server"
  "${PYTHON}" -m minidrop_apiserver \
    --host "${API_HOST}" \
    --port "${API_PORT}" \
    --runtime-dir "${MINIDROP_RUNTIME}" \
    > "${MINIDROP_RUNTIME}/logs/e2e_api.log" 2>&1 &
  API_PID=$!

  for _ in $(seq 1 50); do
    if health_check; then
      break
    fi
    sleep 0.2
  done

  if ! health_check; then
    echo "API server failed to start. Log:"
    tail -n 80 "${MINIDROP_RUNTIME}/logs/e2e_api.log" || true
    exit 1
  fi
fi

echo "[2/6] Starting workload"
"${MINIDROP_RUNTIME}/builds/cpu_hotspot" \
  > "${MINIDROP_RUNTIME}/logs/e2e_cpu_hotspot.log" 2>&1 &
WORKLOAD_PID=$!
sleep 1

if ! kill -0 "${WORKLOAD_PID}" >/dev/null 2>&1; then
  echo "workload process exited unexpectedly"
  tail -n 80 "${MINIDROP_RUNTIME}/logs/e2e_cpu_hotspot.log" || true
  exit 1
fi
echo "workload pid=${WORKLOAD_PID}"
export WORKLOAD_PID DURATION FREQUENCY COLLECTOR

echo "[3/6] Creating ${COLLECTOR} job through API"
CREATE_BODY=$(
  "${PYTHON}" -c 'import json, os; print(json.dumps({
    "pid": int(os.environ["WORKLOAD_PID"]),
    "duration_seconds": int(os.environ["DURATION"]),
    "sample_frequency": int(os.environ["FREQUENCY"]),
    "collector": os.environ["COLLECTOR"],
  }))'
)
JOB_JSON=$(curl -fsS -X POST "${SERVER_URL}/api/jobs" \
  -H "Content-Type: application/json" \
  -d "${CREATE_BODY}")
JOB_ID=$(printf '%s' "${JOB_JSON}" | json_get 'data["job_id"]')
echo "created job=${JOB_ID}"

if [[ "${E2E_RUN_AGENT}" == "1" ]]; then
  echo "[4/6] Running agent until one job completes"
  "${PYTHON}" -m minidrop_agent daemon \
    --runtime-dir "${MINIDROP_RUNTIME}" \
    --server-url "${SERVER_URL}" \
    --agent-id "${AGENT_ID}" \
    --job-source server \
    --heartbeat-interval 5 \
    --poll-interval "${POLL_INTERVAL}" \
    --max-jobs 1 \
    --max-pending-age 300 \
    --max-claim-attempts 3 \
    --lease-seconds "${LEASE_SECONDS}"
else
  echo "[4/6] Waiting for external agent to complete the job"
  wait_for_done
fi

echo "[5/6] Verifying job status and artifacts"
FINAL_JOB_JSON=$(curl -fsS "${SERVER_URL}/api/jobs/${JOB_ID}")
STATUS=$(printf '%s' "${FINAL_JOB_JSON}" | json_get 'data["status"]')
if [[ "${STATUS}" != "DONE" ]]; then
  echo "expected DONE, got ${STATUS}"
  printf '%s\n' "${FINAL_JOB_JSON}"
  exit 1
fi

verify_artifact summary

if [[ "${COLLECTOR}" == "perf" ]]; then
  verify_artifact flamegraph
  verify_artifact hotspots
fi

echo "[6/6] Verifying diagnostic report"
REPORT_JSON=$(curl -fsS "${SERVER_URL}/api/jobs/${JOB_ID}/report")
REPORT_JOB_ID=$(printf '%s' "${REPORT_JSON}" | json_get 'data["job_id"]')
if [[ "${REPORT_JOB_ID}" != "${JOB_ID}" ]]; then
  echo "diagnostic report does not match job"
  printf '%s\n' "${REPORT_JSON}"
  exit 1
fi

echo "E2E demo passed"
echo "Job: ${JOB_ID}"
echo "Web: ${SERVER_URL}/ui"
