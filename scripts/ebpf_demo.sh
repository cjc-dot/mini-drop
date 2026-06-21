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
AGENT_ID=${AGENT_ID:-ebpf-demo-agent}
POLL_INTERVAL=${POLL_INTERVAL:-1}
LEASE_SECONDS=${LEASE_SECONDS:-60}
BASELINE_DELAY_US=${BASELINE_DELAY_US:-50}
CURRENT_DELAY_US=${CURRENT_DELAY_US:-2000}
EBPF_DEMO_RUN_AGENT=${EBPF_DEMO_RUN_AGENT:-${E2E_RUN_AGENT:-1}}
DIFF_OUTPUT=${DIFF_OUTPUT:-"${MINIDROP_RUNTIME}/profiles/ebpf-demo-latency-diff.json"}
PYTHONPATH=${PYTHONPATH:-"${ROOT_DIR}/analysis:${ROOT_DIR}/drop:${ROOT_DIR}/apiserver"}
export MINIDROP_RUNTIME PYTHONPATH

API_PID=""
WORKLOAD_PID=""
CAPTURED_JOB_ID=""

cleanup() {
  stop_workload
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

job_json() {
  local job_id=$1
  curl -fsS "${SERVER_URL}/api/jobs/${job_id}"
}

job_status() {
  local job_id=$1
  job_json "${job_id}" | json_get 'data["status"]'
}

stop_workload() {
  if [[ -n "${WORKLOAD_PID}" ]] && kill -0 "${WORKLOAD_PID}" >/dev/null 2>&1; then
    kill "${WORKLOAD_PID}" >/dev/null 2>&1 || true
    wait "${WORKLOAD_PID}" >/dev/null 2>&1 || true
  fi
  WORKLOAD_PID=""
}

start_api_if_needed() {
  echo "[1/8] Checking API server at ${SERVER_URL}"
  if health_check; then
    echo "API server is already running"
    return
  fi

  echo "Starting API server"
  "${PYTHON}" -m minidrop_apiserver \
    --host "${API_HOST}" \
    --port "${API_PORT}" \
    --runtime-dir "${MINIDROP_RUNTIME}" \
    > "${MINIDROP_RUNTIME}/logs/ebpf_demo_api.log" 2>&1 &
  API_PID=$!

  for _ in $(seq 1 50); do
    if health_check; then
      return
    fi
    sleep 0.2
  done

  echo "API server failed to start. Log:"
  tail -n 80 "${MINIDROP_RUNTIME}/logs/ebpf_demo_api.log" || true
  exit 1
}

start_latency_workload() {
  local label=$1
  local delay_us=$2

  stop_workload
  echo "Starting ${label} workload with writer_delay_us=${delay_us}"
  "${MINIDROP_RUNTIME}/builds/io_latency_hotspot" "${delay_us}" \
    > "${MINIDROP_RUNTIME}/logs/ebpf_demo_${label}.log" 2>&1 &
  WORKLOAD_PID=$!
  sleep 1

  if ! kill -0 "${WORKLOAD_PID}" >/dev/null 2>&1; then
    echo "${label} workload process exited unexpectedly"
    tail -n 80 "${MINIDROP_RUNTIME}/logs/ebpf_demo_${label}.log" || true
    exit 1
  fi

  echo "${label} workload pid=${WORKLOAD_PID}"
}

create_latency_job() {
  local pid=$1
  export WORKLOAD_PID="${pid}" DURATION FREQUENCY
  local body
  body=$(
    "${PYTHON}" -c 'import json, os; print(json.dumps({
      "pid": int(os.environ["WORKLOAD_PID"]),
      "duration_seconds": int(os.environ["DURATION"]),
      "sample_frequency": int(os.environ["FREQUENCY"]),
      "collector": "ebpf_io_latency",
    }))'
  )
  curl -fsS -X POST "${SERVER_URL}/api/jobs" \
    -H "Content-Type: application/json" \
    -d "${body}" | json_get 'data["job_id"]'
}

run_agent_once() {
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
}

wait_for_job_done() {
  local job_id=$1
  local status

  for _ in $(seq 1 120); do
    status=$(job_status "${job_id}")
    case "${status}" in
      DONE)
        return 0
        ;;
      FAILED)
        echo "job ${job_id} failed"
        job_json "${job_id}" || true
        return 1
        ;;
    esac

    if [[ "${EBPF_DEMO_RUN_AGENT}" == "1" ]]; then
      run_agent_once || true
    else
      sleep 1
    fi
  done

  echo "timed out waiting for job ${job_id}"
  job_json "${job_id}" || true
  return 1
}

verify_json_artifact() {
  local job_id=$1
  local artifact_name=$2
  local output_file="${MINIDROP_RUNTIME}/tmp/ebpf_demo_${job_id}_${artifact_name}.json"
  local http_code

  http_code=$(
    curl -fsS \
      -o "${output_file}" \
      -w "%{http_code}" \
      "${SERVER_URL}/api/jobs/${job_id}/artifacts/${artifact_name}"
  )
  if [[ "${http_code}" != "200" || ! -s "${output_file}" ]]; then
    echo "artifact ${artifact_name} is not available through API for ${job_id}"
    return 1
  fi
}

run_latency_capture() {
  local label=$1
  local delay_us=$2
  local job_id

  start_latency_workload "${label}" "${delay_us}"
  echo "Creating ${label} ebpf_io_latency job"
  job_id=$(create_latency_job "${WORKLOAD_PID}")
  echo "${label} job=${job_id}"
  wait_for_job_done "${job_id}"
  verify_json_artifact "${job_id}" summary
  verify_json_artifact "${job_id}" ebpf_io_latency
  verify_json_artifact "${job_id}" suggestions
  stop_workload
  CAPTURED_JOB_ID="${job_id}"
}

mkdir -p "${MINIDROP_RUNTIME}/logs"
mkdir -p "${MINIDROP_RUNTIME}/profiles"
mkdir -p "${MINIDROP_RUNTIME}/jobs"
mkdir -p "${MINIDROP_RUNTIME}/tmp"

start_api_if_needed

echo "[2/8] Capturing baseline eBPF IO latency"
run_latency_capture "baseline" "${BASELINE_DELAY_US}"
BASELINE_JOB_ID="${CAPTURED_JOB_ID}"

echo "[3/8] Capturing current eBPF IO latency with injected delay"
run_latency_capture "current" "${CURRENT_DELAY_US}"
CURRENT_JOB_ID="${CAPTURED_JOB_ID}"

echo "[4/8] Fetching eBPF latency diff"
mkdir -p "$(dirname "${DIFF_OUTPUT}")"
curl -fsS \
  "${SERVER_URL}/api/jobs/${CURRENT_JOB_ID}/compare/ebpf-io-latency?baseline_job_id=${BASELINE_JOB_ID}" \
  > "${DIFF_OUTPUT}"

COMPARISON_AVAILABLE=$(json_get 'data["comparison_available"]' < "${DIFF_OUTPUT}")
if [[ "${COMPARISON_AVAILABLE}" != "True" ]]; then
  echo "latency comparison is not available"
  cat "${DIFF_OUTPUT}"
  exit 1
fi

echo "[5/8] Verifying current diagnostic report"
REPORT_JSON=$(curl -fsS "${SERVER_URL}/api/jobs/${CURRENT_JOB_ID}/report")
REPORT_JOB_ID=$(printf '%s' "${REPORT_JSON}" | json_get 'data["job_id"]')
if [[ "${REPORT_JOB_ID}" != "${CURRENT_JOB_ID}" ]]; then
  echo "diagnostic report does not match current job"
  printf '%s\n' "${REPORT_JSON}"
  exit 1
fi

echo "[6/8] Verifying Web-visible artifacts"
verify_json_artifact "${CURRENT_JOB_ID}" ebpf_io_latency
verify_json_artifact "${CURRENT_JOB_ID}" suggestions

echo "[7/8] Printing latency diff summary"
"${PYTHON}" -c '
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
for event in data.get("events", []):
    print(
        "{}: {} tail>=1ms {}% -> {}% p99 {} -> {}".format(
            event.get("event"),
            event.get("verdict"),
            event.get("baseline_tail_1ms_percent"),
            event.get("current_tail_1ms_percent"),
            event.get("baseline_p99_bucket"),
            event.get("current_p99_bucket"),
        )
    )
' "${DIFF_OUTPUT}"

echo "[8/8] eBPF demo passed"
echo "Baseline Job: ${BASELINE_JOB_ID}"
echo "Current Job: ${CURRENT_JOB_ID}"
echo "Diff: ${DIFF_OUTPUT}"
echo "Web: ${SERVER_URL}/ui"
echo "Compare API: ${SERVER_URL}/api/jobs/${CURRENT_JOB_ID}/compare/ebpf-io-latency?baseline_job_id=${BASELINE_JOB_ID}"
