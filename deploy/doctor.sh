#!/usr/bin/env bash
set -u

failures=0
warnings=0
require_docker="${MINIDROP_REQUIRE_DOCKER:-0}"

section() {
  echo
  echo "== $1 =="
}

pass() {
  echo "PASS: $1"
}

warn() {
  echo "WARN: $1"
  warnings=$((warnings + 1))
}

fail() {
  echo "FAIL: $1"
  failures=$((failures + 1))
}

docker_issue() {
  if [ "$require_docker" = "1" ]; then
    fail "$1"
  else
    warn "$1"
  fi
}

check_command() {
  local name="$1"
  local fix="$2"
  if command -v "$name" >/dev/null 2>&1; then
    pass "$name -> $(command -v "$name")"
  else
    fail "$name not found. $fix"
  fi
}

check_nopasswd() {
  local name="$1"
  local path
  path="$(command -v "$name" || true)"
  if [ -z "$path" ]; then
    warn "skip sudo check for missing command: $name"
    return
  fi

  if sudo -n "$path" --version >/dev/null 2>&1; then
    pass "sudo NOPASSWD works for $path"
  else
    fail "sudo NOPASSWD missing for $path. Run: sudo bash deploy/setup_sudoers.sh"
  fi
}

find_host_perf_bin() {
  local kernel="$1"
  if [ -x "/usr/lib/linux-tools-${kernel}/perf" ]; then
    echo "/usr/lib/linux-tools-${kernel}/perf"
    return
  fi
  if [ -x "/usr/lib/linux-tools/${kernel}/perf" ]; then
    echo "/usr/lib/linux-tools/${kernel}/perf"
    return
  fi
  command -v perf || true
}

section "System"
if [ "$(uname -s)" = "Linux" ]; then
  pass "running on Linux $(uname -r)"
else
  fail "Mini-Drop collectors require Linux. Current system: $(uname -s)"
fi

section "Required Commands"
check_command python3 "Install Python 3."
check_command gcc "Install gcc, for example: sudo apt install -y gcc"
check_command curl "Install curl, for example: sudo apt install -y curl"
check_command perf "Install perf tools, for example: sudo apt install -y linux-tools-\$(uname -r) linux-tools-generic"
check_command bpftrace "Install bpftrace, for example: sudo apt install -y bpftrace"
check_command py-spy "Install Python dependencies, for example: python3 -m pip install -r requirements.txt"

section "Python Dependencies"
if python3 - <<'PY' >/dev/null 2>&1
import fastapi
import uvicorn
PY
then
  pass "fastapi and uvicorn are importable"
else
  fail "Python API dependencies missing. Run: python3 -m pip install -r requirements.txt"
fi

section "Profiling Privileges"
check_nopasswd perf
check_nopasswd bpftrace
check_nopasswd py-spy

if [ -r /proc/sys/kernel/perf_event_paranoid ]; then
  paranoid="$(cat /proc/sys/kernel/perf_event_paranoid)"
  if [ "$paranoid" -le 2 ] 2>/dev/null; then
    pass "perf_event_paranoid=$paranoid"
  else
    warn "perf_event_paranoid=$paranoid. Mini-Drop uses sudo perf, so this is usually acceptable."
  fi
fi

section "Host perf for Docker Agent"
kernel="$(uname -r)"
host_perf_bin="$(find_host_perf_bin "$kernel")"
if [ -n "$host_perf_bin" ] && [ -x "$host_perf_bin" ]; then
  pass "HOST_PERF_BIN=$host_perf_bin"
  if [ "$(basename "$host_perf_bin")" = "perf" ] && [ "$host_perf_bin" = "$(command -v perf 2>/dev/null || true)" ]; then
    warn "HOST_PERF_BIN points to command wrapper. Install kernel-matched tools if Docker Agent reports perf not found."
  fi
  if command -v ldd >/dev/null 2>&1; then
    missing_libs="$(ldd "$host_perf_bin" 2>/dev/null | grep 'not found' || true)"
    if [ -z "$missing_libs" ]; then
      pass "host perf dynamic libraries are resolved on host"
    else
      warn "host perf has unresolved libraries on host:"
      echo "$missing_libs"
    fi
  fi
else
  fail "kernel-matched perf binary not found. Run: sudo apt install -y linux-tools-\$(uname -r) linux-tools-generic"
fi

section "Docker Compose"
if command -v docker >/dev/null 2>&1; then
  pass "docker -> $(command -v docker)"
  if docker ps >/dev/null 2>&1; then
    pass "current user can access Docker daemon"
  else
    docker_issue "current user cannot access Docker daemon. Run: sudo usermod -aG docker \$USER, then relogin or run: newgrp docker"
  fi

  if docker compose version >/dev/null 2>&1; then
    pass "$(docker compose version)"
  else
    docker_issue "docker compose is not available. Install Docker Compose plugin."
  fi
else
  docker_issue "docker not found. Install Docker Engine if you want Compose deployment."
fi

section "Port"
if command -v ss >/dev/null 2>&1; then
  if ss -ltn "( sport = :8000 )" | grep -q ':8000'; then
    warn "port 8000 is already listening. Stop old API server before running Docker Compose."
  else
    pass "port 8000 is free"
  fi
else
  warn "ss not found; skip port 8000 check"
fi

echo
echo "Mini-Drop doctor summary: failures=$failures warnings=$warnings"
if [ "$failures" -ne 0 ]; then
  echo "Doctor failed. Fix the FAIL items above before running full demos."
  exit 1
fi

echo "Doctor passed."
