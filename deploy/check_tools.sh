#!/usr/bin/env bash
set -euo pipefail

missing=0

check_command() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "MISSING: $name"
    missing=1
    return
  fi
  echo "FOUND: $name -> $(command -v "$name")"
}

check_nopasswd() {
  local name="$1"
  local path
  path="$(command -v "$name" || true)"
  if [ -z "$path" ]; then
    return
  fi
  if sudo -n "$path" --version >/dev/null 2>&1; then
    echo "NOPASSWD OK: $path"
  else
    echo "NOPASSWD MISSING: $path"
    missing=1
  fi
}

check_command gcc
check_command python3
check_command perf
check_command bpftrace
check_command py-spy

check_nopasswd perf
check_nopasswd bpftrace
check_nopasswd py-spy

if [ "$missing" -ne 0 ]; then
  echo
  echo "Mini-Drop tool check failed."
  echo "Install missing tools or run: sudo bash deploy/setup_sudoers.sh"
  exit 1
fi

echo
echo "Mini-Drop tool check passed."
