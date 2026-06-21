#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: this script must be run with sudo."
  echo "Usage: sudo bash deploy/setup_sudoers.sh"
  exit 1
fi

target_user="${SUDO_USER:-}"
if [ -z "$target_user" ] || [ "$target_user" = "root" ]; then
  echo "ERROR: cannot detect the non-root user from SUDO_USER."
  echo "Run it as: sudo bash deploy/setup_sudoers.sh"
  exit 1
fi

find_tool() {
  local name="$1"
  local env_name="$2"
  local configured_path="${!env_name:-}"
  local path

  if [ -n "$configured_path" ]; then
    if [ ! -x "$configured_path" ]; then
      echo "ERROR: configured tool path is not executable: $configured_path" >&2
      exit 1
    fi
    readlink -f "$configured_path"
    return
  fi

  path="$(command -v "$name" || true)"
  if [ -z "$path" ]; then
    echo "ERROR: required tool not found: $name" >&2
    exit 1
  fi
  readlink -f "$path"
}

perf_bin="$(find_tool perf MINIDROP_PERF_BIN)"
bpftrace_bin="$(find_tool bpftrace MINIDROP_BPFTRACE_BIN)"
py_spy_bin="$(find_tool py-spy MINIDROP_PY_SPY_BIN)"
sudoers_file="/etc/sudoers.d/mini-drop-tools"
tmp_file="$(mktemp)"

cat > "$tmp_file" <<EOF
# Mini-Drop profiling tools.
# This file allows the target user to run only the required collectors without a password.
$target_user ALL=(root) NOPASSWD: $perf_bin, $bpftrace_bin, $py_spy_bin
EOF

chmod 0440 "$tmp_file"
visudo -cf "$tmp_file" >/dev/null
install -m 0440 "$tmp_file" "$sudoers_file"
rm -f "$tmp_file"

echo "Configured sudoers: $sudoers_file"
echo "User: $target_user"
echo "Tools:"
echo "  $perf_bin"
echo "  $bpftrace_bin"
echo "  $py_spy_bin"
echo
echo "Verify with:"
echo "  sudo -n $perf_bin --version"
echo "  sudo -n $bpftrace_bin --version"
echo "  sudo -n $py_spy_bin --version"
