from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .perf import ProfileSummary


SYSCALL_COUNTER_PATTERN = re.compile(r"@(?P<name>read|write):\s*(?P<count>\d+)")


def parse_bpftrace_syscall_counts(output: str) -> dict[str, int]:
    counts = {"read": 0, "write": 0}
    for match in SYSCALL_COUNTER_PATTERN.finditer(output):
        counts[match.group("name")] = int(match.group("count"))
    return counts


class EbpfSyscallCollector:
    def __init__(self, bpftrace_bin: str = "bpftrace") -> None:
        self.bpftrace_bin = bpftrace_bin

    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        output_path = Path(output_dir).expanduser().resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        raw_output = output_path / "ebpf_syscalls.raw"
        syscall_report = output_path / "ebpf_syscalls.json"
        summary_path = output_path / "summary.json"

        raw_text = self._capture_bpftrace(pid=pid, duration_seconds=duration_seconds)
        counts = parse_bpftrace_syscall_counts(raw_text)
        raw_output.write_text(raw_text, encoding="utf-8")

        report = {
            "pid": pid,
            "collector": "ebpf_syscall",
            "duration_seconds": duration_seconds,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "total_events": sum(counts.values()),
            "events": [
                {"event": "read", "count": counts["read"]},
                {"event": "write", "count": counts["write"]},
            ],
        }
        syscall_report.write_text(json.dumps(report, indent=2), encoding="utf-8")

        summary = ProfileSummary(
            pid=pid,
            collector="ebpf_syscall",
            status="success",
            duration_seconds=duration_seconds,
            sample_frequency=sample_frequency,
            output_dir=str(output_path),
            created_at=report["created_at"],
            artifacts={
                "ebpf_raw": str(raw_output),
                "ebpf_syscalls": str(syscall_report),
                "summary": str(summary_path),
            },
        )
        summary_path.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
        return summary

    def _capture_bpftrace(self, pid: int, duration_seconds: int) -> str:
        script = self._script(pid=pid, duration_seconds=duration_seconds)
        completed = subprocess.run(
            ["sudo", self.bpftrace_bin, "-e", script],
            text=True,
            capture_output=True,
        )
        if completed.returncode != 0:
            detail = "\n".join(
                part.strip()
                for part in [completed.stdout, completed.stderr]
                if part and part.strip()
            )
            raise RuntimeError(
                f"bpftrace failed with exit code {completed.returncode}"
                + (f":\n{detail}" if detail else "")
            )
        return completed.stdout + completed.stderr

    @staticmethod
    def _script(pid: int, duration_seconds: int) -> str:
        return f"""
tracepoint:syscalls:sys_enter_read /pid == {pid}/ {{ @read = count(); }}
tracepoint:syscalls:sys_enter_write /pid == {pid}/ {{ @write = count(); }}
interval:s:{duration_seconds} {{
  print(@read);
  print(@write);
  exit();
}}
"""
