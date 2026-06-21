from __future__ import annotations

import json
import re
import subprocess
import hashlib
import platform
from datetime import datetime, timezone
from pathlib import Path

from .perf import ProfileSummary


SYSCALL_COUNTER_PATTERN = re.compile(r"@(?P<name>read|write):\s*(?P<count>\d+)")
READ_SYSCALL_ID_X86_64 = 0
WRITE_SYSCALL_ID_X86_64 = 1


def parse_bpftrace_syscall_counts(output: str) -> dict[str, int]:
    counts = {"read": 0, "write": 0}
    for match in SYSCALL_COUNTER_PATTERN.finditer(output):
        counts[match.group("name")] = int(match.group("count"))
    return counts


def event_rate(count: int, duration_seconds: int) -> float:
    if duration_seconds <= 0:
        return 0.0
    return round(count / duration_seconds, 2)


def generate_syscall_advice(report: dict) -> dict:
    events = {
        str(event.get("event", "")): event
        for event in report.get("events", [])
        if isinstance(event, dict)
    }
    findings = []
    for event_name in ("read", "write"):
        event = events.get(event_name, {})
        rate = float(event.get("rate_per_second", 0.0))
        if rate >= 500.0:
            findings.append(_build_high_rate_finding(report, event_name, event, rate))

    read_rate = float(events.get("read", {}).get("rate_per_second", 0.0))
    write_rate = float(events.get("write", {}).get("rate_per_second", 0.0))
    if write_rate >= 100.0 and write_rate >= read_rate * 2:
        findings.append(_build_write_dominant_finding(report, read_rate, write_rate))

    return {
        "source": "ebpf_syscalls",
        "total_events": int(report.get("total_events", 0)),
        "duration_seconds": int(report.get("duration_seconds", 0)),
        "finding_count": len(findings),
        "findings": findings,
    }


def format_syscall_advice_markdown(advice_report: dict) -> str:
    lines = [
        "# Mini-Drop eBPF Syscall Suggestions",
        "",
        f"- Total events: {advice_report.get('total_events', 0)}",
        f"- Duration: {advice_report.get('duration_seconds', 0)}s",
        f"- Finding count: {len(advice_report.get('findings', []))}",
        "",
    ]
    if not advice_report.get("findings"):
        lines.extend(["No eBPF syscall rule was triggered.", ""])
        return "\n".join(lines)

    for index, finding in enumerate(advice_report["findings"], start=1):
        evidence = finding.get("evidence", {})
        lines.extend(
            [
                f"## {index}. {finding['title']}",
                "",
                f"- Severity: {finding['severity']}",
                f"- Target: `{finding['target']}`",
                f"- Matched condition: {finding['matched_condition']}",
                f"- Reason: {finding['reason']}",
                f"- Count: {evidence.get('count', '-')}",
                f"- Rate: {evidence.get('rate_per_second', '-')} event/s",
                f"- Advice: {finding['advice']}",
                "",
            ]
        )
        if finding.get("next_actions"):
            lines.append("- Next actions:")
            lines.extend(f"  - {action}" for action in finding["next_actions"])
            lines.append("")
    return "\n".join(lines)


class EbpfSyscallCollector:
    def __init__(self, bpftrace_bin: str = "bpftrace") -> None:
        self.bpftrace_bin = bpftrace_bin

    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        output_path = Path(output_dir).expanduser().resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        raw_output = output_path / "ebpf_syscalls.raw"
        syscall_report = output_path / "ebpf_syscalls.json"
        suggestions = output_path / "suggestions.json"
        suggestions_markdown = output_path / "suggestions.md"
        summary_path = output_path / "summary.json"

        script = self._script(pid=pid, duration_seconds=duration_seconds)
        tracepoint_mode = "syscalls"
        try:
            raw_text = self._capture_bpftrace(pid=pid, duration_seconds=duration_seconds, script=script)
        except RuntimeError as exc:
            if not _is_missing_syscall_tracepoint_error(str(exc)):
                raise
            script = self._raw_syscall_script(pid=pid, duration_seconds=duration_seconds)
            tracepoint_mode = "raw_syscalls"
            raw_text = self._capture_bpftrace(pid=pid, duration_seconds=duration_seconds, script=script)
        counts = parse_bpftrace_syscall_counts(raw_text)
        raw_output.write_text(raw_text, encoding="utf-8")

        report = {
            "pid": pid,
            "collector": "ebpf_syscall",
            "duration_seconds": duration_seconds,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "tool": "bpftrace",
            "tool_version": self._tool_version(),
            "kernel_release": platform.release(),
            "script_hash": self._script_hash(script),
            "tracepoint_mode": tracepoint_mode,
            "total_events": sum(counts.values()),
            "read_per_second": event_rate(counts["read"], duration_seconds),
            "write_per_second": event_rate(counts["write"], duration_seconds),
            "events": [
                {
                    "event": "read",
                    "count": counts["read"],
                    "rate_per_second": event_rate(counts["read"], duration_seconds),
                },
                {
                    "event": "write",
                    "count": counts["write"],
                    "rate_per_second": event_rate(counts["write"], duration_seconds),
                },
            ],
        }
        advice_report = generate_syscall_advice(report)
        syscall_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
        suggestions.write_text(json.dumps(advice_report, indent=2), encoding="utf-8")
        suggestions_markdown.write_text(format_syscall_advice_markdown(advice_report), encoding="utf-8")

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
                "suggestions": str(suggestions),
                "suggestions_markdown": str(suggestions_markdown),
                "summary": str(summary_path),
            },
        )
        summary_path.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
        return summary

    def _capture_bpftrace(self, pid: int, duration_seconds: int, script: str | None = None) -> str:
        if script is None:
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

    def _tool_version(self) -> str:
        try:
            completed = subprocess.run(
                [self.bpftrace_bin, "--version"],
                text=True,
                capture_output=True,
            )
        except OSError:
            return "unknown"
        if completed.returncode != 0:
            return "unknown"
        lines = (completed.stdout or completed.stderr).strip().splitlines()
        return lines[0] if lines else "unknown"

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

    @staticmethod
    def _raw_syscall_script(pid: int, duration_seconds: int) -> str:
        return f"""
tracepoint:raw_syscalls:sys_enter /pid == {pid} && args->id == {READ_SYSCALL_ID_X86_64}/ {{ @read = count(); }}
tracepoint:raw_syscalls:sys_enter /pid == {pid} && args->id == {WRITE_SYSCALL_ID_X86_64}/ {{ @write = count(); }}
interval:s:{duration_seconds} {{
  print(@read);
  print(@write);
  exit();
}}
"""

    @staticmethod
    def _script_hash(script: str) -> str:
        digest = hashlib.sha256(script.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"


def _is_missing_syscall_tracepoint_error(message: str) -> bool:
    return "tracepoint not found" in message and "syscalls:sys_" in message


def _build_high_rate_finding(report: dict, event_name: str, event: dict, rate: float) -> dict:
    count = int(event.get("count", 0))
    return {
        "rule_id": f"high_{event_name}_syscall_rate",
        "title": f"High {event_name} syscall rate",
        "severity": "MEDIUM",
        "target": event_name,
        "matched_condition": f"{event_name}_per_second >= 500.0",
        "reason": f"{event_name} rate {rate} event/s >= 500.0 event/s",
        "evidence": {
            "event": event_name,
            "count": count,
            "rate_per_second": rate,
            "duration_seconds": int(report.get("duration_seconds", 0)),
            "total_events": int(report.get("total_events", 0)),
        },
        "advice": (
            f"目标进程的 {event_name} 系统调用频率较高，建议检查是否存在高频小块 IO、"
            "循环内重复读写、日志刷写过密或缺少批量化缓冲。"
        ),
        "next_actions": [
            f"定位触发 {event_name} 的业务代码路径，确认是否在循环内频繁调用。",
            "统计单次读写大小，判断是否可以合并为批量 IO。",
            "结合 perf 热点和源码确认 syscall 是否处于请求关键路径。",
        ],
    }


def _build_write_dominant_finding(report: dict, read_rate: float, write_rate: float) -> dict:
    return {
        "rule_id": "write_syscall_dominates_read",
        "title": "Write syscall dominates read",
        "severity": "INFO",
        "target": "write",
        "matched_condition": "write_per_second >= 100.0 and write_per_second >= read_per_second * 2",
        "reason": f"write rate {write_rate} event/s is at least 2x read rate {read_rate} event/s",
        "evidence": {
            "read_per_second": read_rate,
            "write_per_second": write_rate,
            "duration_seconds": int(report.get("duration_seconds", 0)),
            "total_events": int(report.get("total_events", 0)),
        },
        "advice": "写系统调用明显多于读系统调用，建议重点检查日志写入、同步刷盘、临时文件写入或输出放大问题。",
        "next_actions": [
            "确认是否存在 debug 日志、频繁 flush 或 fsync。",
            "检查写入路径是否可以缓冲、合并或降低频率。",
            "在优化后重新采集 eBPF syscall 数据，对比 write_per_second 是否下降。",
        ],
    }
