from __future__ import annotations

import hashlib
import json
import platform
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .perf import ProfileSummary


READ_SYSCALL_ID_X86_64 = 0
WRITE_SYSCALL_ID_X86_64 = 1
LATENCY_BUCKETS = [
    {"bucket": "0-10", "lower_us": 0, "upper_us": 10},
    {"bucket": "10-100", "lower_us": 10, "upper_us": 100},
    {"bucket": "100-1000", "lower_us": 100, "upper_us": 1000},
    {"bucket": "1000-10000", "lower_us": 1000, "upper_us": 10000},
    {"bucket": "10000+", "lower_us": 10000, "upper_us": None},
]
BUCKET_BY_KEY = {
    "0_10": LATENCY_BUCKETS[0],
    "10_100": LATENCY_BUCKETS[1],
    "100_1000": LATENCY_BUCKETS[2],
    "1000_10000": LATENCY_BUCKETS[3],
    "10000_plus": LATENCY_BUCKETS[4],
}
LATENCY_COUNTER_PATTERN = re.compile(
    r"@(?P<event>read|write)_(?P<bucket>0_10|10_100|100_1000|1000_10000|10000_plus):\s*(?P<count>\d+)"
)


def parse_bpftrace_latency_counts(output: str) -> dict[str, dict[str, int]]:
    counts = {
        "read": {key: 0 for key in BUCKET_BY_KEY},
        "write": {key: 0 for key in BUCKET_BY_KEY},
    }
    for match in LATENCY_COUNTER_PATTERN.finditer(output):
        counts[match.group("event")][match.group("bucket")] = int(match.group("count"))
    return counts


class EbpfIoLatencyCollector:
    def __init__(self, bpftrace_bin: str = "bpftrace") -> None:
        self.bpftrace_bin = bpftrace_bin

    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        output_path = Path(output_dir).expanduser().resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        raw_output = output_path / "ebpf_io_latency.raw"
        latency_report = output_path / "ebpf_io_latency.json"
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
        counts = parse_bpftrace_latency_counts(raw_text)
        raw_output.write_text(raw_text, encoding="utf-8")

        events = [_build_event_report(event_name, counts[event_name]) for event_name in ("read", "write")]
        report = {
            "pid": pid,
            "collector": "ebpf_io_latency",
            "duration_seconds": duration_seconds,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "tool": "bpftrace",
            "tool_version": self._tool_version(),
            "kernel_release": platform.release(),
            "script_hash": self._script_hash(script),
            "tracepoint_mode": tracepoint_mode,
            "unit": "us",
            "total_events": sum(event["total_count"] for event in events),
            "events": events,
        }
        advice_report = generate_latency_advice(report)
        latency_report.write_text(json.dumps(report, indent=2), encoding="utf-8")
        suggestions.write_text(json.dumps(advice_report, indent=2), encoding="utf-8")
        suggestions_markdown.write_text(format_latency_advice_markdown(advice_report), encoding="utf-8")

        summary = ProfileSummary(
            pid=pid,
            collector="ebpf_io_latency",
            status="success",
            duration_seconds=duration_seconds,
            sample_frequency=sample_frequency,
            output_dir=str(output_path),
            created_at=report["created_at"],
            artifacts={
                "ebpf_io_latency_raw": str(raw_output),
                "ebpf_io_latency": str(latency_report),
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
tracepoint:syscalls:sys_enter_read /pid == {pid}/ {{ @read_start[tid] = nsecs; }}
tracepoint:syscalls:sys_exit_read /@read_start[tid]/ {{
  $delta_us = (nsecs - @read_start[tid]) / 1000;
  if ($delta_us < 10) {{ @read_0_10 = count(); }}
  if ($delta_us >= 10 && $delta_us < 100) {{ @read_10_100 = count(); }}
  if ($delta_us >= 100 && $delta_us < 1000) {{ @read_100_1000 = count(); }}
  if ($delta_us >= 1000 && $delta_us < 10000) {{ @read_1000_10000 = count(); }}
  if ($delta_us >= 10000) {{ @read_10000_plus = count(); }}
  delete(@read_start[tid]);
}}
tracepoint:syscalls:sys_enter_write /pid == {pid}/ {{ @write_start[tid] = nsecs; }}
tracepoint:syscalls:sys_exit_write /@write_start[tid]/ {{
  $delta_us = (nsecs - @write_start[tid]) / 1000;
  if ($delta_us < 10) {{ @write_0_10 = count(); }}
  if ($delta_us >= 10 && $delta_us < 100) {{ @write_10_100 = count(); }}
  if ($delta_us >= 100 && $delta_us < 1000) {{ @write_100_1000 = count(); }}
  if ($delta_us >= 1000 && $delta_us < 10000) {{ @write_1000_10000 = count(); }}
  if ($delta_us >= 10000) {{ @write_10000_plus = count(); }}
  delete(@write_start[tid]);
}}
interval:s:{duration_seconds} {{
  print(@read_0_10);
  print(@read_10_100);
  print(@read_100_1000);
  print(@read_1000_10000);
  print(@read_10000_plus);
  print(@write_0_10);
  print(@write_10_100);
  print(@write_100_1000);
  print(@write_1000_10000);
  print(@write_10000_plus);
  exit();
}}
"""

    @staticmethod
    def _raw_syscall_script(pid: int, duration_seconds: int) -> str:
        return f"""
tracepoint:raw_syscalls:sys_enter /pid == {pid} && args->id == {READ_SYSCALL_ID_X86_64}/ {{ @read_start[tid] = nsecs; }}
tracepoint:raw_syscalls:sys_exit /@read_start[tid]/ {{
  $delta_us = (nsecs - @read_start[tid]) / 1000;
  if ($delta_us < 10) {{ @read_0_10 = count(); }}
  if ($delta_us >= 10 && $delta_us < 100) {{ @read_10_100 = count(); }}
  if ($delta_us >= 100 && $delta_us < 1000) {{ @read_100_1000 = count(); }}
  if ($delta_us >= 1000 && $delta_us < 10000) {{ @read_1000_10000 = count(); }}
  if ($delta_us >= 10000) {{ @read_10000_plus = count(); }}
  delete(@read_start[tid]);
}}
tracepoint:raw_syscalls:sys_enter /pid == {pid} && args->id == {WRITE_SYSCALL_ID_X86_64}/ {{ @write_start[tid] = nsecs; }}
tracepoint:raw_syscalls:sys_exit /@write_start[tid]/ {{
  $delta_us = (nsecs - @write_start[tid]) / 1000;
  if ($delta_us < 10) {{ @write_0_10 = count(); }}
  if ($delta_us >= 10 && $delta_us < 100) {{ @write_10_100 = count(); }}
  if ($delta_us >= 100 && $delta_us < 1000) {{ @write_100_1000 = count(); }}
  if ($delta_us >= 1000 && $delta_us < 10000) {{ @write_1000_10000 = count(); }}
  if ($delta_us >= 10000) {{ @write_10000_plus = count(); }}
  delete(@write_start[tid]);
}}
interval:s:{duration_seconds} {{
  print(@read_0_10);
  print(@read_10_100);
  print(@read_100_1000);
  print(@read_1000_10000);
  print(@read_10000_plus);
  print(@write_0_10);
  print(@write_10_100);
  print(@write_100_1000);
  print(@write_1000_10000);
  print(@write_10000_plus);
  exit();
}}
"""

    @staticmethod
    def _script_hash(script: str) -> str:
        digest = hashlib.sha256(script.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"


def _is_missing_syscall_tracepoint_error(message: str) -> bool:
    return "tracepoint not found" in message and "syscalls:sys_" in message


def generate_latency_advice(report: dict) -> dict:
    findings = []
    for event in report.get("events", []):
        if not isinstance(event, dict) or event.get("total_count", 0) == 0:
            continue
        if _bucket_index(event.get("p99_bucket")) >= _bucket_index(event.get("p50_bucket")) + 2:
            findings.append(_build_tail_latency_finding(event))
        if float(event.get("tail_1ms_percent", 0.0)) >= 5.0:
            findings.append(_build_tail_percent_finding(event))
        if _has_bimodal_shape(event):
            findings.append(_build_bimodal_finding(event))

    return {
        "source": "ebpf_io_latency",
        "total_events": int(report.get("total_events", 0)),
        "duration_seconds": int(report.get("duration_seconds", 0)),
        "finding_count": len(findings),
        "findings": findings,
    }


def format_latency_advice_markdown(advice_report: dict) -> str:
    lines = [
        "# Mini-Drop eBPF IO Latency Suggestions",
        "",
        f"- Total events: {advice_report.get('total_events', 0)}",
        f"- Duration: {advice_report.get('duration_seconds', 0)}s",
        f"- Finding count: {len(advice_report.get('findings', []))}",
        "",
    ]
    if not advice_report.get("findings"):
        lines.extend(["No eBPF IO latency rule was triggered.", ""])
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
                f"- P50 bucket: {evidence.get('p50_bucket', '-')}",
                f"- P99 bucket: {evidence.get('p99_bucket', '-')}",
                f"- Tail >= 1ms: {evidence.get('tail_1ms_percent', '-')}%",
                f"- Advice: {finding['advice']}",
                "",
            ]
        )
        if finding.get("next_actions"):
            lines.append("- Next actions:")
            lines.extend(f"  - {action}" for action in finding["next_actions"])
            lines.append("")
    return "\n".join(lines)


def _build_event_report(event_name: str, bucket_counts: dict[str, int]) -> dict:
    total = sum(bucket_counts.values())
    histogram = []
    for key, bucket_def in BUCKET_BY_KEY.items():
        count = int(bucket_counts.get(key, 0))
        percent = round(count * 100 / total, 2) if total else 0.0
        histogram.append({**bucket_def, "count": count, "percent": percent})
    tail_count = sum(
        item["count"]
        for item in histogram
        if item["lower_us"] >= 1000
    )
    return {
        "event": event_name,
        "total_count": total,
        "histogram": histogram,
        "p50_bucket": _percentile_bucket(histogram, total, 50),
        "p95_bucket": _percentile_bucket(histogram, total, 95),
        "p99_bucket": _percentile_bucket(histogram, total, 99),
        "tail_1ms_count": tail_count,
        "tail_1ms_percent": round(tail_count * 100 / total, 2) if total else 0.0,
    }


def _percentile_bucket(histogram: list[dict], total: int, percentile: int) -> str | None:
    if total <= 0:
        return None
    threshold = total * percentile / 100
    cumulative = 0
    for bucket in histogram:
        cumulative += int(bucket["count"])
        if cumulative >= threshold:
            return str(bucket["bucket"])
    return str(histogram[-1]["bucket"])


def _bucket_index(bucket: str | None) -> int:
    if bucket is None:
        return -1
    for index, bucket_def in enumerate(LATENCY_BUCKETS):
        if bucket_def["bucket"] == bucket:
            return index
    return -1


def _has_bimodal_shape(event: dict) -> bool:
    significant_indexes = [
        index
        for index, bucket in enumerate(event.get("histogram", []))
        if float(bucket.get("percent", 0.0)) >= 20.0
    ]
    return len(significant_indexes) >= 2 and max(significant_indexes) - min(significant_indexes) >= 2


def _build_tail_latency_finding(event: dict) -> dict:
    return {
        "rule_id": "io_latency_p99_far_from_p50",
        "title": "IO latency tail is much slower than median",
        "severity": "HIGH",
        "target": event["event"],
        "matched_condition": "p99 bucket is at least two latency buckets slower than p50 bucket",
        "reason": f"{event['event']} p50 is {event.get('p50_bucket')} while p99 is {event.get('p99_bucket')}",
        "evidence": _event_evidence(event),
        "advice": "该系统调用存在明显长尾延迟，建议关注磁盘抖动、队列拥塞、同步写或阻塞等待路径。",
        "next_actions": [
            "检查高延迟时段是否伴随磁盘繁忙或队列堆积。",
            "确认该 read/write 是否位于请求关键路径。",
            "对比正常负载和异常负载下的延迟分布变化。",
        ],
    }


def _build_tail_percent_finding(event: dict) -> dict:
    return {
        "rule_id": "io_latency_tail_over_1ms",
        "title": "IO latency has visible tail over 1ms",
        "severity": "MEDIUM",
        "target": event["event"],
        "matched_condition": "tail_1ms_percent >= 5.0",
        "reason": f"{event['event']} has {event.get('tail_1ms_percent')}% samples >= 1ms",
        "evidence": _event_evidence(event),
        "advice": "超过 1ms 的 read/write 占比较高，建议检查是否存在阻塞 IO、慢设备、管道等待或频繁同步刷写。",
        "next_actions": [
            "定位慢 syscall 对应的业务路径和文件描述符类型。",
            "确认是否可以使用缓冲、批量处理或异步化减少阻塞。",
        ],
    }


def _build_bimodal_finding(event: dict) -> dict:
    return {
        "rule_id": "io_latency_bimodal_distribution",
        "title": "IO latency distribution looks bimodal",
        "severity": "MEDIUM",
        "target": event["event"],
        "matched_condition": "two non-adjacent latency buckets both have percent >= 20.0",
        "reason": f"{event['event']} has significant samples in separated latency buckets",
        "evidence": _event_evidence(event),
        "advice": "延迟分布可能存在两类路径，例如缓存命中与真实阻塞、普通请求与异常慢请求混在一起。",
        "next_actions": [
            "拆分不同输入规模或不同文件描述符类型分别采样。",
            "检查是否同时存在缓存路径和落盘/阻塞路径。",
        ],
    }


def _event_evidence(event: dict) -> dict:
    return {
        "event": event.get("event"),
        "total_count": int(event.get("total_count", 0)),
        "p50_bucket": event.get("p50_bucket"),
        "p95_bucket": event.get("p95_bucket"),
        "p99_bucket": event.get("p99_bucket"),
        "tail_1ms_count": int(event.get("tail_1ms_count", 0)),
        "tail_1ms_percent": float(event.get("tail_1ms_percent", 0.0)),
    }
