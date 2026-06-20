import json
from pathlib import Path

from minidrop_analysis.ebpf import (
    EbpfSyscallCollector,
    event_rate,
    generate_syscall_advice,
    parse_bpftrace_syscall_counts,
)


class FakeEbpfSyscallCollector(EbpfSyscallCollector):
    def _capture_bpftrace(self, pid: int, duration_seconds: int, script: str | None = None) -> str:
        return """
Attaching 3 probes...
@read: 7
@write: 3
"""

    def _tool_version(self) -> str:
        return "bpftrace v0.test"


def test_parse_bpftrace_syscall_counts() -> None:
    output = "Attaching 3 probes...\n@read: 12\n@write: 5\n"

    assert parse_bpftrace_syscall_counts(output) == {"read": 12, "write": 5}


def test_parse_bpftrace_syscall_counts_defaults_missing_maps_to_zero() -> None:
    output = "Attaching 3 probes...\n"

    assert parse_bpftrace_syscall_counts(output) == {"read": 0, "write": 0}


def test_event_rate_rounds_to_two_decimal_places() -> None:
    assert event_rate(10, 4) == 2.5
    assert event_rate(10, 3) == 3.33
    assert event_rate(10, 0) == 0.0


def test_ebpf_syscall_collector_writes_report_and_summary(tmp_path: Path) -> None:
    summary = FakeEbpfSyscallCollector().collect(
        pid=1234,
        duration_seconds=1,
        sample_frequency=99,
        output_dir=str(tmp_path),
    )

    report = json.loads((tmp_path / "ebpf_syscalls.json").read_text(encoding="utf-8"))
    summary_json = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))

    assert summary.collector == "ebpf_syscall"
    assert summary.artifacts["ebpf_syscalls"].endswith("ebpf_syscalls.json")
    assert summary.artifacts["ebpf_raw"].endswith("ebpf_syscalls.raw")
    assert summary.artifacts["suggestions"].endswith("suggestions.json")
    assert report["total_events"] == 10
    assert report["tool_version"] == "bpftrace v0.test"
    assert report["kernel_release"]
    assert report["script_hash"].startswith("sha256:")
    assert report["read_per_second"] == 7.0
    assert report["write_per_second"] == 3.0
    assert report["events"] == [
        {"event": "read", "count": 7, "rate_per_second": 7.0},
        {"event": "write", "count": 3, "rate_per_second": 3.0},
    ]
    assert summary_json["collector"] == "ebpf_syscall"


def test_ebpf_syscall_script_avoids_end_probe_for_bpftrace_compatibility() -> None:
    script = EbpfSyscallCollector._script(pid=1234, duration_seconds=5)

    assert "END" not in script
    assert "interval:s:5" in script
    assert "print(@read);" in script
    assert "exit();" in script


def test_generate_syscall_advice_reports_high_read_write_rates() -> None:
    report = {
        "collector": "ebpf_syscall",
        "duration_seconds": 5,
        "total_events": 6000,
        "events": [
            {"event": "read", "count": 3100, "rate_per_second": 620.0},
            {"event": "write", "count": 2900, "rate_per_second": 580.0},
        ],
    }

    advice = generate_syscall_advice(report)

    assert advice["source"] == "ebpf_syscalls"
    assert advice["finding_count"] == 2
    assert {finding["rule_id"] for finding in advice["findings"]} == {
        "high_read_syscall_rate",
        "high_write_syscall_rate",
    }
    assert advice["findings"][0]["evidence"]["rate_per_second"] == 620.0
