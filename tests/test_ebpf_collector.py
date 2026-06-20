import json
from pathlib import Path

from minidrop_analysis.ebpf import EbpfSyscallCollector, parse_bpftrace_syscall_counts


class FakeEbpfSyscallCollector(EbpfSyscallCollector):
    def _capture_bpftrace(self, pid: int, duration_seconds: int) -> str:
        return """
Attaching 3 probes...
@read: 7
@write: 3
"""


def test_parse_bpftrace_syscall_counts() -> None:
    output = "Attaching 3 probes...\n@read: 12\n@write: 5\n"

    assert parse_bpftrace_syscall_counts(output) == {"read": 12, "write": 5}


def test_parse_bpftrace_syscall_counts_defaults_missing_maps_to_zero() -> None:
    output = "Attaching 3 probes...\n"

    assert parse_bpftrace_syscall_counts(output) == {"read": 0, "write": 0}


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
    assert report["total_events"] == 10
    assert report["events"] == [{"event": "read", "count": 7}, {"event": "write", "count": 3}]
    assert summary_json["collector"] == "ebpf_syscall"


def test_ebpf_syscall_script_avoids_end_probe_for_bpftrace_compatibility() -> None:
    script = EbpfSyscallCollector._script(pid=1234, duration_seconds=5)

    assert "END" not in script
    assert "interval:s:5" in script
    assert "print(@read);" in script
    assert "exit();" in script
