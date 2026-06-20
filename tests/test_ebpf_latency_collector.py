import json
from pathlib import Path

from minidrop_analysis.ebpf_latency import (
    EbpfIoLatencyCollector,
    generate_latency_advice,
    parse_bpftrace_latency_counts,
)


class FakeEbpfIoLatencyCollector(EbpfIoLatencyCollector):
    def _capture_bpftrace(self, pid: int, duration_seconds: int, script: str | None = None) -> str:
        return """
Attaching 5 probes...
@read_0_10: 60
@read_1000_10000: 40
@write_0_10: 100
"""

    def _tool_version(self) -> str:
        return "bpftrace v0.test"


def test_parse_bpftrace_latency_counts_defaults_missing_buckets_to_zero() -> None:
    counts = parse_bpftrace_latency_counts("@read_0_10: 12\n@write_1000_10000: 2\n")

    assert counts["read"]["0_10"] == 12
    assert counts["read"]["10_100"] == 0
    assert counts["write"]["1000_10000"] == 2
    assert counts["write"]["10000_plus"] == 0


def test_ebpf_io_latency_collector_writes_report_summary_and_suggestions(tmp_path: Path) -> None:
    summary = FakeEbpfIoLatencyCollector().collect(
        pid=1234,
        duration_seconds=5,
        sample_frequency=99,
        output_dir=str(tmp_path),
    )

    report = json.loads((tmp_path / "ebpf_io_latency.json").read_text(encoding="utf-8"))
    suggestions = json.loads((tmp_path / "suggestions.json").read_text(encoding="utf-8"))
    summary_json = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))

    assert summary.collector == "ebpf_io_latency"
    assert summary.artifacts["ebpf_io_latency"].endswith("ebpf_io_latency.json")
    assert summary.artifacts["ebpf_io_latency_raw"].endswith("ebpf_io_latency.raw")
    assert summary.artifacts["suggestions"].endswith("suggestions.json")
    assert report["tool_version"] == "bpftrace v0.test"
    assert report["kernel_release"]
    assert report["script_hash"].startswith("sha256:")
    assert report["unit"] == "us"
    assert report["total_events"] == 200
    read = report["events"][0]
    assert read["event"] == "read"
    assert read["total_count"] == 100
    assert read["p50_bucket"] == "0-10"
    assert read["p99_bucket"] == "1000-10000"
    assert read["tail_1ms_percent"] == 40.0
    assert suggestions["source"] == "ebpf_io_latency"
    assert suggestions["finding_count"] == 3
    assert summary_json["collector"] == "ebpf_io_latency"


def test_ebpf_io_latency_script_tracks_enter_exit_without_end_probe() -> None:
    script = EbpfIoLatencyCollector._script(pid=1234, duration_seconds=5)

    assert "END" not in script
    assert "tracepoint:syscalls:sys_enter_read" in script
    assert "tracepoint:syscalls:sys_exit_read" in script
    assert "@read_start[tid]" in script
    assert "interval:s:5" in script
    assert "print(@read_1000_10000);" in script
    assert "exit();" in script


def test_generate_latency_advice_reports_tail_and_bimodal_distribution() -> None:
    report = {
        "collector": "ebpf_io_latency",
        "duration_seconds": 5,
        "total_events": 100,
        "events": [
            {
                "event": "read",
                "total_count": 100,
                "histogram": [
                    {"bucket": "0-10", "lower_us": 0, "upper_us": 10, "count": 60, "percent": 60.0},
                    {"bucket": "10-100", "lower_us": 10, "upper_us": 100, "count": 0, "percent": 0.0},
                    {"bucket": "100-1000", "lower_us": 100, "upper_us": 1000, "count": 0, "percent": 0.0},
                    {"bucket": "1000-10000", "lower_us": 1000, "upper_us": 10000, "count": 40, "percent": 40.0},
                    {"bucket": "10000+", "lower_us": 10000, "upper_us": None, "count": 0, "percent": 0.0},
                ],
                "p50_bucket": "0-10",
                "p95_bucket": "1000-10000",
                "p99_bucket": "1000-10000",
                "tail_1ms_count": 40,
                "tail_1ms_percent": 40.0,
            }
        ],
    }

    advice = generate_latency_advice(report)

    assert advice["source"] == "ebpf_io_latency"
    assert {finding["rule_id"] for finding in advice["findings"]} == {
        "io_latency_p99_far_from_p50",
        "io_latency_tail_over_1ms",
        "io_latency_bimodal_distribution",
    }
