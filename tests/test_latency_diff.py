import json

from minidrop_analysis.cli import main
from minidrop_analysis.latency_diff import compare_latency_reports, no_latency_baseline_report


def _report(read_tail: float, read_p99: str, read_count: int = 100) -> dict:
    return {
        "collector": "ebpf_io_latency",
        "created_at": "2026-06-20T00:00:00+00:00",
        "unit": "us",
        "total_events": read_count,
        "events": [
            {
                "event": "read",
                "total_count": read_count,
                "histogram": [
                    {"bucket": "0-10", "count": 90, "percent": 90.0},
                    {"bucket": "10-100", "count": 0, "percent": 0.0},
                    {"bucket": "100-1000", "count": 0, "percent": 0.0},
                    {"bucket": "1000-10000", "count": 10, "percent": read_tail},
                    {"bucket": "10000+", "count": 0, "percent": 0.0},
                ],
                "p50_bucket": "0-10",
                "p95_bucket": read_p99,
                "p99_bucket": read_p99,
                "tail_1ms_count": 10,
                "tail_1ms_percent": read_tail,
            }
        ],
    }


def test_compare_latency_reports_marks_regression_when_tail_grows() -> None:
    diff = compare_latency_reports(
        baseline=_report(read_tail=1.0, read_p99="10-100"),
        current=_report(read_tail=25.0, read_p99="1000-10000"),
        baseline_job_id="base",
        current_job_id="current",
    )

    assert diff["source"] == "ebpf_io_latency_diff"
    assert diff["comparison_available"] is True
    assert diff["baseline_job_id"] == "base"
    assert diff["current_job_id"] == "current"
    assert diff["events"][0]["verdict"] == "regressed"
    assert diff["events"][0]["tail_1ms_percent_delta"] == 24.0
    assert diff["finding_count"] == 1
    assert diff["findings"][0]["rule_id"] == "latency_regressed_vs_baseline"


def test_compare_latency_reports_marks_improvement_when_tail_shrinks() -> None:
    diff = compare_latency_reports(
        baseline=_report(read_tail=40.0, read_p99="1000-10000"),
        current=_report(read_tail=5.0, read_p99="10-100"),
    )

    assert diff["events"][0]["verdict"] == "improved"
    assert diff["finding_count"] == 0


def test_no_latency_baseline_report_is_not_an_error() -> None:
    report = no_latency_baseline_report(current_job_id="job-1")

    assert report["comparison_available"] is False
    assert report["current_job_id"] == "job-1"
    assert report["events"] == []


def test_compare_latency_cli_writes_diff_report(tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    output = tmp_path / "diff.json"
    baseline.write_text(json.dumps(_report(read_tail=1.0, read_p99="10-100")), encoding="utf-8-sig")
    current.write_text(json.dumps(_report(read_tail=25.0, read_p99="1000-10000")), encoding="utf-8-sig")

    exit_code = main(
        [
            "compare-latency",
            "--baseline",
            str(baseline),
            "--current",
            str(current),
            "--output",
            str(output),
            "--baseline-job-id",
            "job-base",
            "--current-job-id",
            "job-current",
        ]
    )

    diff = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert diff["source"] == "ebpf_io_latency_diff"
    assert diff["baseline_job_id"] == "job-base"
    assert diff["current_job_id"] == "job-current"
    assert diff["events"][0]["verdict"] == "regressed"
