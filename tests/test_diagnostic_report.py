from minidrop_analysis.report import build_diagnostic_report


def test_build_diagnostic_report_merges_artifact_findings_and_baseline_diff() -> None:
    job = {
        "job_id": "job-current",
        "status": "DONE",
        "reason": "job completed successfully",
        "spec": {
            "pid": 1234,
            "duration_seconds": 5,
            "sample_frequency": 99,
            "collector": "ebpf_io_latency",
            "target": {"comm": "io_latency_hotspot", "starttime": 42},
        },
    }
    artifacts = {
        "hotspots": {
            "total_samples": 100,
            "hotspots": [
                {"function": "hot_func", "self_percent": 80.0, "self_samples": 80, "inclusive_percent": 90.0}
            ],
        },
        "suggestions": {
            "source": "hotspots",
            "findings": [
                {
                    "rule_id": "cpu_self_hotspot",
                    "title": "CPU self hotspot",
                    "severity": "HIGH",
                    "function": "hot_func",
                    "reason": "self_percent 80 >= 50",
                    "next_actions": ["check hot_func loop"],
                }
            ],
        },
        "ebpf_syscalls": {
            "total_events": 1000,
            "duration_seconds": 5,
            "events": [{"event": "read", "count": 900, "rate_per_second": 180.0}],
        },
        "ebpf_io_latency": {
            "total_events": 100,
            "unit": "us",
            "events": [
                {
                    "event": "read",
                    "total_count": 100,
                    "p50_bucket": "10-100",
                    "p99_bucket": "1000-10000",
                    "tail_1ms_percent": 25.0,
                }
            ],
        },
    }
    baseline_diff = {
        "comparison_available": True,
        "baseline_job_id": "job-base",
        "current_job_id": "job-current",
        "events": [
            {
                "event": "read",
                "verdict": "regressed",
                "tail_1ms_percent_delta": 24.0,
                "p99_bucket_delta": 1,
            }
        ],
        "findings": [
            {
                "rule_id": "latency_regressed_vs_baseline",
                "title": "Latency regressed vs baseline",
                "severity": "HIGH",
                "target": "read",
                "reason": "read tail got worse",
                "next_actions": ["compare workload input"],
            }
        ],
    }

    report = build_diagnostic_report(job=job, artifacts=artifacts, baseline_diff=baseline_diff)

    assert report["source"] == "diagnostic_report"
    assert report["severity"] == "HIGH"
    assert report["finding_count"] == 2
    assert report["next_actions"] == ["check hot_func loop", "compare workload input"]
    assert {section["section_id"] for section in report["sections"]} >= {
        "job_overview",
        "target_process",
        "cpu_hotspots",
        "ebpf_syscalls",
        "ebpf_io_latency",
        "baseline_diff",
        "findings",
    }


def test_build_diagnostic_report_handles_done_job_without_findings() -> None:
    job = {
        "job_id": "job-ok",
        "status": "DONE",
        "reason": "job completed successfully",
        "spec": {"collector": "perf", "pid": 1234},
    }

    report = build_diagnostic_report(job=job, artifacts={})

    assert report["severity"] == "OK"
    assert report["finding_count"] == 0
    assert report["sections"][0]["section_id"] == "job_overview"
