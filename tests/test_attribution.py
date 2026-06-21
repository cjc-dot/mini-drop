from minidrop_analysis.attribution import build_attribution_report


def test_build_attribution_report_creates_claims_from_findings_and_sections() -> None:
    diagnostic_report = {
        "source": "diagnostic_report",
        "job_id": "job-1",
        "collector": "perf",
        "findings": [
            {
                "rule_id": "cpu_self_hotspot",
                "title": "CPU self hotspot",
                "severity": "HIGH",
                "function": "hot_func",
                "evidence": {
                    "self_percent": 98.0,
                    "self_samples": 98,
                    "inclusive_percent": 98.0,
                },
            }
        ],
        "sections": [
            {
                "section_id": "ebpf_io_latency",
                "items": [
                    {
                        "label": "read latency",
                        "value": "p50 1000-10000 / p99 1000-10000",
                        "evidence": {
                            "tail_1ms_percent": 45.0,
                            "total_count": 100,
                        },
                    }
                ],
            }
        ],
    }

    report = build_attribution_report(diagnostic_report)

    assert report["source"] == "diagnostic_report"
    assert report["job_id"] == "job-1"
    assert report["collector"] == "perf"
    assert report["severity"] == "HIGH"
    assert report["claim_count"] == 2
    claim_ids = {claim["claim_id"] for claim in report["claims"]}
    assert "cpu_hotspot:hot_func" in claim_ids
    assert "io_latency:read" in claim_ids
    cpu_claim = next(claim for claim in report["claims"] if claim["claim_id"] == "cpu_hotspot:hot_func")
    assert cpu_claim["confidence"] == "HIGH"
    assert cpu_claim["confidence_score"] >= 80
    assert cpu_claim["triage_priority"] == "P1"
    assert cpu_claim["evidence_count"] == 1
    assert cpu_claim["evidence_sources"] == ["suggestions"]
    assert cpu_claim["missing_evidence"]
    assert cpu_claim["evidence"][0]["source"] == "suggestions"
    assert cpu_claim["next_actions"]
    assert report["ranking_policy"]["score_range"] == "0-100"


def test_build_attribution_report_handles_report_without_findings() -> None:
    report = build_attribution_report(
        {
            "source": "diagnostic_report",
            "job_id": "job-ok",
            "collector": "perf",
            "findings": [],
            "sections": [],
        }
    )

    assert report["severity"] == "OK"
    assert report["claim_count"] == 0
    assert report["claims"] == []
