from __future__ import annotations


BUCKET_ORDER = ["0-10", "10-100", "100-1000", "1000-10000", "10000+"]


def compare_latency_reports(
    baseline: dict,
    current: dict,
    baseline_job_id: str | None = None,
    current_job_id: str | None = None,
) -> dict:
    baseline_events = _events_by_name(baseline)
    current_events = _events_by_name(current)
    event_names = sorted(set(baseline_events) | set(current_events))
    events = [
        _compare_event(name, baseline_events.get(name, {}), current_events.get(name, {}))
        for name in event_names
    ]
    findings = _build_findings(events)
    return {
        "source": "ebpf_io_latency_diff",
        "comparison_available": True,
        "baseline_job_id": baseline_job_id,
        "current_job_id": current_job_id,
        "baseline_created_at": baseline.get("created_at"),
        "current_created_at": current.get("created_at"),
        "unit": current.get("unit") or baseline.get("unit") or "us",
        "event_count": len(events),
        "events": events,
        "finding_count": len(findings),
        "findings": findings,
    }


def no_latency_baseline_report(current_job_id: str | None = None) -> dict:
    return {
        "source": "ebpf_io_latency_diff",
        "comparison_available": False,
        "baseline_job_id": None,
        "current_job_id": current_job_id,
        "reason": "no previous ebpf_io_latency baseline job found",
        "event_count": 0,
        "events": [],
        "finding_count": 0,
        "findings": [],
    }


def _events_by_name(report: dict) -> dict[str, dict]:
    return {
        str(event.get("event", "")): event
        for event in report.get("events", [])
        if isinstance(event, dict) and event.get("event")
    }


def _compare_event(event_name: str, baseline_event: dict, current_event: dict) -> dict:
    baseline_tail = _float(baseline_event.get("tail_1ms_percent"))
    current_tail = _float(current_event.get("tail_1ms_percent"))
    baseline_p99 = baseline_event.get("p99_bucket")
    current_p99 = current_event.get("p99_bucket")
    baseline_p50 = baseline_event.get("p50_bucket")
    current_p50 = current_event.get("p50_bucket")
    bucket_diffs = _compare_buckets(baseline_event, current_event)
    return {
        "event": event_name,
        "baseline_total_count": int(baseline_event.get("total_count", 0)),
        "current_total_count": int(current_event.get("total_count", 0)),
        "baseline_p50_bucket": baseline_p50,
        "current_p50_bucket": current_p50,
        "p50_bucket_delta": _bucket_delta(baseline_p50, current_p50),
        "baseline_p99_bucket": baseline_p99,
        "current_p99_bucket": current_p99,
        "p99_bucket_delta": _bucket_delta(baseline_p99, current_p99),
        "baseline_tail_1ms_percent": baseline_tail,
        "current_tail_1ms_percent": current_tail,
        "tail_1ms_percent_delta": round(current_tail - baseline_tail, 2),
        "verdict": _verdict(baseline_tail, current_tail, baseline_p99, current_p99),
        "buckets": bucket_diffs,
    }


def _compare_buckets(baseline_event: dict, current_event: dict) -> list[dict]:
    baseline_buckets = _bucket_map(baseline_event)
    current_buckets = _bucket_map(current_event)
    return [
        {
            "bucket": bucket,
            "baseline_count": int(baseline_buckets.get(bucket, {}).get("count", 0)),
            "current_count": int(current_buckets.get(bucket, {}).get("count", 0)),
            "baseline_percent": _float(baseline_buckets.get(bucket, {}).get("percent")),
            "current_percent": _float(current_buckets.get(bucket, {}).get("percent")),
            "percent_delta": round(
                _float(current_buckets.get(bucket, {}).get("percent"))
                - _float(baseline_buckets.get(bucket, {}).get("percent")),
                2,
            ),
        }
        for bucket in BUCKET_ORDER
    ]


def _bucket_map(event: dict) -> dict[str, dict]:
    return {
        str(bucket.get("bucket", "")): bucket
        for bucket in event.get("histogram", [])
        if isinstance(bucket, dict) and bucket.get("bucket")
    }


def _bucket_delta(baseline_bucket: str | None, current_bucket: str | None) -> int:
    return _bucket_index(current_bucket) - _bucket_index(baseline_bucket)


def _bucket_index(bucket: str | None) -> int:
    if bucket not in BUCKET_ORDER:
        return -1
    return BUCKET_ORDER.index(bucket)


def _float(value: object) -> float:
    try:
        return round(float(value), 2)
    except (TypeError, ValueError):
        return 0.0


def _verdict(baseline_tail: float, current_tail: float, baseline_p99: str | None, current_p99: str | None) -> str:
    tail_delta = current_tail - baseline_tail
    p99_delta = _bucket_delta(baseline_p99, current_p99)
    if tail_delta >= 10.0 or p99_delta >= 1:
        return "regressed"
    if tail_delta <= -10.0 or p99_delta <= -1:
        return "improved"
    return "similar"


def _build_findings(events: list[dict]) -> list[dict]:
    findings = []
    for event in events:
        if event["verdict"] == "regressed":
            findings.append(
                {
                    "rule_id": "latency_regressed_vs_baseline",
                    "title": "Latency regressed vs baseline",
                    "severity": "HIGH",
                    "target": event["event"],
                    "matched_condition": "tail_1ms_percent increased by >= 10 points or p99 bucket became slower",
                    "reason": (
                        f"{event['event']} tail >=1ms changed "
                        f"{event['baseline_tail_1ms_percent']}% -> {event['current_tail_1ms_percent']}%; "
                        f"p99 {event['baseline_p99_bucket']} -> {event['current_p99_bucket']}"
                    ),
                    "evidence": {
                        "baseline_tail_1ms_percent": event["baseline_tail_1ms_percent"],
                        "current_tail_1ms_percent": event["current_tail_1ms_percent"],
                        "tail_1ms_percent_delta": event["tail_1ms_percent_delta"],
                        "baseline_p99_bucket": event["baseline_p99_bucket"],
                        "current_p99_bucket": event["current_p99_bucket"],
                        "p99_bucket_delta": event["p99_bucket_delta"],
                    },
                    "advice": "当前任务相对基线出现 IO latency 退化，建议检查负载变化、同步 IO、阻塞等待或磁盘/管道队列拥塞。",
                    "next_actions": [
                        "确认 baseline 和 current 是否为同一 workload 或同类负载。",
                        "查看退化最明显的 latency bucket，定位慢路径是否集中在 >=1ms。",
                        "结合 eBPF syscall rate 和 perf 热点判断是频率升高还是单次调用变慢。",
                    ],
                }
            )
    return findings
