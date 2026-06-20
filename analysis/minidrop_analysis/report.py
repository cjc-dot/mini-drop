from __future__ import annotations


SEVERITY_ORDER = {"OK": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4}


def build_diagnostic_report(
    job: dict,
    artifacts: dict[str, dict | None],
    baseline_diff: dict | None = None,
    data_quality: list[str] | None = None,
) -> dict:
    findings = _collect_findings(artifacts=artifacts, baseline_diff=baseline_diff)
    severity = _overall_severity(job=job, findings=findings)
    sections = _build_sections(job=job, artifacts=artifacts, baseline_diff=baseline_diff, findings=findings)
    return {
        "source": "diagnostic_report",
        "job_id": job.get("job_id"),
        "status": job.get("status", "UNKNOWN"),
        "collector": job.get("spec", {}).get("collector", "unknown"),
        "target": job.get("spec", {}).get("target", {}),
        "severity": severity,
        "summary": _summary(job=job, severity=severity, findings=findings, baseline_diff=baseline_diff),
        "finding_count": len(findings),
        "findings": findings,
        "next_actions": _collect_next_actions(findings),
        "sections": sections,
        "data_quality": data_quality or [],
    }


def _build_sections(
    job: dict,
    artifacts: dict[str, dict | None],
    baseline_diff: dict | None,
    findings: list[dict],
) -> list[dict]:
    sections = [_job_overview_section(job)]

    target = job.get("spec", {}).get("target", {})
    if target:
        sections.append(_target_section(target))

    hotspots = artifacts.get("hotspots")
    if hotspots:
        sections.append(_hotspot_section(hotspots))

    syscalls = artifacts.get("ebpf_syscalls")
    if syscalls:
        sections.append(_syscall_section(syscalls))

    latency = artifacts.get("ebpf_io_latency")
    if latency:
        sections.append(_latency_section(latency))

    if baseline_diff:
        sections.append(_baseline_diff_section(baseline_diff))

    if findings:
        sections.append(_findings_section(findings))

    return sections


def _job_overview_section(job: dict) -> dict:
    spec = job.get("spec", {})
    return {
        "section_id": "job_overview",
        "title": "Job Overview",
        "items": [
            _item("Status", job.get("status", "UNKNOWN")),
            _item("Reason", job.get("reason", "-")),
            _item("Collector", spec.get("collector", "-")),
            _item("PID", spec.get("pid", "-")),
            _item("Duration", f"{spec.get('duration_seconds', '-')}s"),
            _item("Frequency", f"{spec.get('sample_frequency', '-')}Hz"),
        ],
    }


def _target_section(target: dict) -> dict:
    return {
        "section_id": "target_process",
        "title": "Target Process",
        "items": [
            _item("Command", target.get("comm") or target.get("cmdline") or "-"),
            _item("Cmdline", target.get("cmdline", "-")),
            _item("Starttime", target.get("starttime", "-")),
        ],
    }


def _hotspot_section(report: dict) -> dict:
    hotspots = report.get("hotspots", []) if isinstance(report.get("hotspots"), list) else []
    top_self = max(hotspots, key=lambda item: _number(item.get("self_percent")), default=None)
    top_inclusive = max(hotspots, key=lambda item: _number(item.get("inclusive_percent")), default=None)
    items = [_item("Total samples", report.get("total_samples", 0))]
    if top_self:
        items.append(
            _item(
                "Top self hotspot",
                top_self.get("function", "-"),
                evidence={
                    "self_percent": top_self.get("self_percent", 0),
                    "self_samples": top_self.get("self_samples", 0),
                },
            )
        )
    if top_inclusive:
        items.append(
            _item(
                "Top inclusive hotspot",
                top_inclusive.get("function", "-"),
                evidence={
                    "inclusive_percent": top_inclusive.get("inclusive_percent", 0),
                    "inclusive_samples": top_inclusive.get("inclusive_samples", 0),
                },
            )
        )
    return {"section_id": "cpu_hotspots", "title": "CPU Hotspots", "items": items}


def _syscall_section(report: dict) -> dict:
    events = report.get("events", []) if isinstance(report.get("events"), list) else []
    items = [
        _item("Total events", report.get("total_events", 0)),
        _item("Duration", f"{report.get('duration_seconds', '-')}s"),
    ]
    for event in sorted(events, key=lambda item: _number(item.get("rate_per_second")), reverse=True)[:3]:
        items.append(
            _item(
                f"{event.get('event', 'event')} rate",
                f"{event.get('rate_per_second', 0)}/s",
                evidence={"count": event.get("count", 0)},
            )
        )
    return {"section_id": "ebpf_syscalls", "title": "eBPF Syscalls", "items": items}


def _latency_section(report: dict) -> dict:
    events = report.get("events", []) if isinstance(report.get("events"), list) else []
    items = [
        _item("Total events", report.get("total_events", 0)),
        _item("Unit", report.get("unit", "us")),
    ]
    for event in events:
        items.append(
            _item(
                f"{event.get('event', 'event')} latency",
                f"p50 {event.get('p50_bucket', '-')} / p99 {event.get('p99_bucket', '-')}",
                evidence={
                    "tail_1ms_percent": event.get("tail_1ms_percent", 0),
                    "total_count": event.get("total_count", 0),
                },
            )
        )
    return {"section_id": "ebpf_io_latency", "title": "eBPF IO Latency", "items": items}


def _baseline_diff_section(diff: dict) -> dict:
    if not diff.get("comparison_available"):
        return {
            "section_id": "baseline_diff",
            "title": "Baseline Diff",
            "items": [_item("Status", "No baseline", evidence={"reason": diff.get("reason", "-")})],
        }

    items = [
        _item("Baseline job", diff.get("baseline_job_id", "-")),
        _item("Current job", diff.get("current_job_id", "-")),
    ]
    for event in diff.get("events", []):
        items.append(
            _item(
                f"{event.get('event', 'event')} verdict",
                event.get("verdict", "unknown"),
                evidence={
                    "tail_1ms_percent_delta": event.get("tail_1ms_percent_delta", 0),
                    "p99_bucket_delta": event.get("p99_bucket_delta", 0),
                },
            )
        )
    return {"section_id": "baseline_diff", "title": "Baseline Diff", "items": items}


def _findings_section(findings: list[dict]) -> dict:
    return {
        "section_id": "findings",
        "title": "Findings",
        "items": [
            _item(
                finding.get("title") or finding.get("rule_id") or "Finding",
                finding.get("target") or finding.get("function") or "-",
                evidence={
                    "severity": finding.get("severity", "INFO"),
                    "reason": finding.get("reason") or finding.get("matched_condition") or "",
                },
            )
            for finding in findings
        ],
    }


def _collect_findings(artifacts: dict[str, dict | None], baseline_diff: dict | None) -> list[dict]:
    findings: list[dict] = []
    suggestions = artifacts.get("suggestions")
    if suggestions and isinstance(suggestions.get("findings"), list):
        for finding in suggestions["findings"]:
            copied = dict(finding)
            copied.setdefault("source", suggestions.get("source", "suggestions"))
            findings.append(copied)

    if baseline_diff and isinstance(baseline_diff.get("findings"), list):
        for finding in baseline_diff["findings"]:
            copied = dict(finding)
            copied.setdefault("source", "baseline_diff")
            findings.append(copied)

    return sorted(findings, key=lambda item: SEVERITY_ORDER.get(item.get("severity", "INFO"), 1), reverse=True)


def _collect_next_actions(findings: list[dict]) -> list[str]:
    actions: list[str] = []
    for finding in findings:
        for action in finding.get("next_actions", []):
            if action not in actions:
                actions.append(action)
    return actions[:6]


def _overall_severity(job: dict, findings: list[dict]) -> str:
    if job.get("status") == "FAILED":
        return "HIGH"
    if not findings:
        return "OK"
    score = max(SEVERITY_ORDER.get(finding.get("severity", "INFO"), 1) for finding in findings)
    for severity, value in SEVERITY_ORDER.items():
        if value == score:
            return severity
    return "INFO"


def _summary(job: dict, severity: str, findings: list[dict], baseline_diff: dict | None) -> str:
    if job.get("status") == "FAILED":
        return f"任务失败：{job.get('reason') or job.get('error_message') or 'unknown error'}。"
    if severity == "HIGH":
        return f"发现 {len(findings)} 个高优先级诊断项，建议优先处理最明显的热点或退化。"
    if findings:
        return f"发现 {len(findings)} 个可优化项，建议结合证据和源码逐项确认。"
    if baseline_diff and baseline_diff.get("comparison_available"):
        verdicts = {event.get("verdict") for event in baseline_diff.get("events", [])}
        if "improved" in verdicts and "regressed" not in verdicts:
            return "当前任务相对基线没有明显退化，部分指标有所改善。"
        return "当前任务相对基线没有明显退化。"
    return "当前任务已完成，未发现明显高风险热点或退化信号。"


def _item(label: str, value: object, evidence: dict | None = None) -> dict:
    return {"label": label, "value": value, "evidence": evidence or {}}


def _number(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
