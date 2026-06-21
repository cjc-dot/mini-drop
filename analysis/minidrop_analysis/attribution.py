from __future__ import annotations


SEVERITY_ORDER = {"OK": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4}


def build_attribution_report(diagnostic_report: dict) -> dict:
    """Build deterministic root-cause claims from an existing diagnostic report."""
    base_claims = _deduplicate_claims(
        [
            *_claims_from_findings(diagnostic_report),
            *_claims_from_sections(diagnostic_report),
        ]
    )
    claims = _score_claims(
        _deduplicate_claims([*base_claims, *_fusion_claims(base_claims)]),
        diagnostic_report,
    )
    severity = _overall_severity(claims)
    return {
        "source": "diagnostic_report",
        "job_id": diagnostic_report.get("job_id"),
        "collector": diagnostic_report.get("collector", "unknown"),
        "severity": severity,
        "claim_count": len(claims),
        "summary": _summary(claims, severity),
        "ranking_policy": {
            "description": "Claims are ranked by severity, confidence_score, and evidence_count.",
            "score_range": "0-100",
        },
        "related_evidence_jobs": diagnostic_report.get("related_evidence_jobs", []),
        "claims": claims,
    }


def _claims_from_findings(report: dict) -> list[dict]:
    claims: list[dict] = []
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        return claims
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule_id = str(finding.get("rule_id") or "")
        source = str(finding.get("source") or "suggestions")
        if rule_id == "cpu_self_hotspot":
            claims.append(_cpu_hotspot_claim(finding, source=source))
        elif rule_id == "python_self_hotspot":
            claims.append(_python_hotspot_claim(finding, source=source))
        elif rule_id in {"high_read_syscall_rate", "high_write_syscall_rate", "write_syscall_dominates_read"}:
            claims.append(_syscall_rate_claim(finding, source=source))
        elif rule_id in {
            "io_latency_tail_over_1ms",
            "io_latency_p99_far_from_p50",
            "io_latency_bimodal_distribution",
        }:
            claims.append(_io_latency_claim(finding, source=source))
        elif rule_id in {"latency_regressed_vs_baseline", "io_latency_regressed_vs_baseline"}:
            claims.append(_baseline_regression_claim(finding, source="baseline_diff"))
    return [claim for claim in claims if claim]


def _claims_from_sections(report: dict) -> list[dict]:
    claims: list[dict] = []
    sections = report.get("sections", [])
    if not isinstance(sections, list):
        return claims
    for section in sections:
        if not isinstance(section, dict):
            continue
        section_id = section.get("section_id")
        items = section.get("items", []) if isinstance(section.get("items"), list) else []
        if section_id == "cpu_hotspots":
            claim = _claim_from_cpu_section(items)
            if claim:
                claims.append(claim)
        elif section_id == "python_profile":
            claim = _claim_from_python_section(items)
            if claim:
                claims.append(claim)
        elif section_id == "ebpf_syscalls":
            claims.extend(_claims_from_syscall_section(items))
        elif section_id == "ebpf_io_latency":
            claims.extend(_claims_from_latency_section(items))
        elif section_id == "baseline_diff":
            claims.extend(_claims_from_baseline_section(items))
    return claims


def _cpu_hotspot_claim(finding: dict, source: str) -> dict:
    function = finding.get("function") or finding.get("target") or "unknown"
    evidence = finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else {}
    self_percent = _number(evidence.get("self_percent"))
    severity = finding.get("severity", "HIGH")
    return _claim(
        claim_id=f"cpu_hotspot:{function}",
        title=f"CPU 热点集中在 {function}",
        root_cause=(
            f"{function} 的自身 CPU 采样占比较高，优先怀疑循环次数过多、重复计算、"
            "算法复杂度或内存访问局部性问题。"
        ),
        severity=severity,
        confidence=_confidence([self_percent >= 70, self_percent >= 50]),
        evidence=[
            _evidence(
                evidence_id=f"finding:{finding.get('rule_id', 'cpu_self_hotspot')}:{function}",
                source=source,
                summary=f"{function} self_percent={self_percent:g}%",
                data={"finding": finding},
            )
        ],
        next_actions=[
            f"打开 {function} 的源码，确认主要循环和重复计算位置。",
            "结合输入规模和循环计数，判断热点是否符合预期。",
            "优先尝试减少重复计算、缓存中间结果或提前退出。",
        ],
    )


def _python_hotspot_claim(finding: dict, source: str) -> dict:
    function = finding.get("function") or finding.get("target") or "unknown"
    evidence = finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else {}
    self_percent = _number(evidence.get("self_percent"))
    file_name = evidence.get("file") or "-"
    line = evidence.get("line") or "-"
    return _claim(
        claim_id=f"python_hotspot:{function}:{file_name}:{line}",
        title=f"Python 用户态热点集中在 {function}",
        root_cause=(
            f"{function} 在 Python 用户态采样中占比较高，可能存在解释器层面的循环、对象分配、"
            "字符串/列表处理或小粒度重复操作。"
        ),
        severity=finding.get("severity", "MEDIUM"),
        confidence=_confidence([self_percent >= 70, self_percent >= 50]),
        evidence=[
            _evidence(
                evidence_id=f"finding:{finding.get('rule_id', 'python_self_hotspot')}:{function}",
                source=source,
                summary=f"{function} self_percent={self_percent:g}% at {file_name}:{line}",
                data={"finding": finding},
            )
        ],
        next_actions=[
            f"打开 {file_name}:{line}，确认热点是否集中在循环或重复对象创建。",
            "使用更小输入复现实验，确认热点占比是否稳定。",
            "优先尝试缓存中间结果、合并小操作，必要时考虑下沉到 C/C++ 实现。",
        ],
    )


def _syscall_rate_claim(finding: dict, source: str) -> dict:
    target = finding.get("target") or finding.get("function") or "syscall"
    evidence = finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else {}
    rate = _number(evidence.get("rate_per_second") or evidence.get(f"{target}_per_second"))
    return _claim(
        claim_id=f"syscall_rate:{target}",
        title=f"{target} 系统调用频率偏高",
        root_cause=(
            f"{target} 系统调用频率偏高，可能存在高频小块 IO、循环内重复读写、日志刷写过密"
            "或缺少批量缓冲。"
        ),
        severity=finding.get("severity", "MEDIUM"),
        confidence=_confidence([rate >= 1000, rate >= 500]),
        evidence=[
            _evidence(
                evidence_id=f"finding:{finding.get('rule_id', 'syscall_rate')}:{target}",
                source=source,
                summary=f"{target} rate={rate:g}/s",
                data={"finding": finding},
            )
        ],
        next_actions=[
            f"定位触发 {target} 的业务代码路径，确认是否处于循环或请求关键路径。",
            "统计单次读写大小，判断是否可以批量化。",
            "结合 perf/py-spy 热点确认系统调用开销是否与 CPU 热点相互印证。",
        ],
    )


def _io_latency_claim(finding: dict, source: str) -> dict:
    target = finding.get("target") or finding.get("function") or "io"
    evidence = finding.get("evidence", {}) if isinstance(finding.get("evidence"), dict) else {}
    tail_percent = _number(evidence.get("tail_1ms_percent"))
    return _claim(
        claim_id=f"io_latency:{target}",
        title=f"{target} IO 延迟长尾明显",
        root_cause=(
            f"{target} 的 IO 延迟分布存在长尾，可能来自阻塞 IO、慢设备、管道等待、同步刷写"
            "或缓存命中/真实落盘两类路径混合。"
        ),
        severity=finding.get("severity", "MEDIUM"),
        confidence=_confidence([tail_percent >= 30, tail_percent >= 5]),
        evidence=[
            _evidence(
                evidence_id=f"finding:{finding.get('rule_id', 'io_latency')}:{target}",
                source=source,
                summary=f"{target} tail_1ms_percent={tail_percent:g}%",
                data={"finding": finding},
            )
        ],
        next_actions=[
            f"确认 {target} 对应的文件描述符类型和业务路径。",
            "检查是否可以使用缓冲、批量处理或异步化减少阻塞。",
            "与基线对比 p99/tail 指标，判断是长期问题还是版本退化。",
        ],
    )


def _baseline_regression_claim(finding: dict, source: str) -> dict:
    target = finding.get("target") or finding.get("function") or "latency"
    return _claim(
        claim_id=f"baseline_regression:{target}",
        title=f"{target} 相比基线出现退化",
        root_cause=(
            f"{target} 当前采样结果相对历史基线变差，说明问题更可能来自近期代码、输入、环境或负载变化。"
        ),
        severity=finding.get("severity", "HIGH"),
        confidence="MEDIUM",
        evidence=[
            _evidence(
                evidence_id=f"finding:{finding.get('rule_id', 'baseline_regression')}:{target}",
                source=source,
                summary=str(finding.get("reason") or finding.get("matched_condition") or "baseline regression"),
                data={"finding": finding},
            )
        ],
        next_actions=[
            "确认 baseline 与 current 的输入规模、运行环境和采样参数一致。",
            "优先 diff 最近修改，定位引入退化的代码路径。",
            "重新采样至少两次，排除偶发系统抖动。",
        ],
    )


def _claim_from_cpu_section(items: list[dict]) -> dict | None:
    for item in items:
        if item.get("label") != "Top self hotspot":
            continue
        evidence = item.get("evidence", {}) if isinstance(item.get("evidence"), dict) else {}
        self_percent = _number(evidence.get("self_percent"))
        if self_percent < 50:
            return None
        function = item.get("value") or "unknown"
        return _cpu_hotspot_claim(
            {
                "rule_id": "cpu_self_hotspot",
                "title": "CPU self hotspot",
                "severity": "HIGH" if self_percent >= 80 else "MEDIUM",
                "function": function,
                "evidence": evidence,
            },
            source="diagnostic_section",
        )
    return None


def _claim_from_python_section(items: list[dict]) -> dict | None:
    for item in items:
        evidence = item.get("evidence", {}) if isinstance(item.get("evidence"), dict) else {}
        value = str(item.get("value") or "")
        if not value.startswith("self "):
            continue
        self_percent = _parse_self_percent(value)
        if self_percent < 50:
            continue
        return _python_hotspot_claim(
            {
                "rule_id": "python_self_hotspot",
                "title": "Python self hotspot",
                "severity": "MEDIUM",
                "function": item.get("label") or "unknown",
                "evidence": {
                    **evidence,
                    "self_percent": self_percent,
                },
            },
            source="diagnostic_section",
        )
    return None


def _claims_from_syscall_section(items: list[dict]) -> list[dict]:
    claims: list[dict] = []
    for item in items:
        label = str(item.get("label") or "")
        if not label.endswith(" rate"):
            continue
        rate = _parse_rate(item.get("value"))
        if rate < 500:
            continue
        event = label.removesuffix(" rate")
        claims.append(
            _syscall_rate_claim(
                {
                    "rule_id": f"high_{event}_syscall_rate",
                    "title": "High syscall rate",
                    "severity": "MEDIUM",
                    "target": event,
                    "evidence": {
                        **(item.get("evidence", {}) if isinstance(item.get("evidence"), dict) else {}),
                        "rate_per_second": rate,
                    },
                },
                source="diagnostic_section",
            )
        )
    return claims


def _claims_from_latency_section(items: list[dict]) -> list[dict]:
    claims: list[dict] = []
    for item in items:
        label = str(item.get("label") or "")
        if not label.endswith(" latency"):
            continue
        evidence = item.get("evidence", {}) if isinstance(item.get("evidence"), dict) else {}
        tail_percent = _number(evidence.get("tail_1ms_percent"))
        if tail_percent < 5:
            continue
        event = label.removesuffix(" latency")
        claims.append(
            _io_latency_claim(
                {
                    "rule_id": "io_latency_tail_over_1ms",
                    "title": "IO latency has visible tail over 1ms",
                    "severity": "MEDIUM",
                    "target": event,
                    "evidence": evidence,
                },
                source="diagnostic_section",
            )
        )
    return claims


def _claims_from_baseline_section(items: list[dict]) -> list[dict]:
    claims: list[dict] = []
    for item in items:
        label = str(item.get("label") or "")
        if not label.endswith(" verdict") or item.get("value") != "regressed":
            continue
        target = label.removesuffix(" verdict")
        claims.append(
            _baseline_regression_claim(
                {
                    "rule_id": "latency_regressed_vs_baseline",
                    "title": "Latency regressed vs baseline",
                    "severity": "HIGH",
                    "target": target,
                    "reason": f"{target} verdict is regressed",
                    "evidence": item.get("evidence", {}),
                },
                source="diagnostic_section",
            )
        )
    return claims


def _fusion_claims(claims: list[dict]) -> list[dict]:
    cpu_claim = _first_claim(claims, ("cpu_hotspot:", "python_hotspot:"))
    syscall_claim = _first_claim(claims, ("syscall_rate:",))
    latency_claim = _first_claim(claims, ("io_latency:",))
    baseline_claim = _first_claim(claims, ("baseline_regression:",))
    fused: list[dict] = []

    if cpu_claim and syscall_claim and latency_claim:
        cpu_target = _claim_target(cpu_claim)
        syscall_target = _claim_target(syscall_claim)
        latency_target = _claim_target(latency_claim)
        fused.append(
            _combined_claim(
                claim_id="combined:cpu_hotspot_with_syscall_and_io_latency",
                title="CPU 热点可能伴随高频系统调用和 IO 延迟",
                root_cause=(
                    f"{cpu_target} 是主要用户态热点，同时 {syscall_target} 系统调用频率偏高，"
                    f"{latency_target} IO 延迟也存在异常信号。优先怀疑热点路径附近存在高频小块 IO、"
                    "同步等待或计算与 IO 交织导致的性能下降。"
                ),
                severity=_max_claim_severity([cpu_claim, syscall_claim, latency_claim]),
                confidence="HIGH",
                source_claims=[cpu_claim, syscall_claim, latency_claim],
                next_actions=[
                    f"从 {cpu_target} 的源码向外追踪，确认是否直接或间接触发 {syscall_target}。",
                    "检查热点循环内是否存在小块 read/write、flush、日志输出或同步等待。",
                    "分别优化计算路径和 IO 路径后重新采样，确认 CPU 与 IO 信号是否同步下降。",
                ],
            )
        )
        return fused

    if cpu_claim and syscall_claim:
        cpu_target = _claim_target(cpu_claim)
        syscall_target = _claim_target(syscall_claim)
        fused.append(
            _combined_claim(
                claim_id="combined:cpu_hotspot_with_syscall_pressure",
                title="CPU 热点可能伴随高频系统调用",
                root_cause=(
                    f"{cpu_target} 是主要用户态热点，同时 {syscall_target} 系统调用频率偏高。"
                    "这通常提示热点路径可能存在循环内频繁读写、日志输出或过细粒度的系统调用。"
                ),
                severity=_max_claim_severity([cpu_claim, syscall_claim]),
                confidence="MEDIUM",
                source_claims=[cpu_claim, syscall_claim],
                next_actions=[
                    f"检查 {cpu_target} 附近是否存在循环内 {syscall_target} 调用。",
                    "统计单次系统调用处理的数据量，判断是否可以合并为批量操作。",
                ],
            )
        )

    if cpu_claim and latency_claim:
        cpu_target = _claim_target(cpu_claim)
        latency_target = _claim_target(latency_claim)
        fused.append(
            _combined_claim(
                claim_id="combined:cpu_hotspot_with_io_latency",
                title="CPU 热点可能伴随 IO 延迟长尾",
                root_cause=(
                    f"{cpu_target} 是主要用户态热点，同时 {latency_target} IO 延迟存在长尾。"
                    "这可能说明热点路径中存在阻塞 IO、同步等待，或者计算热点被慢 IO 放大。"
                ),
                severity=_max_claim_severity([cpu_claim, latency_claim]),
                confidence="MEDIUM",
                source_claims=[cpu_claim, latency_claim],
                next_actions=[
                    f"确认 {cpu_target} 是否处在 {latency_target} IO 的调用链附近。",
                    "尝试将同步 IO 改为缓冲、批量或异步处理后复测。",
                ],
            )
        )

    if baseline_claim and latency_claim:
        baseline_target = _claim_target(baseline_claim)
        fused.append(
            _combined_claim(
                claim_id="combined:latency_regression_with_current_io_tail",
                title="IO 退化和当前延迟长尾互相印证",
                root_cause=(
                    f"{baseline_target} 相比基线出现退化，同时当前 IO 延迟分布也有长尾信号。"
                    "这说明该问题更可能是近期变更、输入变化或运行环境变化带来的真实退化，而不是单次偶发样本。"
                ),
                severity=_max_claim_severity([baseline_claim, latency_claim]),
                confidence="HIGH",
                source_claims=[baseline_claim, latency_claim],
                next_actions=[
                    "确认 baseline 与 current 的输入、采样时长、运行环境保持一致。",
                    "对近期代码改动做二分或回退验证，确认退化引入点。",
                ],
            )
        )

    return fused


def _combined_claim(
    claim_id: str,
    title: str,
    root_cause: str,
    severity: str,
    confidence: str,
    source_claims: list[dict],
    next_actions: list[str],
) -> dict:
    claim = _claim(
        claim_id=claim_id,
        title=title,
        root_cause=root_cause,
        severity=severity,
        confidence=confidence,
        evidence=_combined_evidence(source_claims),
        next_actions=next_actions,
    )
    claim["claim_type"] = "fusion"
    claim["fused_claims"] = [source.get("claim_id", "-") for source in source_claims]
    return claim


def _combined_evidence(source_claims: list[dict]) -> list[dict]:
    evidence: list[dict] = []
    for source in source_claims:
        evidence.append(
            _evidence(
                evidence_id=f"claim:{source.get('claim_id', '-')}",
                source="attribution_claim",
                summary=(
                    f"{source.get('title', source.get('claim_id', '-'))} "
                    f"({source.get('severity', 'INFO')}/{source.get('confidence', 'LOW')})"
                ),
                data={
                    "claim_id": source.get("claim_id"),
                    "severity": source.get("severity"),
                    "confidence": source.get("confidence"),
                },
            )
        )
        source_evidence = source.get("evidence", [])
        if isinstance(source_evidence, list) and source_evidence:
            evidence.append(source_evidence[0])
    return evidence


def _first_claim(claims: list[dict], prefixes: tuple[str, ...]) -> dict | None:
    for claim in claims:
        claim_id = str(claim.get("claim_id", ""))
        if claim_id.startswith(prefixes):
            return claim
    return None


def _claim_target(claim: dict) -> str:
    claim_id = str(claim.get("claim_id", ""))
    if ":" not in claim_id:
        return claim.get("title") or "unknown"
    return claim_id.split(":", 1)[1].split(":", 1)[0] or "unknown"


def _max_claim_severity(claims: list[dict]) -> str:
    severity = "INFO"
    for claim in claims:
        severity = _max_severity(severity, claim.get("severity", "INFO"))
    return severity


def _deduplicate_claims(claims: list[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for claim in claims:
        claim_id = claim["claim_id"]
        if claim_id not in merged:
            merged[claim_id] = claim
            continue
        existing = merged[claim_id]
        existing["evidence"].extend(claim.get("evidence", []))
        existing["next_actions"] = _deduplicate(existing.get("next_actions", []) + claim.get("next_actions", []))
        existing["severity"] = _max_severity(existing.get("severity", "INFO"), claim.get("severity", "INFO"))
        existing["confidence"] = _max_confidence(existing.get("confidence", "LOW"), claim.get("confidence", "LOW"))
    return sorted(
        merged.values(),
        key=lambda item: (SEVERITY_ORDER.get(item.get("severity", "INFO"), 1), len(item.get("evidence", []))),
        reverse=True,
    )


def _score_claims(claims: list[dict], diagnostic_report: dict) -> list[dict]:
    available_sources = _available_sources(diagnostic_report)
    scored: list[dict] = []
    for claim in claims:
        evidence = claim.get("evidence", []) if isinstance(claim.get("evidence"), list) else []
        evidence_sources = _deduplicate(
            [
                str(item.get("source"))
                for item in evidence
                if isinstance(item, dict) and item.get("source")
            ]
        )
        confidence_score = _confidence_score(claim, evidence_count=len(evidence), evidence_sources=evidence_sources)
        enriched = dict(claim)
        enriched["confidence_score"] = confidence_score
        enriched["triage_priority"] = _triage_priority(claim.get("severity", "INFO"), confidence_score)
        enriched["evidence_count"] = len(evidence)
        enriched["evidence_sources"] = evidence_sources
        enriched["missing_evidence"] = _missing_evidence(claim, available_sources)
        scored.append(enriched)
    return sorted(scored, key=_claim_rank_key, reverse=True)


def _available_sources(report: dict) -> set[str]:
    sources: set[str] = set()
    sections = report.get("sections", [])
    if isinstance(sections, list):
        for section in sections:
            if isinstance(section, dict) and section.get("section_id"):
                sources.add(str(section["section_id"]))
    findings = report.get("findings", [])
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict) and finding.get("source"):
                sources.add(str(finding["source"]))
    return sources


def _confidence_score(claim: dict, evidence_count: int, evidence_sources: list[str]) -> int:
    severity_score = {
        "HIGH": 45,
        "MEDIUM": 30,
        "LOW": 18,
        "INFO": 8,
        "OK": 0,
    }.get(claim.get("severity", "INFO"), 8)
    confidence_score = {
        "HIGH": 30,
        "MEDIUM": 20,
        "LOW": 10,
    }.get(claim.get("confidence", "LOW"), 10)
    evidence_score = min(15, evidence_count * 6)
    source_score = min(10, len(evidence_sources) * 5)
    return min(100, severity_score + confidence_score + evidence_score + source_score)


def _triage_priority(severity: str, confidence_score: int) -> str:
    if severity == "HIGH" and confidence_score >= 80:
        return "P1"
    if severity in {"HIGH", "MEDIUM"} and confidence_score >= 60:
        return "P2"
    if confidence_score >= 40:
        return "P3"
    return "P4"


def _claim_rank_key(claim: dict) -> tuple[int, int, int, int]:
    priority_order = {"P1": 4, "P2": 3, "P3": 2, "P4": 1}
    return (
        priority_order.get(claim.get("triage_priority", "P4"), 1),
        SEVERITY_ORDER.get(claim.get("severity", "INFO"), 1),
        int(claim.get("confidence_score", 0)),
        int(claim.get("evidence_count", 0)),
    )


def _missing_evidence(claim: dict, available_sources: set[str]) -> list[str]:
    claim_id = str(claim.get("claim_id", ""))
    missing: list[str] = []
    if claim_id.startswith("combined:"):
        fused_claims = claim.get("fused_claims", [])
        fused_text = " ".join(str(item) for item in fused_claims) if isinstance(fused_claims, list) else ""
        if "baseline_regression:" not in fused_text and "baseline_diff" not in available_sources:
            missing.append("缺少基线对比证据，暂时不能判断这个融合根因是长期问题还是近期退化。")
        if "syscall_rate:" not in fused_text and "ebpf_syscalls" not in available_sources:
            missing.append("缺少 eBPF syscall 证据，暂时不能判断是否存在系统调用放大。")
    elif claim_id.startswith("cpu_hotspot:"):
        if "ebpf_syscalls" not in available_sources:
            missing.append("缺少 eBPF syscall 证据，暂时不能判断热点是否伴随高频系统调用。")
        if "ebpf_io_latency" not in available_sources:
            missing.append("缺少 eBPF IO 延迟证据，暂时不能判断热点是否受到阻塞 IO 放大。")
    elif claim_id.startswith("io_latency:"):
        if "cpu_hotspots" not in available_sources and "python_profile" not in available_sources:
            missing.append("缺少 CPU 或 Python 热点证据，暂时不能判断慢 IO 是否也造成用户态计算热点。")
        if "baseline_diff" not in available_sources:
            missing.append("缺少基线对比证据，暂时不能判断这是长期问题还是本次退化。")
    elif claim_id.startswith("syscall_rate:"):
        if "cpu_hotspots" not in available_sources and "python_profile" not in available_sources:
            missing.append("缺少用户态热点证据，暂时不能定位高频系统调用来自哪段业务代码。")
    elif claim_id.startswith("python_hotspot:"):
        if "cpu_hotspots" not in available_sources:
            missing.append("缺少 perf CPU 热点证据，暂时不能和内核采样结果互相验证。")
    elif claim_id.startswith("baseline_regression:"):
        if "ebpf_io_latency" not in available_sources:
            missing.append("缺少当前 eBPF IO 延迟分布，退化原因还需要结合原始延迟样本确认。")
    return missing[:3]


def _claim(
    claim_id: str,
    title: str,
    root_cause: str,
    severity: str,
    confidence: str,
    evidence: list[dict],
    next_actions: list[str],
) -> dict:
    return {
        "claim_id": claim_id,
        "title": title,
        "root_cause": root_cause,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "next_actions": next_actions,
    }


def _evidence(evidence_id: str, source: str, summary: str, data: dict) -> dict:
    return {
        "evidence_id": evidence_id,
        "source": source,
        "summary": summary,
        "data": data,
    }


def _overall_severity(claims: list[dict]) -> str:
    if not claims:
        return "OK"
    return max(claims, key=lambda item: SEVERITY_ORDER.get(item.get("severity", "INFO"), 1)).get("severity", "INFO")


def _summary(claims: list[dict], severity: str) -> str:
    if not claims:
        return "没有形成明确根因假设；当前结果可作为无明显异常的基线样本保留。"
    if severity == "HIGH":
        return f"形成 {len(claims)} 条可验证根因假设，其中包含高优先级问题，建议先处理证据最强的项。"
    return f"形成 {len(claims)} 条可验证根因假设，建议结合源码和复测结果逐条确认。"


def _confidence(conditions: list[bool]) -> str:
    matched = sum(1 for condition in conditions if condition)
    if matched >= 2:
        return "HIGH"
    if matched == 1:
        return "MEDIUM"
    return "LOW"


def _max_severity(left: str, right: str) -> str:
    return left if SEVERITY_ORDER.get(left, 0) >= SEVERITY_ORDER.get(right, 0) else right


def _max_confidence(left: str, right: str) -> str:
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _deduplicate(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return result


def _parse_self_percent(value: str) -> float:
    marker = "self "
    if marker not in value:
        return 0.0
    after = value.split(marker, 1)[1]
    number = after.split("%", 1)[0]
    return _number(number)


def _parse_rate(value: object) -> float:
    text = str(value or "")
    return _number(text.removesuffix("/s"))


def _number(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
