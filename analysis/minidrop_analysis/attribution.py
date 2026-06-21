from __future__ import annotations


SEVERITY_ORDER = {"OK": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4}


def build_attribution_report(diagnostic_report: dict) -> dict:
    """Build deterministic root-cause claims from an existing diagnostic report."""
    claims = _deduplicate_claims(
        [
            *_claims_from_findings(diagnostic_report),
            *_claims_from_sections(diagnostic_report),
        ]
    )
    severity = _overall_severity(claims)
    return {
        "source": "diagnostic_report",
        "job_id": diagnostic_report.get("job_id"),
        "collector": diagnostic_report.get("collector", "unknown"),
        "severity": severity,
        "claim_count": len(claims),
        "summary": _summary(claims, severity),
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
        if rule_id == "cpu_self_hotspot":
            claims.append(_cpu_hotspot_claim(finding, source="suggestions"))
        elif rule_id == "python_self_hotspot":
            claims.append(_python_hotspot_claim(finding, source="suggestions"))
        elif rule_id in {"high_read_syscall_rate", "high_write_syscall_rate"}:
            claims.append(_syscall_rate_claim(finding, source="suggestions"))
        elif rule_id in {
            "io_latency_tail_over_1ms",
            "io_latency_p99_far_from_p50",
            "io_latency_bimodal_distribution",
        }:
            claims.append(_io_latency_claim(finding, source="suggestions"))
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
