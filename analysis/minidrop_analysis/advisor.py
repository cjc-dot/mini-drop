from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Iterable


@dataclass(frozen=True)
class AdviceRule:
    rule_id: str
    title: str
    pattern: str
    advice: str
    min_self_percent: float = 0.0
    min_inclusive_percent: float = 0.0
    severity: str = "INFO"


DEFAULT_RULES = [
    AdviceRule(
        rule_id="cpu_self_hotspot",
        title="CPU self hotspot",
        pattern=r".+",
        min_self_percent=50.0,
        severity="HIGH",
        advice=(
            "该函数自身样本占比很高，优先检查循环次数、算法复杂度、分支判断、内存访问局部性，"
            "并结合源码确认是否存在可减少的重复计算。"
        ),
    ),
    AdviceRule(
        rule_id="allocation_hotspot",
        title="Memory allocation hotspot",
        pattern=r"(malloc|calloc|realloc|free|operator new|_Znwm|_Znam)",
        min_inclusive_percent=5.0,
        severity="MEDIUM",
        advice="热点链路中出现内存分配相关函数，建议检查是否存在频繁分配释放，可考虑对象池、缓存复用或批量分配。",
    ),
    AdviceRule(
        rule_id="lock_contention",
        title="Lock contention hotspot",
        pattern=r"(pthread_mutex|futex|__lll_lock_wait|sem_wait)",
        min_inclusive_percent=5.0,
        severity="MEDIUM",
        advice="热点链路中出现锁或 futex 等同步等待函数，建议检查临界区大小、锁粒度和线程竞争情况。",
    ),
    AdviceRule(
        rule_id="sync_io_hotspot",
        title="Synchronous IO hotspot",
        pattern=r"(read|write|pread|pwrite|fsync|fdatasync|sync_file_range)",
        min_inclusive_percent=5.0,
        severity="MEDIUM",
        advice="热点链路中出现同步 IO 相关函数，建议检查阻塞读写、刷盘频率和是否可以批量化或异步化。",
    ),
]


def generate_advice(hotspot_report: dict, rules: Iterable[AdviceRule] = DEFAULT_RULES, limit: int = 10) -> dict:
    findings = []
    for hotspot in hotspot_report.get("hotspots", []):
        for rule in rules:
            if _matches_rule(hotspot, rule):
                findings.append(_build_finding(hotspot, rule))
                if len(findings) >= limit:
                    return _build_report(hotspot_report, findings)
    return _build_report(hotspot_report, findings)


def format_advice_markdown(advice_report: dict) -> str:
    lines = [
        "# Mini-Drop Analysis Suggestions",
        "",
        f"- Total samples: {advice_report.get('total_samples', 0)}",
        f"- Finding count: {len(advice_report.get('findings', []))}",
        "",
    ]
    if not advice_report.get("findings"):
        lines.extend(
            [
                "No rule-based suggestion was generated.",
                "",
            ]
        )
        return "\n".join(lines)

    for index, finding in enumerate(advice_report["findings"], start=1):
        evidence = finding["evidence"]
        lines.extend(
            [
                f"## {index}. {finding['title']}",
                "",
                f"- Severity: {finding['severity']}",
                f"- Function: `{finding['function']}`",
                f"- Self samples: {evidence['self_samples']} ({evidence['self_percent']}%)",
                f"- Inclusive samples: {evidence['inclusive_samples']} ({evidence['inclusive_percent']}%)",
                f"- Advice: {finding['advice']}",
                "",
            ]
        )
    return "\n".join(lines)


def _matches_rule(hotspot: dict, rule: AdviceRule) -> bool:
    function = str(hotspot.get("function", ""))
    if not re.search(rule.pattern, function):
        return False
    return (
        float(hotspot.get("self_percent", 0.0)) >= rule.min_self_percent
        and float(hotspot.get("inclusive_percent", 0.0)) >= rule.min_inclusive_percent
    )


def _build_finding(hotspot: dict, rule: AdviceRule) -> dict:
    return {
        "rule": asdict(rule),
        "rule_id": rule.rule_id,
        "title": rule.title,
        "severity": rule.severity,
        "function": hotspot.get("function", ""),
        "evidence": {
            "self_samples": int(hotspot.get("self_samples", 0)),
            "inclusive_samples": int(hotspot.get("inclusive_samples", 0)),
            "self_percent": float(hotspot.get("self_percent", 0.0)),
            "inclusive_percent": float(hotspot.get("inclusive_percent", 0.0)),
        },
        "advice": rule.advice,
    }


def _build_report(hotspot_report: dict, findings: list[dict]) -> dict:
    return {
        "source": "hotspots",
        "total_samples": int(hotspot_report.get("total_samples", 0)),
        "finding_count": len(findings),
        "findings": findings,
    }
