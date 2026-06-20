from __future__ import annotations

from dataclasses import dataclass
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
    next_actions: tuple[str, ...] = ()


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
        next_actions=(
            "打开热点函数源码，确认主要循环和重复计算位置。",
            "用更小输入或日志计数验证循环次数是否异常。",
            "优先尝试减少重复计算、提前退出或缓存中间结果。",
        ),
    ),
    AdviceRule(
        rule_id="allocation_hotspot",
        title="Memory allocation hotspot",
        pattern=r"(malloc|calloc|realloc|free|operator new|_Znwm|_Znam)",
        min_inclusive_percent=5.0,
        severity="MEDIUM",
        advice="热点链路中出现内存分配相关函数，建议检查是否存在频繁分配释放，可考虑对象池、缓存复用或批量分配。",
        next_actions=(
            "检查热点路径中是否在循环内反复 malloc/free 或 new/delete。",
            "统计对象分配次数，确认是否可以复用缓冲区或对象池。",
        ),
    ),
    AdviceRule(
        rule_id="lock_contention",
        title="Lock contention hotspot",
        pattern=r"(pthread_mutex|futex|__lll_lock_wait|sem_wait)",
        min_inclusive_percent=5.0,
        severity="MEDIUM",
        advice="热点链路中出现锁或 futex 等同步等待函数，建议检查临界区大小、锁粒度和线程竞争情况。",
        next_actions=(
            "检查锁保护的临界区是否过大。",
            "统计竞争线程数量和锁等待时间。",
            "评估是否可以拆分锁粒度或减少共享状态。",
        ),
    ),
    AdviceRule(
        rule_id="sync_io_hotspot",
        title="Synchronous IO hotspot",
        pattern=r"(read|write|pread|pwrite|fsync|fdatasync|sync_file_range)",
        min_inclusive_percent=5.0,
        severity="MEDIUM",
        advice="热点链路中出现同步 IO 相关函数，建议检查阻塞读写、刷盘频率和是否可以批量化或异步化。",
        next_actions=(
            "检查是否存在高频小块 read/write 或 fsync。",
            "确认 IO 是否位于请求关键路径。",
            "评估批量写入、缓冲或异步 IO 的可行性。",
        ),
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
                f"- Matched condition: {finding['matched_condition']}",
                f"- Reason: {finding['reason']}",
                f"- Self samples: {evidence['self_samples']} ({evidence['self_percent']}%)",
                f"- Inclusive samples: {evidence['inclusive_samples']} ({evidence['inclusive_percent']}%)",
                f"- Advice: {finding['advice']}",
                "",
            ]
        )
        if finding.get("next_actions"):
            lines.append("- Next actions:")
            lines.extend(f"  - {action}" for action in finding["next_actions"])
            lines.append("")
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
    evidence = {
        "self_samples": int(hotspot.get("self_samples", 0)),
        "inclusive_samples": int(hotspot.get("inclusive_samples", 0)),
        "self_percent": float(hotspot.get("self_percent", 0.0)),
        "inclusive_percent": float(hotspot.get("inclusive_percent", 0.0)),
    }
    return {
        "rule_id": rule.rule_id,
        "title": rule.title,
        "severity": rule.severity,
        "function": hotspot.get("function", ""),
        "matched_condition": _matched_condition(rule),
        "reason": _reason(hotspot, rule, evidence),
        "evidence": evidence,
        "advice": rule.advice,
        "next_actions": list(rule.next_actions),
    }


def _build_report(hotspot_report: dict, findings: list[dict]) -> dict:
    return {
        "source": "hotspots",
        "total_samples": int(hotspot_report.get("total_samples", 0)),
        "finding_count": len(findings),
        "findings": findings,
    }


def _matched_condition(rule: AdviceRule) -> str:
    conditions = [f"function matches /{rule.pattern}/"]
    if rule.min_self_percent > 0:
        conditions.append(f"self_percent >= {rule.min_self_percent}")
    if rule.min_inclusive_percent > 0:
        conditions.append(f"inclusive_percent >= {rule.min_inclusive_percent}")
    return " and ".join(conditions)


def _reason(hotspot: dict, rule: AdviceRule, evidence: dict) -> str:
    function = str(hotspot.get("function", ""))
    reasons = [f"`{function}` matched /{rule.pattern}/"]
    if rule.min_self_percent > 0:
        reasons.append(f"self_percent {evidence['self_percent']} >= {rule.min_self_percent}")
    if rule.min_inclusive_percent > 0:
        reasons.append(f"inclusive_percent {evidence['inclusive_percent']} >= {rule.min_inclusive_percent}")
    return "; ".join(reasons)
