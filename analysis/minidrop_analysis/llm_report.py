from __future__ import annotations

import json
import os
from typing import Protocol
from urllib import request


class LlmClient(Protocol):
    def generate(self, prompt: str) -> str:
        ...


class OpenAICompatibleClient:
    def __init__(self, api_key: str, base_url: str, model: str, timeout_seconds: int = 30) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds

    def generate(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a performance diagnosis assistant. "
                        "Use only the supplied Mini-Drop JSON evidence. "
                        "Write concise Chinese engineering analysis."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }
        data = json.dumps(payload).encode("utf-8")
        http_request = request.Request(
            f"{self.base_url}/chat/completions",
            data=data,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with request.urlopen(http_request, timeout=self.timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
        choices = body.get("choices", [])
        if not choices:
            raise RuntimeError("LLM response has no choices")
        message = choices[0].get("message", {})
        content = message.get("content")
        if not content:
            raise RuntimeError("LLM response has no message content")
        return str(content)


def build_llm_report(
    diagnostic_report: dict,
    attribution_report: dict,
    mode: str = "auto",
    client: LlmClient | None = None,
) -> dict:
    normalized_mode = mode if mode in {"auto", "template", "llm"} else "auto"
    prompt = build_llm_prompt(diagnostic_report, attribution_report)
    provider = "template"
    llm_error = None
    generated_text = None

    if normalized_mode in {"auto", "llm"}:
        configured_client = client or _client_from_env()
        if configured_client is not None:
            try:
                generated_text = configured_client.generate(prompt)
                provider = "openai_compatible"
            except Exception as exc:  # pragma: no cover - network failures are environment-dependent.
                if normalized_mode == "llm":
                    raise
                llm_error = f"{type(exc).__name__}: {exc}"
        elif normalized_mode == "llm":
            raise RuntimeError("LLM client is not configured")

    template = _template_report(diagnostic_report, attribution_report)
    markdown = generated_text or template["markdown"]
    return {
        "source": "llm_report",
        "mode": "llm" if generated_text else "template",
        "provider": provider,
        "job_id": diagnostic_report.get("job_id"),
        "collector": diagnostic_report.get("collector", "unknown"),
        "severity": attribution_report.get("severity") or diagnostic_report.get("severity", "INFO"),
        "summary": template["summary"],
        "key_points": template["key_points"],
        "recommendations": template["recommendations"],
        "evidence_used": template["evidence_used"],
        "markdown": markdown,
        "llm_error": llm_error,
    }


def build_llm_prompt(diagnostic_report: dict, attribution_report: dict) -> str:
    compact = {
        "diagnostic_report": _compact_diagnostic_report(diagnostic_report),
        "attribution_report": _compact_attribution_report(attribution_report),
    }
    return (
        "请基于下面 Mini-Drop 结构化性能诊断结果，生成中文工程诊断报告。\n"
        "要求：\n"
        "1. 不要编造 JSON 中不存在的证据。\n"
        "2. 先说明最可能根因，再说明证据链和下一步验证动作。\n"
        "3. 如果证据不足，要明确写出缺少什么证据。\n\n"
        f"{json.dumps(compact, ensure_ascii=False, indent=2)}"
    )


def _client_from_env() -> OpenAICompatibleClient | None:
    api_key = os.environ.get("MINIDROP_LLM_API_KEY")
    if not api_key:
        return None
    base_url = os.environ.get("MINIDROP_LLM_BASE_URL", "https://api.openai.com/v1")
    model = os.environ.get("MINIDROP_LLM_MODEL", "gpt-4o-mini")
    timeout = int(os.environ.get("MINIDROP_LLM_TIMEOUT", "30"))
    return OpenAICompatibleClient(api_key=api_key, base_url=base_url, model=model, timeout_seconds=timeout)


def _template_report(diagnostic_report: dict, attribution_report: dict) -> dict:
    claims = attribution_report.get("claims", [])
    claims = claims if isinstance(claims, list) else []
    findings = diagnostic_report.get("findings", [])
    findings = findings if isinstance(findings, list) else []
    top_claim = claims[0] if claims else None
    severity = attribution_report.get("severity") or diagnostic_report.get("severity", "INFO")
    collector = diagnostic_report.get("collector", "unknown")
    job_id = diagnostic_report.get("job_id", "-")

    if top_claim:
        root_cause = str(top_claim.get("root_cause") or "").strip()
        root_cause_text = f" {root_cause}" if root_cause else ""
        summary = (
            f"任务 {job_id} 的主要诊断结论是：{top_claim.get('title', top_claim.get('claim_id', '未知问题'))}。"
            f"{root_cause_text} 当前严重级别为 {severity}，建议优先验证证据最强的根因假设。"
        )
    elif findings:
        summary = f"任务 {job_id} 已发现 {len(findings)} 条规则诊断结果，但暂未形成稳定根因归因。"
    else:
        summary = f"任务 {job_id} 未发现明确高风险问题，可作为当前输入和环境下的基线样本。"

    key_points = _key_points(claims, findings)
    recommendations = _recommendations(claims, diagnostic_report)
    evidence_used = _evidence_used(claims, diagnostic_report, attribution_report)
    markdown = _markdown_report(
        job_id=str(job_id),
        collector=str(collector),
        severity=str(severity),
        summary=summary,
        key_points=key_points,
        recommendations=recommendations,
        evidence_used=evidence_used,
    )
    return {
        "summary": summary,
        "key_points": key_points,
        "recommendations": recommendations,
        "evidence_used": evidence_used,
        "markdown": markdown,
    }


def _key_points(claims: list[dict], findings: list[dict]) -> list[str]:
    points: list[str] = []
    for claim in claims[:3]:
        title = claim.get("title") or claim.get("claim_id") or "Root cause claim"
        confidence = claim.get("confidence", "LOW")
        priority = claim.get("triage_priority", "P4")
        points.append(f"{title}，置信度 {confidence}，排查优先级 {priority}。")
    if not points:
        for finding in findings[:3]:
            title = finding.get("title") or finding.get("rule_id") or "Finding"
            reason = finding.get("reason") or finding.get("matched_condition") or ""
            points.append(f"{title}：{reason}")
    return points


def _recommendations(claims: list[dict], diagnostic_report: dict) -> list[str]:
    actions: list[str] = []
    for claim in claims:
        for action in claim.get("next_actions", []):
            if action not in actions:
                actions.append(str(action))
            if len(actions) >= 5:
                return actions
    for action in diagnostic_report.get("next_actions", []):
        if action not in actions:
            actions.append(str(action))
        if len(actions) >= 5:
            break
    if not actions:
        actions.append("保留本次结果作为基线，后续在输入规模、代码版本或运行环境变化后重新采样对比。")
    return actions


def _evidence_used(claims: list[dict], diagnostic_report: dict, attribution_report: dict) -> list[dict]:
    evidence: list[dict] = []
    for claim in claims[:4]:
        evidence.append(
            {
                "type": "claim",
                "id": claim.get("claim_id"),
                "severity": claim.get("severity"),
                "confidence": claim.get("confidence"),
                "sources": claim.get("evidence_sources", []),
            }
        )
    for job in attribution_report.get("related_evidence_jobs", []):
        evidence.append(
            {
                "type": "related_job",
                "job_id": job.get("job_id"),
                "collector": job.get("collector"),
                "severity": job.get("severity"),
                "finding_count": job.get("finding_count"),
            }
        )
    if not evidence:
        evidence.append(
            {
                "type": "diagnostic_report",
                "severity": diagnostic_report.get("severity", "INFO"),
                "finding_count": diagnostic_report.get("finding_count", 0),
            }
        )
    return evidence


def _markdown_report(
    job_id: str,
    collector: str,
    severity: str,
    summary: str,
    key_points: list[str],
    recommendations: list[str],
    evidence_used: list[dict],
) -> str:
    lines = [
        "# Mini-Drop LLM Report",
        "",
        f"- Job ID: `{job_id}`",
        f"- Collector: `{collector}`",
        f"- Severity: `{severity}`",
        "",
        "## 结论",
        "",
        summary,
        "",
        "## 关键依据",
        "",
    ]
    lines.extend(f"- {point}" for point in key_points)
    lines.extend(["", "## 建议动作", ""])
    lines.extend(f"{index}. {action}" for index, action in enumerate(recommendations, start=1))
    lines.extend(["", "## 使用的证据", ""])
    for item in evidence_used:
        lines.append(f"- `{item.get('type')}`: {json.dumps(item, ensure_ascii=False)}")
    lines.append("")
    return "\n".join(lines)


def _compact_diagnostic_report(report: dict) -> dict:
    return {
        "job_id": report.get("job_id"),
        "collector": report.get("collector"),
        "severity": report.get("severity"),
        "summary": report.get("summary"),
        "finding_count": report.get("finding_count"),
        "findings": _limit_list(report.get("findings", []), 6),
        "next_actions": _limit_list(report.get("next_actions", []), 6),
        "data_quality": report.get("data_quality", []),
    }


def _compact_attribution_report(report: dict) -> dict:
    claims = report.get("claims", [])
    compact_claims = []
    if isinstance(claims, list):
        for claim in claims[:6]:
            compact_claims.append(
                {
                    "claim_id": claim.get("claim_id"),
                    "claim_type": claim.get("claim_type"),
                    "title": claim.get("title"),
                    "root_cause": claim.get("root_cause"),
                    "severity": claim.get("severity"),
                    "confidence": claim.get("confidence"),
                    "confidence_score": claim.get("confidence_score"),
                    "triage_priority": claim.get("triage_priority"),
                    "evidence_sources": claim.get("evidence_sources", []),
                    "missing_evidence": claim.get("missing_evidence", []),
                    "next_actions": _limit_list(claim.get("next_actions", []), 4),
                }
            )
    return {
        "severity": report.get("severity"),
        "summary": report.get("summary"),
        "related_evidence_jobs": report.get("related_evidence_jobs", []),
        "claims": compact_claims,
    }


def _limit_list(value: object, limit: int) -> list:
    if not isinstance(value, list):
        return []
    return value[:limit]
