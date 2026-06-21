from __future__ import annotations

import pytest

from minidrop_analysis.llm_report import build_llm_prompt, build_llm_report


class FakeLlmClient:
    def __init__(self, text: str = "LLM generated report") -> None:
        self.text = text
        self.prompt = ""

    def generate(self, prompt: str) -> str:
        self.prompt = prompt
        return self.text


def test_build_llm_report_falls_back_to_template_without_client() -> None:
    diagnostic_report = _diagnostic_report()
    attribution_report = _attribution_report()

    report = build_llm_report(diagnostic_report, attribution_report, mode="auto")

    assert report["source"] == "llm_report"
    assert report["mode"] == "template"
    assert report["provider"] == "template"
    assert report["job_id"] == "job-1"
    assert report["collector"] == "perf"
    assert report["severity"] == "HIGH"
    assert "hot_func" in report["summary"]
    assert report["key_points"]
    assert report["recommendations"]
    assert report["evidence_used"]
    assert "# Mini-Drop LLM Report" in report["markdown"]


def test_build_llm_report_uses_injected_client() -> None:
    client = FakeLlmClient("外部大模型生成的报告")

    report = build_llm_report(_diagnostic_report(), _attribution_report(), mode="llm", client=client)

    assert report["mode"] == "llm"
    assert report["provider"] == "openai_compatible"
    assert report["markdown"] == "外部大模型生成的报告"
    assert "diagnostic_report" in client.prompt
    assert "attribution_report" in client.prompt


def test_build_llm_report_rejects_forced_llm_without_client_or_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MINIDROP_LLM_API_KEY", raising=False)

    with pytest.raises(RuntimeError, match="LLM client is not configured"):
        build_llm_report(_diagnostic_report(), _attribution_report(), mode="llm")


def test_build_llm_prompt_contains_compact_evidence() -> None:
    prompt = build_llm_prompt(_diagnostic_report(), _attribution_report())

    assert "不要编造" in prompt
    assert "cpu_hotspot:hot_func" in prompt
    assert "combined:cpu_hotspot_with_syscall_pressure" in prompt


def _diagnostic_report() -> dict:
    return {
        "source": "diagnostic_report",
        "job_id": "job-1",
        "collector": "perf",
        "severity": "HIGH",
        "summary": "发现 CPU 热点",
        "finding_count": 1,
        "findings": [
            {
                "rule_id": "cpu_self_hotspot",
                "title": "CPU self hotspot",
                "severity": "HIGH",
                "function": "hot_func",
                "reason": "hot_func self_percent >= 50",
            }
        ],
        "next_actions": ["检查 hot_func 循环"],
        "data_quality": [],
    }


def _attribution_report() -> dict:
    return {
        "source": "diagnostic_report",
        "job_id": "job-1",
        "collector": "perf",
        "severity": "HIGH",
        "summary": "形成 2 条根因假设",
        "related_evidence_jobs": [
            {
                "job_id": "job-syscall",
                "collector": "ebpf_syscall",
                "severity": "INFO",
                "finding_count": 1,
            }
        ],
        "claims": [
            {
                "claim_id": "combined:cpu_hotspot_with_syscall_pressure",
                "claim_type": "fusion",
                "title": "CPU 热点可能伴随高频系统调用",
                "root_cause": "hot_func 与 write syscall 压力同时出现。",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "confidence_score": 90,
                "triage_priority": "P1",
                "evidence_count": 4,
                "evidence_sources": ["hotspots", "related_job:job-syscall:ebpf_syscalls"],
                "missing_evidence": [],
                "next_actions": ["检查 hot_func 附近是否存在 write 调用"],
            },
            {
                "claim_id": "cpu_hotspot:hot_func",
                "title": "CPU 热点集中在 hot_func",
                "root_cause": "hot_func 自身 CPU 采样占比较高。",
                "severity": "HIGH",
                "confidence": "HIGH",
                "confidence_score": 97,
                "triage_priority": "P1",
                "evidence_count": 2,
                "evidence_sources": ["hotspots"],
                "missing_evidence": [],
                "next_actions": ["检查 hot_func 源码"],
            },
        ],
    }
