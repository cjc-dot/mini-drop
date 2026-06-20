from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .perf import ProfileSummary


def analyze_speedscope_profile(profile: dict, limit: int = 20) -> dict:
    frames = profile.get("shared", {}).get("frames", [])
    samples = []
    for sampled_profile in profile.get("profiles", []):
        if isinstance(sampled_profile, dict):
            samples.extend(sampled_profile.get("samples", []) or [])

    inclusive: dict[int, int] = {}
    self_samples: dict[int, int] = {}
    for sample in samples:
        if not isinstance(sample, list) or not sample:
            continue
        for frame_id in set(frame for frame in sample if isinstance(frame, int)):
            inclusive[frame_id] = inclusive.get(frame_id, 0) + 1
        leaf = sample[-1]
        if isinstance(leaf, int):
            self_samples[leaf] = self_samples.get(leaf, 0) + 1

    total_samples = len([sample for sample in samples if isinstance(sample, list) and sample])
    hotspots = []
    for frame_id, inclusive_count in inclusive.items():
        frame = frames[frame_id] if 0 <= frame_id < len(frames) and isinstance(frames[frame_id], dict) else {}
        name = str(frame.get("name") or f"frame_{frame_id}")
        file_name = frame.get("file")
        line = frame.get("line")
        self_count = self_samples.get(frame_id, 0)
        hotspots.append(
            {
                "function": name,
                "file": file_name,
                "line": line,
                "self_samples": self_count,
                "inclusive_samples": inclusive_count,
                "self_percent": _percent(self_count, total_samples),
                "inclusive_percent": _percent(inclusive_count, total_samples),
            }
        )

    hotspots.sort(key=lambda item: (item["self_samples"], item["inclusive_samples"]), reverse=True)
    return {
        "source": "py_spy",
        "total_samples": total_samples,
        "limit": limit,
        "hotspots": hotspots[:limit],
    }


def generate_pyspy_advice(report: dict) -> dict:
    findings = []
    for hotspot in report.get("hotspots", []):
        self_percent = float(hotspot.get("self_percent", 0.0))
        if self_percent >= 50.0:
            function = hotspot.get("function", "-")
            findings.append(
                {
                    "rule_id": "python_self_hotspot",
                    "title": "Python self hotspot",
                    "severity": "MEDIUM",
                    "function": function,
                    "matched_condition": "self_percent >= 50.0",
                    "reason": f"{function} self_percent {self_percent} >= 50.0",
                    "evidence": {
                        "self_samples": hotspot.get("self_samples", 0),
                        "inclusive_samples": hotspot.get("inclusive_samples", 0),
                        "self_percent": self_percent,
                        "inclusive_percent": hotspot.get("inclusive_percent", 0.0),
                        "file": hotspot.get("file"),
                        "line": hotspot.get("line"),
                    },
                    "advice": (
                        "该 Python 函数自身采样占比较高，建议优先检查循环、对象创建、"
                        "字符串或列表处理、解释器层面的重复计算，以及是否可以批量化或下沉到 C 扩展。"
                    ),
                    "next_actions": [
                        "打开该 Python 函数源码，确认热点是否集中在循环或重复计算。",
                        "用更小输入复现实验，确认 self_percent 是否稳定出现。",
                        "优先尝试缓存中间结果、减少对象分配或合并小粒度操作。",
                    ],
                }
            )
    return {
        "source": "py_spy",
        "total_samples": int(report.get("total_samples", 0)),
        "finding_count": len(findings),
        "findings": findings,
    }


def format_pyspy_advice_markdown(advice_report: dict) -> str:
    lines = [
        "# Mini-Drop py-spy Suggestions",
        "",
        f"- Total samples: {advice_report.get('total_samples', 0)}",
        f"- Finding count: {len(advice_report.get('findings', []))}",
        "",
    ]
    if not advice_report.get("findings"):
        lines.extend(["No py-spy rule was triggered.", ""])
        return "\n".join(lines)

    for index, finding in enumerate(advice_report["findings"], start=1):
        evidence = finding.get("evidence", {})
        lines.extend(
            [
                f"## {index}. {finding['title']}",
                "",
                f"- Severity: {finding['severity']}",
                f"- Function: `{finding['function']}`",
                f"- Reason: {finding['reason']}",
                f"- Self percent: {evidence.get('self_percent', '-')}%",
                f"- Inclusive percent: {evidence.get('inclusive_percent', '-')}%",
                f"- Advice: {finding['advice']}",
                "",
            ]
        )
        if finding.get("next_actions"):
            lines.append("- Next actions:")
            lines.extend(f"  - {action}" for action in finding["next_actions"])
            lines.append("")
    return "\n".join(lines)


class PySpyCollector:
    def __init__(self, py_spy_bin: str = "py-spy", use_sudo: bool = True) -> None:
        self.py_spy_bin = py_spy_bin
        self.use_sudo = use_sudo

    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        output_path = Path(output_dir).expanduser().resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        speedscope = output_path / "py_spy.speedscope.json"
        pyspy_report = output_path / "py_spy_profile.json"
        suggestions = output_path / "suggestions.json"
        suggestions_markdown = output_path / "suggestions.md"
        summary_path = output_path / "summary.json"

        self._run_py_spy(
            pid=pid,
            duration_seconds=duration_seconds,
            sample_frequency=sample_frequency,
            output_path=speedscope,
        )
        profile = json.loads(speedscope.read_text(encoding="utf-8-sig"))
        report = analyze_speedscope_profile(profile)
        report.update(
            {
                "pid": pid,
                "collector": "py_spy",
                "duration_seconds": duration_seconds,
                "sample_frequency": sample_frequency,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "tool": "py-spy",
                "tool_version": self._tool_version(),
            }
        )
        advice_report = generate_pyspy_advice(report)

        pyspy_report.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        suggestions.write_text(json.dumps(advice_report, ensure_ascii=False, indent=2), encoding="utf-8")
        suggestions_markdown.write_text(format_pyspy_advice_markdown(advice_report), encoding="utf-8")

        summary = ProfileSummary(
            pid=pid,
            collector="py_spy",
            status="success",
            duration_seconds=duration_seconds,
            sample_frequency=sample_frequency,
            output_dir=str(output_path),
            created_at=report["created_at"],
            artifacts={
                "pyspy_speedscope": str(speedscope),
                "pyspy_profile": str(pyspy_report),
                "suggestions": str(suggestions),
                "suggestions_markdown": str(suggestions_markdown),
                "summary": str(summary_path),
            },
        )
        summary_path.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
        return summary

    def _run_py_spy(
        self,
        pid: int,
        duration_seconds: int,
        sample_frequency: int,
        output_path: Path,
    ) -> None:
        command = [
            self._resolved_py_spy_bin(),
            "record",
            "--pid",
            str(pid),
            "--duration",
            str(duration_seconds),
            "--rate",
            str(sample_frequency),
            "--format",
            "speedscope",
            "--output",
            str(output_path),
        ]
        if self.use_sudo:
            command.insert(0, "sudo")
        completed = subprocess.run(command, text=True, capture_output=True)
        if completed.returncode != 0:
            detail = "\n".join(
                part.strip()
                for part in [completed.stdout, completed.stderr]
                if part and part.strip()
            )
            raise RuntimeError(
                f"py-spy failed with exit code {completed.returncode}"
                + (f":\n{detail}" if detail else "")
            )

    def _tool_version(self) -> str:
        try:
            completed = subprocess.run(
                [self._resolved_py_spy_bin(), "--version"],
                text=True,
                capture_output=True,
            )
        except OSError:
            return "unknown"
        if completed.returncode != 0:
            return "unknown"
        lines = (completed.stdout or completed.stderr).strip().splitlines()
        return lines[0] if lines else "unknown"

    def _resolved_py_spy_bin(self) -> str:
        return shutil.which(self.py_spy_bin) or self.py_spy_bin


def _percent(count: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(count * 100 / total, 2)
