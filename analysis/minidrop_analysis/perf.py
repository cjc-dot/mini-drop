from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .advisor import format_advice_markdown, generate_advice
from .folded import collapse_perf_script, format_folded
from .hotspots import analyze_hotspots
from .svg import render_flamegraph_svg


@dataclass(frozen=True)
class ProfileSummary:
    pid: int
    collector: str
    status: str
    duration_seconds: int
    sample_frequency: int
    output_dir: str
    created_at: str
    artifacts: dict[str, str]

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "collector": self.collector,
            "status": self.status,
            "duration_seconds": self.duration_seconds,
            "sample_frequency": self.sample_frequency,
            "output_dir": self.output_dir,
            "created_at": self.created_at,
            "artifacts": self.artifacts,
        }


class PerfCollector:
    def __init__(self, perf_bin: str = "perf") -> None:
        self.perf_bin = perf_bin

    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        output_path = Path(output_dir).expanduser().resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        perf_data = output_path / "perf.data"
        perf_script = output_path / "out.perf"
        folded_stack = output_path / "out.folded"
        flamegraph = output_path / "flamegraph.svg"
        hotspots = output_path / "hotspots.json"
        suggestions = output_path / "suggestions.json"
        suggestions_markdown = output_path / "suggestions.md"
        summary_path = output_path / "summary.json"

        self._run(
            [
                "sudo",
                self.perf_bin,
                "record",
                "-F",
                str(sample_frequency),
                "-g",
                "-p",
                str(pid),
                "-o",
                str(perf_data),
                "--",
                "sleep",
                str(duration_seconds),
            ]
        )

        script_text = self._capture(["sudo", self.perf_bin, "script", "-i", str(perf_data)])
        perf_script.write_text(script_text, encoding="utf-8")

        stacks = collapse_perf_script(script_text)
        folded_stack.write_text(format_folded(stacks), encoding="utf-8")
        flamegraph.write_text(render_flamegraph_svg(stacks), encoding="utf-8")
        hotspot_report = analyze_hotspots(stacks)
        advice_report = generate_advice(hotspot_report)
        hotspots.write_text(json.dumps(hotspot_report, indent=2), encoding="utf-8")
        suggestions.write_text(json.dumps(advice_report, indent=2), encoding="utf-8")
        suggestions_markdown.write_text(format_advice_markdown(advice_report), encoding="utf-8")

        summary = ProfileSummary(
            pid=pid,
            collector="perf",
            status="success",
            duration_seconds=duration_seconds,
            sample_frequency=sample_frequency,
            output_dir=str(output_path),
            created_at=datetime.now(timezone.utc).isoformat(),
            artifacts={
                "perf_data": str(perf_data),
                "perf_script": str(perf_script),
                "folded_stack": str(folded_stack),
                "flamegraph": str(flamegraph),
                "hotspots": str(hotspots),
                "suggestions": str(suggestions),
                "suggestions_markdown": str(suggestions_markdown),
                "summary": str(summary_path),
            },
        )
        summary_path.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
        return summary

    @staticmethod
    def _run(command: list[str]) -> None:
        subprocess.run(command, check=True)

    @staticmethod
    def _capture(command: list[str]) -> str:
        completed = subprocess.run(command, check=True, text=True, capture_output=True)
        return completed.stdout
