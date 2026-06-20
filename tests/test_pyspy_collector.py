import json
from pathlib import Path

from minidrop_analysis.pyspy import PySpyCollector, analyze_speedscope_profile, generate_pyspy_advice


SPEEDSCOPE_PROFILE = {
    "shared": {
        "frames": [
            {"name": "<module>", "file": "workloads/python_hotspot.py", "line": 1},
            {"name": "main", "file": "workloads/python_hotspot.py", "line": 21},
            {"name": "hot_python_loop", "file": "workloads/python_hotspot.py", "line": 8},
            {"name": "cold_python_loop", "file": "workloads/python_hotspot.py", "line": 14},
        ]
    },
    "profiles": [
        {
            "type": "sampled",
            "name": "pid 1234",
            "unit": "seconds",
            "samples": [[0, 1, 2], [0, 1, 2], [0, 1, 2], [0, 1, 3]],
        }
    ],
}


class FakePySpyCollector(PySpyCollector):
    def _run_py_spy(
        self,
        pid: int,
        duration_seconds: int,
        sample_frequency: int,
        output_path: Path,
    ) -> None:
        output_path.write_text(json.dumps(SPEEDSCOPE_PROFILE), encoding="utf-8")

    def _tool_version(self) -> str:
        return "py-spy 0.test"


def test_analyze_speedscope_profile_calculates_python_hotspots() -> None:
    report = analyze_speedscope_profile(SPEEDSCOPE_PROFILE)

    assert report["source"] == "py_spy"
    assert report["total_samples"] == 4
    assert report["hotspots"][0]["function"] == "hot_python_loop"
    assert report["hotspots"][0]["self_samples"] == 3
    assert report["hotspots"][0]["self_percent"] == 75.0
    assert report["hotspots"][1]["function"] == "cold_python_loop"


def test_generate_pyspy_advice_reports_self_hotspot() -> None:
    profile = analyze_speedscope_profile(SPEEDSCOPE_PROFILE)

    advice = generate_pyspy_advice(profile)

    assert advice["source"] == "py_spy"
    assert advice["finding_count"] == 1
    assert advice["findings"][0]["rule_id"] == "python_self_hotspot"
    assert advice["findings"][0]["function"] == "hot_python_loop"


def test_pyspy_collector_writes_profile_summary_and_suggestions(tmp_path: Path) -> None:
    summary = FakePySpyCollector(use_sudo=False).collect(
        pid=1234,
        duration_seconds=5,
        sample_frequency=99,
        output_dir=str(tmp_path),
    )

    profile = json.loads((tmp_path / "py_spy_profile.json").read_text(encoding="utf-8"))
    suggestions = json.loads((tmp_path / "suggestions.json").read_text(encoding="utf-8"))
    summary_json = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))

    assert summary.collector == "py_spy"
    assert summary.artifacts["pyspy_speedscope"].endswith("py_spy.speedscope.json")
    assert summary.artifacts["pyspy_profile"].endswith("py_spy_profile.json")
    assert summary.artifacts["suggestions"].endswith("suggestions.json")
    assert profile["collector"] == "py_spy"
    assert profile["tool_version"] == "py-spy 0.test"
    assert profile["hotspots"][0]["function"] == "hot_python_loop"
    assert suggestions["finding_count"] == 1
    assert summary_json["collector"] == "py_spy"
