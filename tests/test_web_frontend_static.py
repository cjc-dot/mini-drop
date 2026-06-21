import json
from pathlib import Path

from fastapi.testclient import TestClient

from minidrop_apiserver.app import create_app


def test_web_frontend_assets_exist() -> None:
    root = Path(__file__).resolve().parents[1]

    assert (root / "web_frontend" / "index.html").exists()
    assert (root / "web_frontend" / "app.js").exists()
    assert (root / "web_frontend" / "styles.css").exists()


def test_web_frontend_uses_existing_api_routes() -> None:
    root = Path(__file__).resolve().parents[1]
    app_js = (root / "web_frontend" / "app.js").read_text(encoding="utf-8")

    assert 'fetchJson("/api/jobs")' in app_js
    assert 'fetchJson("/api/agents")' in app_js
    assert 'fetchJson("/api/continuous-profiles")' in app_js
    assert '"/api/continuous-profiles"' in app_js
    assert 'const url = continuous ? "/api/continuous-profiles" : "/api/jobs";' in app_js
    assert "fetchJson(url, {" in app_js
    assert "/artifacts/hotspots" in app_js
    assert "/artifacts/suggestions" in app_js
    assert "/artifacts/ebpf_syscalls" in app_js
    assert "/artifacts/ebpf_io_latency" in app_js
    assert "/artifacts/pyspy_profile" in app_js
    assert "/compare/ebpf-io-latency" in app_js
    assert "/report" in app_js
    assert "/attribution" in app_js
    assert "/llm-report" in app_js
    assert "collectorInput" in app_js
    assert "continuousInput" in app_js
    assert "renderContinuousProfiles" in app_js


def test_web_frontend_contains_job_report_panel() -> None:
    root = Path(__file__).resolve().parents[1]
    index = (root / "web_frontend" / "index.html").read_text(encoding="utf-8")
    app_js = (root / "web_frontend" / "app.js").read_text(encoding="utf-8")

    assert 'id="jobReportPanel"' in index
    assert 'class="analysis-workbench"' in index
    assert 'id="hotspotsBody"' in index
    assert 'id="suggestionsBody"' in index
    assert 'id="ebpfBody"' in index
    assert 'id="ebpfLatencyChart"' in index
    assert 'id="ebpfLatencyBody"' in index
    assert 'id="ebpfDiffBody"' in index
    assert 'id="pyspyBody"' in index
    assert 'id="diagnosisBody"' in index
    assert 'id="attributionBody"' in index
    assert 'id="llmBody"' in index
    assert "LLM Report" in index
    assert 'id="collectorInput"' in index
    assert 'id="continuousInput"' in index
    assert 'id="sliceCountInput"' in index
    assert 'id="intervalInput"' in index
    assert 'id="continuousBody"' in index
    assert "Rate/s" in index
    assert "Continuous Profiles" in index
    assert "Diagnosis Report" in index
    assert "Root Cause Attribution" in index
    assert "eBPF IO Latency" in index
    assert "eBPF Baseline Diff" in index
    assert "Python Profile" in index
    assert "py-spy Python profile" in index
    assert 'data-report-job' in app_js
    assert "selectedJobId" in app_js
    assert "loadJobReport" in app_js
    assert "formatFindingEvidence" in app_js
    assert "renderEbpfLatency" in app_js
    assert "renderLatencyChart" in app_js
    assert "renderLatencyBar" in app_js
    assert "renderLatencyDiff" in app_js
    assert "renderDiagnosticReport" in app_js
    assert "renderAttribution" in app_js
    assert "renderLlmReport" in app_js
    assert "confidence_score" in app_js
    assert "triage_priority" in app_js
    assert "claim_type" in app_js
    assert "evidenceLimit" in app_js
    assert "missing_evidence" in app_js
    assert "renderPyspyProfile" in app_js
    assert "formatSigned" in app_js


def test_web_frontend_contains_latency_chart_styles() -> None:
    root = Path(__file__).resolve().parents[1]
    styles = (root / "web_frontend" / "styles.css").read_text(encoding="utf-8")

    assert ".latency-chart" in styles
    assert ".latency-row" in styles
    assert ".latency-track" in styles
    assert ".latency-fill" in styles
    assert ".diff-grid" in styles
    assert ".diff-card" in styles
    assert ".badge.regressed" in styles
    assert ".diagnosis-body" in styles
    assert ".diagnosis-grid" in styles
    assert ".attribution-body" in styles
    assert ".attribution-card" in styles
    assert ".badge.priority" in styles
    assert ".attribution-missing" in styles
    assert ".llm-body" in styles
    assert ".llm-card" in styles
    assert ".llm-markdown" in styles


def test_web_ui_route_serves_index(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path)))

    response = client.get("/ui")
    slash_response = client.get("/ui/")

    assert response.status_code == 200
    assert slash_response.status_code == 200
    assert "Mini-Drop" in response.text


def test_artifact_route_serves_known_artifacts_inside_runtime(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    profile_dir = runtime_dir / "profiles" / "job-1"
    job_dir = runtime_dir / "jobs" / "job-1"
    profile_dir.mkdir(parents=True)
    job_dir.mkdir(parents=True)

    flamegraph = profile_dir / "flamegraph.svg"
    flamegraph.write_text("<svg>ok</svg>", encoding="utf-8")
    hotspots = profile_dir / "hotspots.json"
    hotspots.write_text('{"hotspots":[]}', encoding="utf-8")
    suggestions = profile_dir / "suggestions.json"
    suggestions.write_text('{"findings":[]}', encoding="utf-8")
    ebpf_syscalls = profile_dir / "ebpf_syscalls.json"
    ebpf_syscalls.write_text('{"events":[{"event":"read","count":1}]}', encoding="utf-8")
    ebpf_io_latency = profile_dir / "ebpf_io_latency.json"
    ebpf_io_latency.write_text('{"events":[{"event":"read","histogram":[]}]}', encoding="utf-8")
    pyspy_profile = profile_dir / "py_spy_profile.json"
    pyspy_profile.write_text('{"hotspots":[{"function":"hot_python_loop"}]}', encoding="utf-8")
    job = {
        "job_id": "job-1",
        "status": "DONE",
        "spec": {
            "job_id": "job-1",
            "pid": 1234,
            "duration_seconds": 10,
            "sample_frequency": 99,
            "collector": "perf",
        },
        "artifacts": {
            "flamegraph": str(flamegraph),
            "hotspots": str(hotspots),
            "suggestions": str(suggestions),
            "ebpf_syscalls": str(ebpf_syscalls),
            "ebpf_io_latency": str(ebpf_io_latency),
            "pyspy_profile": str(pyspy_profile),
        },
        "reason": "job completed successfully",
        "error_message": None,
        "created_at": "2026-06-16T00:00:00+00:00",
        "updated_at": "2026-06-16T00:00:10+00:00",
    }
    (job_dir / "job.json").write_text(json.dumps(job), encoding="utf-8")
    client = TestClient(create_app(str(runtime_dir)))

    response = client.get("/api/jobs/job-1/artifacts/flamegraph")
    hotspots_response = client.get("/api/jobs/job-1/artifacts/hotspots")
    suggestions_response = client.get("/api/jobs/job-1/artifacts/suggestions")
    ebpf_response = client.get("/api/jobs/job-1/artifacts/ebpf_syscalls")
    ebpf_latency_response = client.get("/api/jobs/job-1/artifacts/ebpf_io_latency")
    pyspy_response = client.get("/api/jobs/job-1/artifacts/pyspy_profile")

    assert response.status_code == 200
    assert response.text == "<svg>ok</svg>"
    assert hotspots_response.status_code == 200
    assert hotspots_response.json() == {"hotspots": []}
    assert suggestions_response.status_code == 200
    assert suggestions_response.json() == {"findings": []}
    assert ebpf_response.status_code == 200
    assert ebpf_response.json() == {"events": [{"event": "read", "count": 1}]}
    assert ebpf_latency_response.status_code == 200
    assert ebpf_latency_response.json() == {"events": [{"event": "read", "histogram": []}]}
    assert pyspy_response.status_code == 200
    assert pyspy_response.json() == {"hotspots": [{"function": "hot_python_loop"}]}


def test_artifact_route_rejects_file_outside_runtime(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    job_dir = runtime_dir / "jobs" / "job-1"
    job_dir.mkdir(parents=True)
    outside_file = tmp_path / "outside.svg"
    outside_file.write_text("<svg>outside</svg>", encoding="utf-8")
    job = {
        "job_id": "job-1",
        "status": "DONE",
        "spec": {
            "job_id": "job-1",
            "pid": 1234,
            "duration_seconds": 10,
            "sample_frequency": 99,
            "collector": "perf",
        },
        "artifacts": {"flamegraph": str(outside_file)},
        "reason": "job completed successfully",
        "error_message": None,
        "created_at": "2026-06-16T00:00:00+00:00",
        "updated_at": "2026-06-16T00:00:10+00:00",
    }
    (job_dir / "job.json").write_text(json.dumps(job), encoding="utf-8")
    client = TestClient(create_app(str(runtime_dir)))

    response = client.get("/api/jobs/job-1/artifacts/flamegraph")

    assert response.status_code == 403
