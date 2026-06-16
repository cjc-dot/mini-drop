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
    assert 'fetchJson("/api/jobs", {' in app_js


def test_web_ui_route_serves_index(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path)))

    response = client.get("/ui")
    slash_response = client.get("/ui/")

    assert response.status_code == 200
    assert slash_response.status_code == 200
    assert "Mini-Drop" in response.text


def test_artifact_route_serves_flamegraph_inside_runtime(tmp_path: Path) -> None:
    runtime_dir = tmp_path / "runtime"
    profile_dir = runtime_dir / "profiles" / "job-1"
    job_dir = runtime_dir / "jobs" / "job-1"
    profile_dir.mkdir(parents=True)
    job_dir.mkdir(parents=True)

    flamegraph = profile_dir / "flamegraph.svg"
    flamegraph.write_text("<svg>ok</svg>", encoding="utf-8")
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
        "artifacts": {"flamegraph": str(flamegraph)},
        "reason": "job completed successfully",
        "error_message": None,
        "created_at": "2026-06-16T00:00:00+00:00",
        "updated_at": "2026-06-16T00:00:10+00:00",
    }
    (job_dir / "job.json").write_text(json.dumps(job), encoding="utf-8")
    client = TestClient(create_app(str(runtime_dir)))

    response = client.get("/api/jobs/job-1/artifacts/flamegraph")

    assert response.status_code == 200
    assert response.text == "<svg>ok</svg>"


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
