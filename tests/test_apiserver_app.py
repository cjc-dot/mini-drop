from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from fastapi.testclient import TestClient

from minidrop_apiserver.app import create_app


class FakeProcessInspector:
    def __init__(self, targets: dict[int, dict]) -> None:
        self.targets = targets

    def inspect(self, pid: int) -> dict | None:
        return self.targets.get(pid)


def test_create_job_rejects_missing_target_pid(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({})))

    response = client.post(
        "/api/jobs",
        json={"pid": 999999, "duration_seconds": 10, "sample_frequency": 99},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "TARGET_PROCESS_NOT_FOUND"
    assert response.json()["detail"]["message"] == "target pid 999999 does not exist"


def test_create_job_persists_target_process_metadata(tmp_path) -> None:
    target = {
        "pid": 1234,
        "comm": "cpu_hotspot",
        "cmdline": "/tmp/cpu_hotspot",
        "starttime": 42,
    }
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: target})))

    response = client.post(
        "/api/jobs",
        json={"pid": 1234, "duration_seconds": 10, "sample_frequency": 99},
    )

    assert response.status_code == 201
    job = response.json()
    assert job["status"] == "PENDING"
    assert job["spec"]["pid"] == 1234
    assert job["spec"]["target"] == target


def test_create_job_accepts_ebpf_syscall_collector(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: {"pid": 1234}})))

    response = client.post(
        "/api/jobs",
        json={
            "pid": 1234,
            "duration_seconds": 10,
            "sample_frequency": 99,
            "collector": "ebpf_syscall",
        },
    )

    assert response.status_code == 201
    assert response.json()["spec"]["collector"] == "ebpf_syscall"


def test_create_job_accepts_ebpf_io_latency_collector(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: {"pid": 1234}})))

    response = client.post(
        "/api/jobs",
        json={
            "pid": 1234,
            "duration_seconds": 10,
            "sample_frequency": 99,
            "collector": "ebpf_io_latency",
        },
    )

    assert response.status_code == 201
    assert response.json()["spec"]["collector"] == "ebpf_io_latency"


def test_create_job_accepts_py_spy_collector(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: {"pid": 1234}})))

    response = client.post(
        "/api/jobs",
        json={
            "pid": 1234,
            "duration_seconds": 10,
            "sample_frequency": 99,
            "collector": "py_spy",
        },
    )

    assert response.status_code == 201
    assert response.json()["spec"]["collector"] == "py_spy"


def test_agent_claim_and_finish_job_over_http(tmp_path) -> None:
    target = {
        "pid": 1234,
        "comm": "cpu_hotspot",
        "cmdline": "/tmp/cpu_hotspot",
        "starttime": 42,
    }
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: target})))
    created = client.post(
        "/api/jobs",
        json={"pid": 1234, "duration_seconds": 10, "sample_frequency": 99},
    ).json()

    claim_response = client.post(
        "/api/agents/local-agent/jobs/claim",
        json={"max_pending_age_seconds": 300},
    )

    assert claim_response.status_code == 200
    claim = claim_response.json()
    assert claim["job"]["job_id"] == created["job_id"]
    assert claim["job"]["status"] == "RUNNING"
    assert claim["job"]["claimed_by"] == "local-agent"
    lease_token = claim["job"]["lease_token"]

    finish_response = client.post(
        f"/api/agents/local-agent/jobs/{created['job_id']}/finish",
        json={
            "status": "DONE",
            "lease_token": lease_token,
            "artifacts": {"flamegraph": str(tmp_path / "profiles" / created["job_id"] / "flamegraph.svg")},
        },
    )

    assert finish_response.status_code == 200
    assert finish_response.json()["status"] == "DONE"
    events = client.get(f"/api/jobs/{created['job_id']}/events").json()
    assert [event["status"] for event in events] == ["PENDING", "RUNNING", "UPLOADING", "DONE"]


def test_agent_finish_rejects_unclaimed_job_over_http(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: {"pid": 1234}})))
    created = client.post(
        "/api/jobs",
        json={"pid": 1234, "duration_seconds": 10, "sample_frequency": 99},
    ).json()

    response = client.post(
        f"/api/agents/local-agent/jobs/{created['job_id']}/finish",
        json={"status": "DONE", "artifacts": {}},
    )

    assert response.status_code == 409


def test_agent_uploads_artifacts_over_http_before_finish(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: {"pid": 1234}})))
    created = client.post(
        "/api/jobs",
        json={"pid": 1234, "duration_seconds": 10, "sample_frequency": 99},
    ).json()
    claimed = client.post("/api/agents/local-agent/jobs/claim", json={"max_pending_age_seconds": 300}).json()["job"]
    lease_token = claimed["lease_token"]

    upload_response = client.post(
        f"/api/agents/local-agent/jobs/{created['job_id']}/artifacts",
        json={
            "encoding": "base64",
            "lease_token": lease_token,
            "artifacts": {
                "flamegraph": base64.b64encode(b"<svg>uploaded</svg>").decode("ascii"),
            },
        },
    )

    assert upload_response.status_code == 200
    uploaded = upload_response.json()
    assert uploaded["status"] == "UPLOADING"
    flamegraph = tmp_path / "profiles" / created["job_id"] / "flamegraph.svg"
    assert flamegraph.read_text(encoding="utf-8") == "<svg>uploaded</svg>"

    finish_response = client.post(
        f"/api/agents/local-agent/jobs/{created['job_id']}/finish",
        json={"status": "DONE", "lease_token": lease_token},
    )

    assert finish_response.status_code == 200
    assert finish_response.json()["artifacts"]["flamegraph"] == str(flamegraph)
    events = client.get(f"/api/jobs/{created['job_id']}/events").json()
    assert [event["status"] for event in events] == ["PENDING", "RUNNING", "UPLOADING", "DONE"]


def test_agent_renews_claimed_job_lease_over_http(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: {"pid": 1234}})))
    created = client.post(
        "/api/jobs",
        json={"pid": 1234, "duration_seconds": 10, "sample_frequency": 99},
    ).json()
    claimed = client.post(
        "/api/agents/local-agent/jobs/claim",
        json={"max_pending_age_seconds": 300, "lease_seconds": 1},
    ).json()["job"]

    response = client.post(
        f"/api/agents/local-agent/jobs/{created['job_id']}/lease",
        json={"lease_token": claimed["lease_token"], "lease_seconds": 60},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "RUNNING"
    assert response.json()["lease_expires_at"] > claimed["lease_expires_at"]


def test_maintenance_endpoint_requeues_expired_running_jobs(tmp_path) -> None:
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: {"pid": 1234}})))
    created = client.post(
        "/api/jobs",
        json={"pid": 1234, "duration_seconds": 10, "sample_frequency": 99},
    ).json()
    claimed = client.post(
        "/api/agents/crash-agent/jobs/claim",
        json={"max_pending_age_seconds": 300, "lease_seconds": 60, "max_claim_attempts": 3},
    ).json()["job"]
    claimed["lease_expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    job_file = Path(tmp_path) / "jobs" / created["job_id"] / "job.json"
    job_file.write_text(json.dumps(claimed), encoding="utf-8")

    response = client.post(
        "/api/maintenance/requeue-expired-leases",
        json={"max_claim_attempts": 3},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["processed_count"] == 1
    assert payload["processed"][0]["reason"] == "job lease expired before completion"
    job = client.get(f"/api/jobs/{created['job_id']}").json()
    assert job["status"] == "PENDING"
    assert job["previous_claimed_by"] == "crash-agent"


def test_compare_ebpf_io_latency_uses_previous_done_job_as_baseline(tmp_path) -> None:
    runtime_dir = tmp_path / "runtime"
    _write_latency_job(
        runtime_dir=runtime_dir,
        job_id="job-base",
        created_at="2026-06-20T00:00:00+00:00",
        tail_1ms_percent=1.0,
        p99_bucket="10-100",
    )
    _write_latency_job(
        runtime_dir=runtime_dir,
        job_id="job-current",
        created_at="2026-06-20T00:01:00+00:00",
        tail_1ms_percent=25.0,
        p99_bucket="1000-10000",
    )
    client = TestClient(create_app(str(runtime_dir), process_inspector=FakeProcessInspector({})))

    response = client.get("/api/jobs/job-current/compare/ebpf-io-latency")

    assert response.status_code == 200
    payload = response.json()
    assert payload["comparison_available"] is True
    assert payload["baseline_job_id"] == "job-base"
    assert payload["current_job_id"] == "job-current"
    assert payload["events"][0]["verdict"] == "regressed"
    assert payload["finding_count"] == 1


def test_compare_ebpf_io_latency_returns_no_baseline_report(tmp_path) -> None:
    runtime_dir = tmp_path / "runtime"
    _write_latency_job(
        runtime_dir=runtime_dir,
        job_id="job-current",
        created_at="2026-06-20T00:01:00+00:00",
        tail_1ms_percent=25.0,
        p99_bucket="1000-10000",
    )
    client = TestClient(create_app(str(runtime_dir), process_inspector=FakeProcessInspector({})))

    response = client.get("/api/jobs/job-current/compare/ebpf-io-latency")

    assert response.status_code == 200
    payload = response.json()
    assert payload["comparison_available"] is False
    assert payload["reason"] == "no previous ebpf_io_latency baseline job found"


def test_diagnostic_report_endpoint_aggregates_job_artifacts_and_baseline_diff(tmp_path) -> None:
    runtime_dir = tmp_path / "runtime"
    _write_latency_job(
        runtime_dir=runtime_dir,
        job_id="job-base",
        created_at="2026-06-20T00:00:00+00:00",
        tail_1ms_percent=1.0,
        p99_bucket="10-100",
    )
    _write_latency_job(
        runtime_dir=runtime_dir,
        job_id="job-current",
        created_at="2026-06-20T00:01:00+00:00",
        tail_1ms_percent=25.0,
        p99_bucket="1000-10000",
    )
    current_profile = runtime_dir / "profiles" / "job-current"
    suggestions = current_profile / "suggestions.json"
    suggestions.write_text(
        json.dumps(
            {
                "source": "ebpf_io_latency",
                "finding_count": 1,
                "findings": [
                    {
                        "rule_id": "io_latency_tail_over_1ms",
                        "title": "IO latency has visible tail over 1ms",
                        "severity": "MEDIUM",
                        "target": "read",
                        "reason": "read tail is visible",
                        "next_actions": ["inspect read path"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    job_file = runtime_dir / "jobs" / "job-current" / "job.json"
    job = json.loads(job_file.read_text(encoding="utf-8"))
    job["artifacts"]["suggestions"] = str(suggestions)
    job_file.write_text(json.dumps(job), encoding="utf-8")
    client = TestClient(create_app(str(runtime_dir), process_inspector=FakeProcessInspector({})))

    response = client.get("/api/jobs/job-current/report")

    assert response.status_code == 200
    report = response.json()
    assert report["source"] == "diagnostic_report"
    assert report["job_id"] == "job-current"
    assert report["severity"] == "HIGH"
    assert report["finding_count"] == 2
    assert "inspect read path" in report["next_actions"]
    assert {section["section_id"] for section in report["sections"]} >= {
        "job_overview",
        "ebpf_io_latency",
        "baseline_diff",
        "findings",
    }


def test_diagnostic_report_endpoint_includes_python_profile_section(tmp_path) -> None:
    runtime_dir = tmp_path / "runtime"
    profile_dir = runtime_dir / "profiles" / "job-python"
    job_dir = runtime_dir / "jobs" / "job-python"
    profile_dir.mkdir(parents=True)
    job_dir.mkdir(parents=True)
    pyspy_profile = profile_dir / "py_spy_profile.json"
    pyspy_profile.write_text(
        json.dumps(
            {
                "collector": "py_spy",
                "total_samples": 10,
                "tool_version": "py-spy 0.test",
                "hotspots": [
                    {
                        "function": "hot_python_loop",
                        "file": "workloads/python_hotspot.py",
                        "line": 8,
                        "self_samples": 8,
                        "inclusive_samples": 8,
                        "self_percent": 80.0,
                        "inclusive_percent": 80.0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    job = {
        "job_id": "job-python",
        "status": "DONE",
        "reason": "job completed successfully",
        "spec": {
            "job_id": "job-python",
            "pid": 1234,
            "duration_seconds": 5,
            "sample_frequency": 99,
            "collector": "py_spy",
            "target": {"comm": "python3"},
        },
        "artifacts": {"pyspy_profile": str(pyspy_profile)},
        "error_message": None,
        "created_at": "2026-06-16T00:00:00+00:00",
        "updated_at": "2026-06-16T00:00:10+00:00",
    }
    (job_dir / "job.json").write_text(json.dumps(job), encoding="utf-8")
    client = TestClient(create_app(str(runtime_dir), process_inspector=FakeProcessInspector({})))

    response = client.get("/api/jobs/job-python/report")

    assert response.status_code == 200
    report = response.json()
    assert report["collector"] == "py_spy"
    assert "python_profile" in {section["section_id"] for section in report["sections"]}


def _write_latency_job(
    runtime_dir: Path,
    job_id: str,
    created_at: str,
    tail_1ms_percent: float,
    p99_bucket: str,
) -> None:
    profile_dir = runtime_dir / "profiles" / job_id
    job_dir = runtime_dir / "jobs" / job_id
    profile_dir.mkdir(parents=True)
    job_dir.mkdir(parents=True)
    latency_file = profile_dir / "ebpf_io_latency.json"
    latency_file.write_text(
        json.dumps(
            {
                "collector": "ebpf_io_latency",
                "created_at": created_at,
                "unit": "us",
                "total_events": 100,
                "events": [
                    {
                        "event": "read",
                        "total_count": 100,
                        "histogram": [
                            {"bucket": "0-10", "count": 90, "percent": 90.0},
                            {"bucket": "10-100", "count": 0, "percent": 0.0},
                            {"bucket": "100-1000", "count": 0, "percent": 0.0},
                            {"bucket": "1000-10000", "count": 10, "percent": tail_1ms_percent},
                            {"bucket": "10000+", "count": 0, "percent": 0.0},
                        ],
                        "p50_bucket": "0-10",
                        "p95_bucket": p99_bucket,
                        "p99_bucket": p99_bucket,
                        "tail_1ms_count": 10,
                        "tail_1ms_percent": tail_1ms_percent,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    job = {
        "job_id": job_id,
        "status": "DONE",
        "reason": "job completed successfully",
        "spec": {
            "job_id": job_id,
            "pid": 1234,
            "duration_seconds": 5,
            "sample_frequency": 99,
            "collector": "ebpf_io_latency",
            "target": {"comm": "io_latency_hotspot"},
        },
        "artifacts": {"ebpf_io_latency": str(latency_file)},
        "error_message": None,
        "created_at": created_at,
        "updated_at": created_at,
    }
    (job_dir / "job.json").write_text(json.dumps(job), encoding="utf-8")
