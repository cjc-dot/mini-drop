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
