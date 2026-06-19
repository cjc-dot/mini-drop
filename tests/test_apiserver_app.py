from __future__ import annotations

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
