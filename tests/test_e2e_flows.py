from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from minidrop_agent.http_jobs import HttpJobRunner, ServerJobClient
from minidrop_analysis.perf import ProfileSummary
from minidrop_apiserver.app import create_app


class FakeProcessInspector:
    def __init__(self, targets: dict[int, dict]) -> None:
        self.targets = targets

    def inspect(self, pid: int) -> dict | None:
        return self.targets.get(pid)


class FakeProfileCollector:
    def __init__(self) -> None:
        self.calls = 0

    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        self.calls += 1
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        flamegraph = output_path / "flamegraph.svg"
        hotspots = output_path / "hotspots.json"
        suggestions = output_path / "suggestions.json"
        summary = output_path / "summary.json"

        flamegraph.write_text("<svg>fake flamegraph</svg>", encoding="utf-8")
        hotspots.write_text(
            json.dumps(
                {
                    "total_samples": 10,
                    "hotspots": [
                        {
                            "function": "hot_func",
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
        suggestions.write_text(
            json.dumps(
                {
                    "source": "hotspots",
                    "finding_count": 1,
                    "findings": [
                        {
                            "rule_id": "cpu_self_hotspot",
                            "title": "CPU self hotspot",
                            "severity": "HIGH",
                            "function": "hot_func",
                            "reason": "hot_func self_percent 80.0 >= 50.0",
                            "next_actions": ["inspect hot_func source"],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        profile_summary = ProfileSummary(
            pid=pid,
            collector="perf",
            status="success",
            duration_seconds=duration_seconds,
            sample_frequency=sample_frequency,
            output_dir=str(output_path),
            created_at="2026-06-20T00:00:00+00:00",
            artifacts={
                "flamegraph": str(flamegraph),
                "hotspots": str(hotspots),
                "suggestions": str(suggestions),
                "summary": str(summary),
            },
        )
        summary.write_text(json.dumps(profile_summary.to_dict()), encoding="utf-8")
        return profile_summary


class TestClientServerJobClient:
    def __init__(self, client: TestClient) -> None:
        self.client = client

    def claim(
        self,
        agent_id: str,
        max_pending_age_seconds: int | None = 300,
        lease_seconds: int = 60,
        max_claim_attempts: int = 3,
    ) -> dict:
        return self._post_json(
            f"/api/agents/{agent_id}/jobs/claim",
            {
                "max_pending_age_seconds": max_pending_age_seconds,
                "lease_seconds": lease_seconds,
                "max_claim_attempts": max_claim_attempts,
            },
        )

    def renew_lease(self, agent_id: str, job_id: str, lease_token: str, lease_seconds: int = 60) -> dict:
        return self._post_json(
            f"/api/agents/{agent_id}/jobs/{job_id}/lease",
            {
                "lease_token": lease_token,
                "lease_seconds": lease_seconds,
            },
        )

    def finish(
        self,
        agent_id: str,
        job_id: str,
        status: str,
        lease_token: str | None = None,
        artifacts: dict[str, str] | None = None,
        error_message: str | None = None,
        reason: str | None = None,
    ) -> dict:
        payload = {
            "status": status,
            "lease_token": lease_token,
            "artifacts": artifacts,
            "error_message": error_message,
            "reason": reason,
        }
        return self._post_json(f"/api/agents/{agent_id}/jobs/{job_id}/finish", payload)

    def upload_artifacts(self, agent_id: str, job_id: str, lease_token: str, artifacts: dict[str, str]) -> dict:
        return self._post_json(
            f"/api/agents/{agent_id}/jobs/{job_id}/artifacts",
            {
                "encoding": "base64",
                "lease_token": lease_token,
                "artifacts": ServerJobClient._encode_uploadable_artifacts(artifacts),
            },
        )

    def _post_json(self, path: str, payload: dict) -> dict:
        response = self.client.post(path, json=payload)
        if response.status_code >= 400:
            raise RuntimeError(f"HTTP {response.status_code}: {response.text}")
        return response.json()


def test_e2e_success_path_creates_job_agent_collects_and_report_is_available(tmp_path: Path) -> None:
    target = {"pid": 1234, "comm": "cpu_hotspot", "cmdline": "/tmp/cpu_hotspot", "starttime": 42}
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: target})))
    collector = FakeProfileCollector()
    runner = HttpJobRunner(
        runtime_dir=str(tmp_path),
        agent_id="agent-e2e",
        client=TestClientServerJobClient(client),
        collector=collector,
        process_inspector=FakeProcessInspector({1234: target}),
        lease_seconds=10,
    )

    created = client.post(
        "/api/jobs",
        json={"pid": 1234, "duration_seconds": 5, "sample_frequency": 49, "collector": "perf"},
    ).json()
    result = runner.run_pending_once(validate_pid=True, max_pending_age_seconds=300)

    assert result is not None
    assert result.status == "DONE"
    assert collector.calls == 1

    job = client.get(f"/api/jobs/{created['job_id']}").json()
    assert job["status"] == "DONE"
    assert {"flamegraph", "hotspots", "suggestions", "summary"} <= set(job["artifacts"])

    events = client.get(f"/api/jobs/{created['job_id']}/events").json()
    assert [event["status"] for event in events] == ["PENDING", "RUNNING", "UPLOADING", "DONE"]

    flamegraph = client.get(f"/api/jobs/{created['job_id']}/artifacts/flamegraph")
    assert flamegraph.status_code == 200
    assert "fake flamegraph" in flamegraph.text

    report = client.get(f"/api/jobs/{created['job_id']}/report").json()
    assert report["job_id"] == created["job_id"]
    assert report["severity"] == "HIGH"
    assert "inspect hot_func source" in report["next_actions"]


def test_e2e_invalid_pid_is_rejected_before_job_enters_queue(tmp_path: Path) -> None:
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({})))

    response = client.post(
        "/api/jobs",
        json={"pid": 999999, "duration_seconds": 5, "sample_frequency": 49, "collector": "perf"},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "TARGET_PROCESS_NOT_FOUND"
    assert client.get("/api/jobs").json() == []


def test_e2e_pid_reuse_guard_marks_claimed_job_failed(tmp_path: Path) -> None:
    original = {"pid": 1234, "comm": "cpu_hotspot", "cmdline": "/tmp/cpu_hotspot", "starttime": 42}
    reused = {"pid": 1234, "comm": "other", "cmdline": "/tmp/other", "starttime": 99}
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: original})))
    collector = FakeProfileCollector()
    runner = HttpJobRunner(
        runtime_dir=str(tmp_path),
        agent_id="agent-e2e",
        client=TestClientServerJobClient(client),
        collector=collector,
        process_inspector=FakeProcessInspector({1234: reused}),
        lease_seconds=10,
    )

    created = client.post(
        "/api/jobs",
        json={"pid": 1234, "duration_seconds": 5, "sample_frequency": 49, "collector": "perf"},
    ).json()
    result = runner.run_pending_once(validate_pid=True, max_pending_age_seconds=300)

    assert result is not None
    assert result.status == "FAILED"
    assert collector.calls == 0

    job = client.get(f"/api/jobs/{created['job_id']}").json()
    assert job["status"] == "FAILED"
    assert job["reason"] == "target process changed before collect"
    assert job["error_message"] == "pid 1234 starttime changed from 42 to 99"

    events = client.get(f"/api/jobs/{created['job_id']}/events").json()
    assert [event["status"] for event in events] == ["PENDING", "RUNNING", "FAILED"]


def test_e2e_continuous_profile_runs_all_slices_through_agent(tmp_path: Path) -> None:
    target = {"pid": 1234, "comm": "cpu_hotspot", "cmdline": "/tmp/cpu_hotspot", "starttime": 42}
    client = TestClient(create_app(str(tmp_path), process_inspector=FakeProcessInspector({1234: target})))
    collector = FakeProfileCollector()
    runner = HttpJobRunner(
        runtime_dir=str(tmp_path),
        agent_id="agent-e2e",
        client=TestClientServerJobClient(client),
        collector=collector,
        process_inspector=FakeProcessInspector({1234: target}),
        lease_seconds=10,
    )

    session = client.post(
        "/api/continuous-profiles",
        json={
            "pid": 1234,
            "slice_duration_seconds": 1,
            "sample_frequency": 49,
            "collector": "perf",
            "slice_count": 2,
            "interval_seconds": 0,
        },
    ).json()
    _force_session_jobs_ready(tmp_path, session)

    first = runner.run_pending_once(validate_pid=True, max_pending_age_seconds=300)
    second = runner.run_pending_once(validate_pid=True, max_pending_age_seconds=300)

    assert first is not None and first.status == "DONE"
    assert second is not None and second.status == "DONE"
    assert collector.calls == 2

    refreshed = client.get(f"/api/continuous-profiles/{session['session_id']}").json()
    assert refreshed["status"] == "DONE"
    assert refreshed["status_counts"] == {"DONE": 2}
    assert [job["status"] for job in refreshed["jobs"]] == ["DONE", "DONE"]


def _force_session_jobs_ready(runtime_dir: Path, session: dict) -> None:
    ready_time = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    for job in session["jobs"]:
        job_file = runtime_dir / "jobs" / job["job_id"] / "job.json"
        payload = json.loads(job_file.read_text(encoding="utf-8"))
        payload["spec"]["scheduled_at"] = ready_time
        job_file.write_text(json.dumps(payload), encoding="utf-8")
