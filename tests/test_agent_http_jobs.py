from __future__ import annotations

import base64
from pathlib import Path

from minidrop_agent.http_jobs import HttpJobRunner, ServerJobClient
from minidrop_analysis.perf import ProfileSummary


class FakeCollector:
    def __init__(self) -> None:
        self.calls = 0

    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        self.calls += 1
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        flamegraph = Path(output_dir) / "flamegraph.svg"
        flamegraph.write_text("<svg></svg>\n", encoding="utf-8")
        return ProfileSummary(
            pid=pid,
            collector="perf",
            status="success",
            duration_seconds=duration_seconds,
            sample_frequency=sample_frequency,
            output_dir=output_dir,
            created_at="2026-06-20T00:00:00+00:00",
            artifacts={"flamegraph": str(flamegraph)},
        )


class FailingCollector:
    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        raise RuntimeError("collector boom")


class FakeClient:
    def __init__(self, claim_response: dict) -> None:
        self.claim_response = claim_response
        self.claim_args = []
        self.renewed = []
        self.uploaded = []
        self.finished = []

    def claim(
        self,
        agent_id: str,
        max_pending_age_seconds: int | None = 300,
        lease_seconds: int = 60,
        max_claim_attempts: int = 3,
    ) -> dict:
        self.claim_args.append(
            {
                "agent_id": agent_id,
                "max_pending_age_seconds": max_pending_age_seconds,
                "lease_seconds": lease_seconds,
                "max_claim_attempts": max_claim_attempts,
            }
        )
        return self.claim_response

    def renew_lease(self, agent_id: str, job_id: str, lease_token: str, lease_seconds: int = 60) -> dict:
        self.renewed.append(
            {
                "agent_id": agent_id,
                "job_id": job_id,
                "lease_token": lease_token,
                "lease_seconds": lease_seconds,
            }
        )
        return {"job_id": job_id, "status": "RUNNING"}

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
            "job_id": job_id,
            "status": status,
            "lease_token": lease_token,
            "artifacts": artifacts or {},
            "error_message": error_message,
            "reason": reason,
        }
        self.finished.append(payload)
        return payload

    def upload_artifacts(self, agent_id: str, job_id: str, lease_token: str, artifacts: dict[str, str]) -> dict:
        self.uploaded.append(
            {
                "agent_id": agent_id,
                "job_id": job_id,
                "lease_token": lease_token,
                "artifacts": artifacts,
            }
        )
        return {
            "job_id": job_id,
            "status": "UPLOADING",
            "artifacts": {name: f"/server/runtime/profiles/{job_id}/{Path(path).name}" for name, path in artifacts.items()},
        }


class FakeProcessInspector:
    def __init__(self, target: dict | None) -> None:
        self.target = target

    def inspect(self, pid: int) -> dict | None:
        return self.target


def _claimed_job() -> dict:
    return {
        "job_id": "job-1",
        "status": "RUNNING",
        "lease_token": "lease-1",
        "spec": {
            "job_id": "job-1",
            "pid": 1234,
            "duration_seconds": 10,
            "sample_frequency": 99,
            "collector": "perf",
            "target": {"pid": 1234, "starttime": 42},
        },
        "artifacts": {},
    }


def test_http_job_runner_returns_none_when_server_has_no_pending_job(tmp_path: Path) -> None:
    skipped = []
    client = FakeClient({"job": None, "skipped": [{"job_id": "old", "reason": "expired", "error_message": "stale"}]})
    runner = HttpJobRunner(runtime_dir=str(tmp_path), client=client)

    result = runner.run_pending_once(on_skip=lambda job_id, reason, error: skipped.append((job_id, reason, error)))

    assert result is None
    assert skipped == [("old", "expired", "stale")]


def test_http_job_runner_claims_collects_and_reports_done(tmp_path: Path) -> None:
    collector = FakeCollector()
    client = FakeClient({"job": _claimed_job(), "skipped": []})
    runner = HttpJobRunner(
        runtime_dir=str(tmp_path),
        agent_id="agent-1",
        client=client,
        collector=collector,
        process_inspector=FakeProcessInspector({"pid": 1234, "starttime": 42}),
    )

    result = runner.run_pending_once(validate_pid=True)

    assert result is not None
    assert result.status == "DONE"
    assert collector.calls == 1
    assert client.claim_args[0]["lease_seconds"] == 60
    assert client.claim_args[0]["max_claim_attempts"] == 3
    assert client.uploaded[0]["job_id"] == "job-1"
    assert client.uploaded[0]["lease_token"] == "lease-1"
    assert client.uploaded[0]["artifacts"]["flamegraph"].endswith("flamegraph.svg")
    assert client.finished[0]["status"] == "DONE"
    assert client.finished[0]["lease_token"] == "lease-1"
    assert client.finished[0]["artifacts"] == {}
    assert result.artifacts["flamegraph"] == "/server/runtime/profiles/job-1/flamegraph.svg"


def test_http_job_runner_reports_failed_when_target_identity_changed(tmp_path: Path) -> None:
    collector = FakeCollector()
    client = FakeClient({"job": _claimed_job(), "skipped": []})
    runner = HttpJobRunner(
        runtime_dir=str(tmp_path),
        agent_id="agent-1",
        client=client,
        collector=collector,
        process_inspector=FakeProcessInspector({"pid": 1234, "starttime": 99}),
    )

    result = runner.run_pending_once(validate_pid=True)

    assert result is not None
    assert result.status == "FAILED"
    assert collector.calls == 0
    assert client.finished[0]["status"] == "FAILED"
    assert client.finished[0]["lease_token"] == "lease-1"
    assert client.finished[0]["reason"] == "target process changed before collect"
    assert client.finished[0]["error_message"] == "pid 1234 starttime changed from 42 to 99"


def test_http_job_runner_reports_failed_when_collector_raises(tmp_path: Path) -> None:
    client = FakeClient({"job": _claimed_job(), "skipped": []})
    runner = HttpJobRunner(
        runtime_dir=str(tmp_path),
        agent_id="agent-1",
        client=client,
        collector=FailingCollector(),
        process_inspector=FakeProcessInspector({"pid": 1234, "starttime": 42}),
    )

    result = runner.run_pending_once(validate_pid=True)

    assert result is not None
    assert result.status == "FAILED"
    assert result.error_message == "collector boom"
    assert client.finished[0]["status"] == "FAILED"
    assert client.finished[0]["lease_token"] == "lease-1"
    assert client.finished[0]["reason"] == "collector failed"


def test_server_job_client_skips_raw_perf_data_when_encoding_uploads(tmp_path: Path) -> None:
    perf_data = tmp_path / "perf.data"
    perf_data.write_bytes(b"raw perf data")
    flamegraph = tmp_path / "flamegraph.svg"
    flamegraph.write_text("<svg></svg>", encoding="utf-8")

    encoded = ServerJobClient._encode_uploadable_artifacts(
        {
            "perf_data": str(perf_data),
            "flamegraph": str(flamegraph),
        }
    )

    assert "perf_data" not in encoded
    assert encoded["flamegraph"] == base64.b64encode(b"<svg></svg>").decode("ascii")
