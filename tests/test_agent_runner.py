from __future__ import annotations

import json
from pathlib import Path

from minidrop_agent.job import JobSpec
from minidrop_agent.runner import LocalAgent
from minidrop_analysis.perf import ProfileSummary
from minidrop_apiserver.store import ServerJobStore


class FakeCollector:
    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
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
            created_at="2026-06-14T00:00:00+00:00",
            artifacts={"flamegraph": str(flamegraph)},
        )


class FailingCollector:
    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        raise RuntimeError("perf failed")


def test_local_agent_persists_successful_state_transitions(tmp_path: Path) -> None:
    spec = JobSpec(job_id="job-test", pid=1234, duration_seconds=10, sample_frequency=99)
    result = LocalAgent(runtime_dir=str(tmp_path), collector=FakeCollector()).run(spec)

    assert result.status == "DONE"

    events = [
        json.loads(line)["status"]
        for line in (tmp_path / "jobs" / "job-test" / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert events == ["PENDING", "RUNNING", "UPLOADING", "DONE"]

    job = json.loads((tmp_path / "jobs" / "job-test" / "job.json").read_text(encoding="utf-8"))
    assert job["status"] == "DONE"
    assert job["artifacts"]["flamegraph"].endswith("flamegraph.svg")
    assert list((tmp_path / "jobs" / "job-test").glob(".*.tmp")) == []


def test_local_agent_persists_failed_state(tmp_path: Path) -> None:
    spec = JobSpec(job_id="job-fail", pid=1234, duration_seconds=10, sample_frequency=99)
    result = LocalAgent(runtime_dir=str(tmp_path), collector=FailingCollector()).run(spec)

    assert result.status == "FAILED"

    job = json.loads((tmp_path / "jobs" / "job-fail" / "job.json").read_text(encoding="utf-8"))
    assert job["status"] == "FAILED"
    assert job["error_message"] == "perf failed"


def test_local_agent_consumes_server_created_pending_job(tmp_path: Path) -> None:
    server_store = ServerJobStore(str(tmp_path))
    pending_job = server_store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)

    result = LocalAgent(runtime_dir=str(tmp_path), collector=FakeCollector()).run_pending_once()

    assert result is not None
    assert result.job_id == pending_job["job_id"]
    assert result.status == "DONE"

    events = [
        json.loads(line)["status"]
        for line in (tmp_path / "jobs" / pending_job["job_id"] / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert events == ["PENDING", "RUNNING", "UPLOADING", "DONE"]

    job = json.loads((tmp_path / "jobs" / pending_job["job_id"] / "job.json").read_text(encoding="utf-8"))
    assert job["status"] == "DONE"
    assert job["created_at"] == pending_job["created_at"]


def test_local_agent_can_consume_specific_pending_job(tmp_path: Path) -> None:
    server_store = ServerJobStore(str(tmp_path))
    first = server_store.create_job(pid=1001, duration_seconds=10, sample_frequency=99)
    second = server_store.create_job(pid=1002, duration_seconds=10, sample_frequency=99)

    result = LocalAgent(runtime_dir=str(tmp_path), collector=FakeCollector()).run_pending_once(job_id=second["job_id"])

    assert result is not None
    assert result.job_id == second["job_id"]
    assert server_store.get_job(first["job_id"])["status"] == "PENDING"
    assert server_store.get_job(second["job_id"])["status"] == "DONE"
