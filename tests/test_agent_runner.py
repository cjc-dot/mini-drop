from __future__ import annotations

import json
from pathlib import Path

from minidrop_agent.job import JobSpec
from minidrop_agent.runner import LocalAgent
from minidrop_agent.store import JobStore
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


class CountingCollector(FakeCollector):
    def __init__(self) -> None:
        self.calls = 0

    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        self.calls += 1
        return super().collect(pid, duration_seconds, sample_frequency, output_dir)


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


def test_claim_pending_spec_moves_job_to_running(tmp_path: Path) -> None:
    server_store = ServerJobStore(str(tmp_path))
    pending_job = server_store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    store = JobStore(str(tmp_path))

    spec = store.claim_pending_spec(job_id=pending_job["job_id"])

    assert spec is not None
    assert spec.job_id == pending_job["job_id"]
    job = server_store.get_job(pending_job["job_id"])
    assert job["status"] == "RUNNING"
    assert job["reason"] == "job claimed by local agent"
    events = [
        json.loads(line)["status"]
        for line in (tmp_path / "jobs" / pending_job["job_id"] / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert events == ["PENDING", "RUNNING"]


def test_claim_pending_spec_returns_none_for_non_pending_job(tmp_path: Path) -> None:
    server_store = ServerJobStore(str(tmp_path))
    pending_job = server_store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    store = JobStore(str(tmp_path))
    assert store.claim_pending_spec(job_id=pending_job["job_id"]) is not None

    assert store.claim_pending_spec(job_id=pending_job["job_id"]) is None


def test_local_agent_does_not_execute_already_claimed_job(tmp_path: Path) -> None:
    server_store = ServerJobStore(str(tmp_path))
    pending_job = server_store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    store = JobStore(str(tmp_path))
    assert store.claim_pending_spec(job_id=pending_job["job_id"]) is not None
    collector = CountingCollector()

    result = LocalAgent(runtime_dir=str(tmp_path), collector=collector).run_pending_once(job_id=pending_job["job_id"])

    assert result is None
    assert collector.calls == 0
    assert server_store.get_job(pending_job["job_id"])["status"] == "RUNNING"


def test_local_agent_can_consume_specific_pending_job(tmp_path: Path) -> None:
    server_store = ServerJobStore(str(tmp_path))
    first = server_store.create_job(pid=1001, duration_seconds=10, sample_frequency=99)
    second = server_store.create_job(pid=1002, duration_seconds=10, sample_frequency=99)

    result = LocalAgent(runtime_dir=str(tmp_path), collector=FakeCollector()).run_pending_once(job_id=second["job_id"])

    assert result is not None
    assert result.job_id == second["job_id"]
    assert server_store.get_job(first["job_id"])["status"] == "PENDING"
    assert server_store.get_job(second["job_id"])["status"] == "DONE"
