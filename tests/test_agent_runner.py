from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from minidrop_agent.job import JobSpec
from minidrop_agent.runner import LocalAgent
from minidrop_agent.store import InvalidJobTransition, JobStore
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


def test_claim_pending_spec_marks_missing_pid_failed_and_skips_to_next_pending_job(tmp_path: Path) -> None:
    store = JobStore(str(tmp_path), pid_exists=lambda pid: pid == 2222)
    missing_pid = JobSpec(job_id="job-001", pid=1111, duration_seconds=10, sample_frequency=99)
    live_pid = JobSpec(job_id="job-002", pid=2222, duration_seconds=10, sample_frequency=99)
    store.init_job(missing_pid)
    store.init_job(live_pid)
    skipped = []

    claimed = store.claim_pending_spec(
        validate_pid=True,
        on_skip=lambda job_id, reason, error: skipped.append((job_id, reason, error)),
    )

    assert claimed is not None
    assert claimed.job_id == "job-002"
    assert skipped == [("job-001", "target process not found before claim", "pid 1111 does not exist")]
    missing_job = store.read_job("job-001")
    assert missing_job["status"] == "FAILED"
    assert missing_job["reason"] == "target process not found before claim"
    assert missing_job["error_message"] == "pid 1111 does not exist"
    live_job = store.read_job("job-002")
    assert live_job["status"] == "RUNNING"


def test_claim_pending_spec_marks_pid_reuse_failed_and_skips_to_next_pending_job(tmp_path: Path) -> None:
    def inspect_process(pid: int) -> dict | None:
        return {
            1111: {"pid": 1111, "starttime": 20},
            2222: {"pid": 2222, "starttime": 30},
        }.get(pid)

    store = JobStore(str(tmp_path), pid_exists=lambda pid: True, inspect_process=inspect_process)
    reused_pid = JobSpec(
        job_id="job-001",
        pid=1111,
        duration_seconds=10,
        sample_frequency=99,
        target={"pid": 1111, "starttime": 10},
    )
    live_pid = JobSpec(
        job_id="job-002",
        pid=2222,
        duration_seconds=10,
        sample_frequency=99,
        target={"pid": 2222, "starttime": 30},
    )
    store.init_job(reused_pid)
    store.init_job(live_pid)
    skipped = []

    claimed = store.claim_pending_spec(
        validate_pid=True,
        on_skip=lambda job_id, reason, error: skipped.append((job_id, reason, error)),
    )

    assert claimed is not None
    assert claimed.job_id == "job-002"
    assert skipped == [
        ("job-001", "target process changed before claim", "pid 1111 starttime changed from 10 to 20")
    ]
    reused_job = store.read_job("job-001")
    assert reused_job["status"] == "FAILED"
    assert reused_job["reason"] == "target process changed before claim"
    assert reused_job["error_message"] == "pid 1111 starttime changed from 10 to 20"
    live_job = store.read_job("job-002")
    assert live_job["status"] == "RUNNING"


def test_claim_pending_spec_allows_old_jobs_without_target_identity(tmp_path: Path) -> None:
    store = JobStore(str(tmp_path), pid_exists=lambda pid: True, inspect_process=lambda pid: {"pid": pid, "starttime": 20})
    old_job = JobSpec(job_id="job-001", pid=1111, duration_seconds=10, sample_frequency=99)
    store.init_job(old_job)

    claimed = store.claim_pending_spec(validate_pid=True)

    assert claimed is not None
    assert claimed.job_id == "job-001"
    assert store.read_job("job-001")["status"] == "RUNNING"


def test_claim_pending_spec_marks_stale_pending_job_failed_and_skips_to_next_pending_job(tmp_path: Path) -> None:
    store = JobStore(str(tmp_path), pid_exists=lambda pid: True)
    stale = JobSpec(job_id="job-001", pid=1111, duration_seconds=10, sample_frequency=99)
    fresh = JobSpec(job_id="job-002", pid=2222, duration_seconds=10, sample_frequency=99)
    store.init_job(stale)
    store.init_job(fresh)

    stale_job = store.read_job("job-001")
    stale_job["created_at"] = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()
    stale_job["updated_at"] = stale_job["created_at"]
    store._write_json_atomic(store.job_file("job-001"), stale_job)
    skipped = []

    claimed = store.claim_pending_spec(
        validate_pid=True,
        max_pending_age_seconds=300,
        on_skip=lambda job_id, reason, error: skipped.append((job_id, reason, error)),
    )

    assert claimed is not None
    assert claimed.job_id == "job-002"
    assert skipped == [
        ("job-001", "pending job expired before claim", "job stayed PENDING for more than 300 seconds")
    ]
    expired_job = store.read_job("job-001")
    assert expired_job["status"] == "FAILED"
    assert expired_job["reason"] == "pending job expired before claim"
    assert expired_job["error_message"] == "job stayed PENDING for more than 300 seconds"


def test_transition_job_rejects_unexpected_status(tmp_path: Path) -> None:
    server_store = ServerJobStore(str(tmp_path))
    pending_job = server_store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    store = JobStore(str(tmp_path))
    assert store.claim_pending_spec(job_id=pending_job["job_id"]) is not None

    try:
        store.transition_job(
            pending_job["job_id"],
            "UPLOADING",
            "artifacts ready",
            expected_status="PENDING",
        )
    except InvalidJobTransition:
        pass
    else:
        raise AssertionError("transition_job should reject an unexpected current status")

    job = server_store.get_job(pending_job["job_id"])
    assert job["status"] == "RUNNING"
    events = [
        json.loads(line)["status"]
        for line in (tmp_path / "jobs" / pending_job["job_id"] / "events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert events == ["PENDING", "RUNNING"]


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
