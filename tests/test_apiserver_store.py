from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from minidrop_apiserver.store import InvalidJobTransition, ServerJobStore


def test_create_job_persists_pending_snapshot_and_event(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    job = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)

    assert job["status"] == "PENDING"
    assert job["spec"]["pid"] == 1234
    assert job["spec"]["collector"] == "perf"

    saved = store.get_job(job["job_id"])
    assert saved is not None
    assert saved["job_id"] == job["job_id"]
    assert saved["status"] == "PENDING"

    events = store.get_events(job["job_id"])
    assert [event["status"] for event in events] == ["PENDING"]
    assert events[0]["reason"] == "job created by api server"


def test_list_jobs_returns_newest_first(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    first = store.create_job(pid=1001, duration_seconds=10, sample_frequency=99)
    second = store.create_job(pid=1002, duration_seconds=10, sample_frequency=99)

    jobs = store.list_jobs()

    assert [job["job_id"] for job in jobs] == [second["job_id"], first["job_id"]]


def test_get_missing_job_returns_none(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))

    assert store.get_job("missing-job") is None
    assert store.get_events("missing-job") == []


def test_create_job_atomic_snapshot_write_leaves_no_temp_file(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    job = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    job_dir = tmp_path / "jobs" / job["job_id"]

    assert (job_dir / "job.json").exists()
    assert list(job_dir.glob(".*.tmp")) == []


def test_claim_pending_job_marks_job_running_and_records_agent(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)

    claim = store.claim_pending_job(agent_id="agent-1")

    assert claim["skipped"] == []
    assert claim["job"]["job_id"] == pending["job_id"]
    assert claim["job"]["status"] == "RUNNING"
    assert claim["job"]["claimed_by"] == "agent-1"
    assert store.get_job(pending["job_id"])["status"] == "RUNNING"
    assert [event["status"] for event in store.get_events(pending["job_id"])] == ["PENDING", "RUNNING"]


def test_claim_pending_job_marks_stale_job_failed_and_claims_next(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    stale = store.create_job(pid=1001, duration_seconds=10, sample_frequency=99)
    fresh = store.create_job(pid=1002, duration_seconds=10, sample_frequency=99)

    stale_job = store.get_job(stale["job_id"])
    stale_job["created_at"] = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()
    stale_job["updated_at"] = stale_job["created_at"]
    store._write_json_atomic(tmp_path / "jobs" / stale["job_id"] / "job.json", stale_job)

    claim = store.claim_pending_job(agent_id="agent-1", max_pending_age_seconds=300)

    assert claim["job"]["job_id"] == fresh["job_id"]
    assert claim["job"]["status"] == "RUNNING"
    assert claim["skipped"] == [
        {
            "job_id": stale["job_id"],
            "reason": "pending job expired before claim",
            "error_message": "job stayed PENDING for more than 300 seconds",
            "status": "FAILED",
        }
    ]
    assert store.get_job(stale["job_id"])["status"] == "FAILED"


def test_finish_claimed_job_records_uploading_and_done_events(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    store.claim_pending_job(agent_id="agent-1")

    done = store.finish_claimed_job(
        agent_id="agent-1",
        job_id=pending["job_id"],
        status="DONE",
        artifacts={"flamegraph": "/tmp/flamegraph.svg"},
    )

    assert done["status"] == "DONE"
    assert done["artifacts"] == {"flamegraph": "/tmp/flamegraph.svg"}
    assert [event["status"] for event in store.get_events(pending["job_id"])] == [
        "PENDING",
        "RUNNING",
        "UPLOADING",
        "DONE",
    ]


def test_finish_claimed_job_rejects_other_agent(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    store.claim_pending_job(agent_id="agent-1")

    try:
        store.finish_claimed_job(agent_id="agent-2", job_id=pending["job_id"], status="DONE")
    except InvalidJobTransition:
        pass
    else:
        raise AssertionError("finish_claimed_job should reject a different agent")
