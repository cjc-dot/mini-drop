from __future__ import annotations

import base64
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

    claim = store.claim_pending_job(agent_id="agent-1", lease_seconds=60)

    assert claim["skipped"] == []
    assert claim["job"]["job_id"] == pending["job_id"]
    assert claim["job"]["status"] == "RUNNING"
    assert claim["job"]["claimed_by"] == "agent-1"
    assert claim["job"]["claim_attempts"] == 1
    assert claim["job"]["lease_token"]
    assert claim["job"]["lease_expires_at"] is not None
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
    claimed = store.claim_pending_job(agent_id="agent-1")["job"]

    done = store.finish_claimed_job(
        agent_id="agent-1",
        job_id=pending["job_id"],
        status="DONE",
        lease_token=claimed["lease_token"],
        artifacts={"flamegraph": "/tmp/flamegraph.svg"},
    )

    assert done["status"] == "DONE"
    assert done["artifacts"] == {"flamegraph": "/tmp/flamegraph.svg"}
    assert done["lease_token"] is None
    assert done["lease_expires_at"] is None
    assert [event["status"] for event in store.get_events(pending["job_id"])] == [
        "PENDING",
        "RUNNING",
        "UPLOADING",
        "DONE",
    ]


def test_finish_claimed_job_failure_clears_lease_fields(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    claimed = store.claim_pending_job(agent_id="agent-1")["job"]

    failed = store.finish_claimed_job(
        agent_id="agent-1",
        job_id=pending["job_id"],
        status="FAILED",
        lease_token=claimed["lease_token"],
        reason="collector failed",
        error_message="perf failed",
    )

    assert failed["status"] == "FAILED"
    assert failed["reason"] == "collector failed"
    assert failed["error_message"] == "perf failed"
    assert failed["lease_token"] is None
    assert failed["lease_expires_at"] is None
    assert [event["status"] for event in store.get_events(pending["job_id"])] == ["PENDING", "RUNNING", "FAILED"]


def test_finish_claimed_job_rejects_other_agent(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    claimed = store.claim_pending_job(agent_id="agent-1")["job"]

    try:
        store.finish_claimed_job(
            agent_id="agent-2",
            job_id=pending["job_id"],
            status="DONE",
            lease_token=claimed["lease_token"],
        )
    except InvalidJobTransition:
        pass
    else:
        raise AssertionError("finish_claimed_job should reject a different agent")


def test_upload_artifacts_writes_files_inside_server_runtime(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    claimed = store.claim_pending_job(agent_id="agent-1")["job"]

    uploaded = store.upload_artifacts(
        agent_id="agent-1",
        job_id=pending["job_id"],
        lease_token=claimed["lease_token"],
        artifact_payloads={
            "flamegraph": base64.b64encode(b"<svg>server copy</svg>").decode("ascii"),
            "hotspots": base64.b64encode(b'{"hotspots": []}').decode("ascii"),
        },
    )

    assert uploaded["status"] == "UPLOADING"
    flamegraph = tmp_path / "profiles" / pending["job_id"] / "flamegraph.svg"
    hotspots = tmp_path / "profiles" / pending["job_id"] / "hotspots.json"
    assert flamegraph.read_text(encoding="utf-8") == "<svg>server copy</svg>"
    assert hotspots.read_text(encoding="utf-8") == '{"hotspots": []}'
    assert uploaded["artifacts"]["flamegraph"] == str(flamegraph)
    assert uploaded["artifacts"]["hotspots"] == str(hotspots)

    done = store.finish_claimed_job(
        agent_id="agent-1",
        job_id=pending["job_id"],
        status="DONE",
        lease_token=claimed["lease_token"],
    )

    assert done["status"] == "DONE"
    assert done["artifacts"]["flamegraph"] == str(flamegraph)
    assert [event["status"] for event in store.get_events(pending["job_id"])] == [
        "PENDING",
        "RUNNING",
        "UPLOADING",
        "DONE",
    ]


def test_upload_artifacts_rejects_unknown_artifact_name(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    claimed = store.claim_pending_job(agent_id="agent-1")["job"]

    try:
        store.upload_artifacts(
            agent_id="agent-1",
            job_id=pending["job_id"],
            lease_token=claimed["lease_token"],
            artifact_payloads={"../../bad": base64.b64encode(b"bad").decode("ascii")},
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("upload_artifacts should reject unknown artifact names")


def test_renew_job_lease_extends_running_job_deadline(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    claimed = store.claim_pending_job(agent_id="agent-1", lease_seconds=1)["job"]

    renewed = store.renew_job_lease(
        agent_id="agent-1",
        job_id=pending["job_id"],
        lease_token=claimed["lease_token"],
        lease_seconds=60,
    )

    assert renewed["status"] == "RUNNING"
    assert renewed["claimed_by"] == "agent-1"
    assert renewed["lease_expires_at"] > claimed["lease_expires_at"]


def test_requeue_expired_leases_moves_running_job_back_to_pending(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    claimed = store.claim_pending_job(agent_id="agent-1", lease_seconds=60)["job"]
    claimed["lease_expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    store._write_json_atomic(tmp_path / "jobs" / pending["job_id"] / "job.json", claimed)

    skipped = store.requeue_expired_leases()

    assert skipped == [
        {
            "job_id": pending["job_id"],
            "reason": "job lease expired before completion",
            "error_message": f"lease expired at {claimed['lease_expires_at']}",
            "status": "PENDING",
        }
    ]
    job = store.get_job(pending["job_id"])
    assert job["status"] == "PENDING"
    assert job["artifacts"] == {}
    assert job["claimed_by"] is None
    assert job["lease_token"] is None
    assert job["lease_expires_at"] is None
    assert job["previous_claimed_by"] == "agent-1"
    assert [event["status"] for event in store.get_events(pending["job_id"])] == ["PENDING", "RUNNING", "PENDING"]


def test_requeue_expired_leases_fails_uploading_job_instead_of_requeueing(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    claimed = store.claim_pending_job(agent_id="agent-1", lease_seconds=60)["job"]
    uploaded = store.upload_artifacts(
        agent_id="agent-1",
        job_id=pending["job_id"],
        lease_token=claimed["lease_token"],
        artifact_payloads={"flamegraph": base64.b64encode(b"<svg>partial</svg>").decode("ascii")},
    )
    uploaded["lease_expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    store._write_json_atomic(tmp_path / "jobs" / pending["job_id"] / "job.json", uploaded)

    skipped = store.requeue_expired_leases(max_claim_attempts=3)

    assert skipped == [
        {
            "job_id": pending["job_id"],
            "reason": "job lease expired during artifact upload",
            "error_message": f"lease expired at {uploaded['lease_expires_at']}",
            "status": "FAILED",
        }
    ]
    job = store.get_job(pending["job_id"])
    assert job["status"] == "FAILED"
    assert job["artifacts"] == {}
    assert job["previous_claimed_by"] == "agent-1"
    assert job["lease_token"] is None
    assert job["lease_expires_at"] is None
    assert [event["status"] for event in store.get_events(pending["job_id"])] == [
        "PENDING",
        "RUNNING",
        "UPLOADING",
        "FAILED",
    ]


def test_requeue_expired_lease_fails_job_after_claim_attempt_limit(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    claimed = store.claim_pending_job(agent_id="agent-1", lease_seconds=60, max_claim_attempts=1)["job"]
    claimed["lease_expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    store._write_json_atomic(tmp_path / "jobs" / pending["job_id"] / "job.json", claimed)

    skipped = store.requeue_expired_leases(max_claim_attempts=1)

    assert skipped == [
        {
            "job_id": pending["job_id"],
            "reason": "job claim attempts exhausted after lease expiration",
            "error_message": "job was claimed 1 time(s); max allowed is 1",
            "status": "FAILED",
        }
    ]
    job = store.get_job(pending["job_id"])
    assert job["status"] == "FAILED"
    assert job["previous_claimed_by"] == "agent-1"
    assert job["lease_token"] is None
    assert job["lease_expires_at"] is None
    assert [event["status"] for event in store.get_events(pending["job_id"])] == ["PENDING", "RUNNING", "FAILED"]


def test_claim_pending_job_requeues_expired_lease_before_claiming_next_job(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    first = store.create_job(pid=1001, duration_seconds=10, sample_frequency=99)
    second = store.create_job(pid=1002, duration_seconds=10, sample_frequency=99)
    first_claimed = store.claim_pending_job(agent_id="agent-1", lease_seconds=60)["job"]
    first_claimed["lease_expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    store._write_json_atomic(tmp_path / "jobs" / first["job_id"] / "job.json", first_claimed)

    claim = store.claim_pending_job(agent_id="agent-2", lease_seconds=60)

    assert claim["job"]["job_id"] == first["job_id"]
    assert claim["job"]["claimed_by"] == "agent-2"
    assert claim["job"]["claim_attempts"] == 2
    assert claim["skipped"][0]["reason"] == "job lease expired before completion"
    assert store.get_job(second["job_id"])["status"] == "PENDING"


def test_stale_lease_token_cannot_finish_reclaimed_job(tmp_path: Path) -> None:
    store = ServerJobStore(str(tmp_path))
    pending = store.create_job(pid=1234, duration_seconds=10, sample_frequency=99)
    first_claim = store.claim_pending_job(agent_id="agent-1", lease_seconds=60)["job"]
    first_claim["lease_expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    store._write_json_atomic(tmp_path / "jobs" / pending["job_id"] / "job.json", first_claim)

    second_claim = store.claim_pending_job(agent_id="agent-2", lease_seconds=60)["job"]

    try:
        store.finish_claimed_job(
            agent_id="agent-1",
            job_id=pending["job_id"],
            status="DONE",
            lease_token=first_claim["lease_token"],
        )
    except InvalidJobTransition:
        pass
    else:
        raise AssertionError("old lease owner should not be allowed to finish a reclaimed job")

    done = store.finish_claimed_job(
        agent_id="agent-2",
        job_id=pending["job_id"],
        status="DONE",
        lease_token=second_claim["lease_token"],
    )
    assert done["status"] == "DONE"
