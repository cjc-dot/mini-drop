from __future__ import annotations

from pathlib import Path

from minidrop_apiserver.store import ServerJobStore


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
