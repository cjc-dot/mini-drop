from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import time
from uuid import uuid4

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback for local editing.
    fcntl = None


class InvalidJobTransition(RuntimeError):
    pass


class ArtifactUploadError(RuntimeError):
    pass


ARTIFACT_FILENAMES = {
    "perf_data": "perf.data",
    "perf_script": "out.perf",
    "folded_stack": "out.folded",
    "flamegraph": "flamegraph.svg",
    "hotspots": "hotspots.json",
    "suggestions": "suggestions.json",
    "suggestions_markdown": "suggestions.md",
    "ebpf_raw": "ebpf_syscalls.raw",
    "ebpf_syscalls": "ebpf_syscalls.json",
    "ebpf_io_latency_raw": "ebpf_io_latency.raw",
    "ebpf_io_latency": "ebpf_io_latency.json",
    "pyspy_speedscope": "py_spy.speedscope.json",
    "pyspy_profile": "py_spy_profile.json",
    "summary": "summary.json",
}

MAX_ARTIFACT_BYTES = 20 * 1024 * 1024
DEFAULT_LEASE_SECONDS = 60
DEFAULT_MAX_CLAIM_ATTEMPTS = 3


class ServerJobStore:
    def __init__(self, runtime_dir: str) -> None:
        self.runtime_dir = Path(runtime_dir).expanduser().resolve()
        self.jobs_dir = self.runtime_dir / "jobs"
        self.continuous_dir = self.runtime_dir / "continuous_profiles"

    def create_job(
        self,
        pid: int,
        duration_seconds: int,
        sample_frequency: int,
        collector: str = "perf",
        target: dict | None = None,
        extra_spec: dict | None = None,
    ) -> dict:
        job_id = self._new_job_id()
        created_at = self._now()
        spec = {
            "job_id": job_id,
            "pid": pid,
            "duration_seconds": duration_seconds,
            "sample_frequency": sample_frequency,
            "collector": collector,
            "target": target or {},
        }
        if extra_spec:
            spec.update(extra_spec)
        job = {
            "job_id": job_id,
            "status": "PENDING",
            "reason": "job created by api server",
            "spec": spec,
            "artifacts": {},
            "error_message": None,
            "created_at": created_at,
            "updated_at": created_at,
        }
        self._job_dir(job_id).mkdir(parents=True, exist_ok=True)
        self._write_job(job)
        self._append_event(job_id, "PENDING", "job created by api server")
        return job

    def create_continuous_profile(
        self,
        pid: int,
        slice_duration_seconds: int,
        sample_frequency: int,
        collector: str,
        slice_count: int,
        interval_seconds: int,
        target: dict | None = None,
    ) -> dict:
        session_id = self._new_continuous_session_id()
        created_at = self._now()
        base_time = datetime.now(timezone.utc)
        jobs: list[dict] = []

        for index in range(slice_count):
            scheduled_at = (
                base_time + timedelta(seconds=index * (slice_duration_seconds + interval_seconds))
            ).isoformat()
            job = self.create_job(
                pid=pid,
                duration_seconds=slice_duration_seconds,
                sample_frequency=sample_frequency,
                collector=collector,
                target=target,
                extra_spec={
                    "scheduled_at": scheduled_at,
                    "continuous": {
                        "session_id": session_id,
                        "slice_index": index + 1,
                        "slice_count": slice_count,
                        "interval_seconds": interval_seconds,
                    },
                },
            )
            jobs.append(
                {
                    "job_id": job["job_id"],
                    "slice_index": index + 1,
                    "scheduled_at": scheduled_at,
                }
            )

        session = {
            "session_id": session_id,
            "status": "SCHEDULED",
            "reason": "continuous profiling session created",
            "pid": pid,
            "collector": collector,
            "slice_duration_seconds": slice_duration_seconds,
            "sample_frequency": sample_frequency,
            "slice_count": slice_count,
            "interval_seconds": interval_seconds,
            "target": target or {},
            "jobs": jobs,
            "created_at": created_at,
            "updated_at": self._now(),
        }
        self._write_continuous_session(session)
        return self._hydrate_continuous_session(session)

    def list_continuous_profiles(self) -> list[dict]:
        if not self.continuous_dir.exists():
            return []

        sessions = []
        for session_file in self.continuous_dir.glob("*/session.json"):
            sessions.append(
                self._hydrate_continuous_session(
                    json.loads(session_file.read_text(encoding="utf-8"))
                )
            )
        return sorted(sessions, key=lambda session: session.get("created_at", ""), reverse=True)

    def get_continuous_profile(self, session_id: str) -> dict | None:
        session_file = self._continuous_session_file(session_id)
        if not session_file.exists():
            return None
        return self._hydrate_continuous_session(json.loads(session_file.read_text(encoding="utf-8")))

    def list_jobs(self) -> list[dict]:
        if not self.jobs_dir.exists():
            return []

        jobs = []
        for job_file in self.jobs_dir.glob("*/job.json"):
            jobs.append(json.loads(job_file.read_text(encoding="utf-8")))
        return sorted(jobs, key=lambda job: job.get("created_at", ""), reverse=True)

    def get_job(self, job_id: str) -> dict | None:
        job_file = self._job_file(job_id)
        if not job_file.exists():
            return None
        return json.loads(job_file.read_text(encoding="utf-8"))

    def get_events(self, job_id: str) -> list[dict]:
        events_file = self._events_file(job_id)
        if not events_file.exists():
            return []
        return [json.loads(line) for line in events_file.read_text(encoding="utf-8").splitlines() if line]

    def claim_pending_job(
        self,
        agent_id: str,
        max_pending_age_seconds: int | None = 300,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
        max_claim_attempts: int = DEFAULT_MAX_CLAIM_ATTEMPTS,
    ) -> dict:
        skipped: list[dict] = []
        if not self.jobs_dir.exists():
            return {"job": None, "skipped": skipped}

        skipped.extend(self.requeue_expired_leases(max_claim_attempts=max_claim_attempts))

        for job_id in self._pending_job_ids_oldest_first():
            with self._job_lock(job_id):
                job = self.get_job(job_id)
                if job is None or job.get("status") != "PENDING":
                    continue

                if self._is_scheduled_for_future(job):
                    continue

                if self._has_exhausted_claim_attempts(job, max_claim_attempts):
                    reason = "job claim attempts exhausted before claim"
                    error_message = self._claim_attempts_exhausted_message(job, max_claim_attempts)
                    failed = self._transition_job_locked(
                        job=job,
                        status="FAILED",
                        reason=reason,
                        error_message=error_message,
                        expected_status="PENDING",
                    )
                    skipped.append(
                        {
                            "job_id": job_id,
                            "reason": reason,
                            "error_message": error_message,
                            "status": failed["status"],
                        }
                    )
                    continue

                if self._is_pending_expired(job, max_pending_age_seconds):
                    reason = "pending job expired before claim"
                    error_message = f"job stayed PENDING for more than {max_pending_age_seconds} seconds"
                    failed = self._transition_job_locked(
                        job=job,
                        status="FAILED",
                        reason=reason,
                        error_message=error_message,
                        expected_status="PENDING",
                    )
                    skipped.append(
                        {
                            "job_id": job_id,
                            "reason": reason,
                            "error_message": error_message,
                            "status": failed["status"],
                        }
                    )
                    continue

                claimed = self._transition_job_locked(
                    job=job,
                    status="RUNNING",
                    reason=f"job claimed by {agent_id}",
                    expected_status="PENDING",
                    extra={
                        "claimed_by": agent_id,
                        "claimed_at": self._now(),
                        "claim_attempts": self._claim_attempts(job) + 1,
                        "lease_token": uuid4().hex,
                        "lease_expires_at": self._lease_deadline(lease_seconds),
                    },
                )
                return {"job": claimed, "skipped": skipped}
        return {"job": None, "skipped": skipped}

    def renew_job_lease(
        self,
        agent_id: str,
        job_id: str,
        lease_token: str,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> dict:
        with self._job_lock(job_id):
            job = self.get_job(job_id)
            if job is None:
                raise FileNotFoundError(f"job not found: {job_id}")

            self._validate_claim_owner(job, agent_id, lease_token)
            if job.get("status") not in {"RUNNING", "UPLOADING"}:
                raise InvalidJobTransition(f"cannot renew lease for {job_id} from {job.get('status')}")

            renewed = dict(job)
            renewed["lease_expires_at"] = self._lease_deadline(lease_seconds)
            renewed["updated_at"] = self._now()
            self._write_json_atomic(self._job_file(job_id), renewed)
            return renewed

    def requeue_expired_leases(self, max_claim_attempts: int = DEFAULT_MAX_CLAIM_ATTEMPTS) -> list[dict]:
        skipped: list[dict] = []
        if not self.jobs_dir.exists():
            return skipped

        for job_file in self.jobs_dir.glob("*/job.json"):
            job_id = job_file.parent.name
            with self._job_lock(job_id):
                job = self.get_job(job_id)
                if job is None or job.get("status") not in {"RUNNING", "UPLOADING"}:
                    continue
                lease_expires_at = job.get("lease_expires_at")
                if not lease_expires_at or not self._is_time_expired(lease_expires_at):
                    continue

                if job.get("status") == "UPLOADING":
                    reason = "job lease expired during artifact upload"
                    error_message = f"lease expired at {lease_expires_at}"
                    failed = self._transition_job_locked(
                        job=job,
                        status="FAILED",
                        reason=reason,
                        artifacts={},
                        error_message=error_message,
                        expected_status="UPLOADING",
                        extra={
                            "lease_token": None,
                            "lease_expires_at": None,
                            "previous_claimed_by": job.get("claimed_by"),
                        },
                    )
                    skipped.append(
                        {
                            "job_id": job_id,
                            "reason": reason,
                            "error_message": error_message,
                            "status": failed["status"],
                        }
                    )
                    continue

                if self._has_exhausted_claim_attempts(job, max_claim_attempts):
                    reason = "job claim attempts exhausted after lease expiration"
                    error_message = self._claim_attempts_exhausted_message(job, max_claim_attempts)
                    failed = self._transition_job_locked(
                        job=job,
                        status="FAILED",
                        reason=reason,
                        artifacts=job.get("artifacts", {}),
                        error_message=error_message,
                        expected_status=("RUNNING", "UPLOADING"),
                        extra={
                            "lease_token": None,
                            "lease_expires_at": None,
                            "previous_claimed_by": job.get("claimed_by"),
                        },
                    )
                    skipped.append(
                        {
                            "job_id": job_id,
                            "reason": reason,
                            "error_message": error_message,
                            "status": failed["status"],
                        }
                    )
                    continue

                reason = "job lease expired before completion"
                requeued = self._transition_job_locked(
                    job=job,
                    status="PENDING",
                    reason=reason,
                    artifacts={},
                    expected_status=("RUNNING", "UPLOADING"),
                    extra={
                        "claimed_by": None,
                        "claimed_at": None,
                        "lease_token": None,
                        "lease_expires_at": None,
                        "previous_claimed_by": job.get("claimed_by"),
                    },
                )
                skipped.append(
                    {
                        "job_id": job_id,
                        "reason": reason,
                        "error_message": f"lease expired at {lease_expires_at}",
                        "status": requeued["status"],
                    }
                )
        return skipped

    def finish_claimed_job(
        self,
        agent_id: str,
        job_id: str,
        status: str,
        artifacts: dict[str, str] | None = None,
        error_message: str | None = None,
        reason: str | None = None,
        lease_token: str | None = None,
    ) -> dict:
        if status not in {"DONE", "FAILED"}:
            raise ValueError(f"unsupported finish status: {status}")

        with self._job_lock(job_id):
            job = self.get_job(job_id)
            if job is None:
                raise FileNotFoundError(f"job not found: {job_id}")

            self._validate_claim_owner(job, agent_id, lease_token)

            if status == "FAILED":
                return self._transition_job_locked(
                    job=job,
                    status="FAILED",
                    reason=reason or "collector failed",
                    artifacts=artifacts,
                    error_message=error_message,
                    expected_status=("RUNNING", "UPLOADING"),
                    extra={"lease_token": None, "lease_expires_at": None},
                )

            if job.get("status") == "RUNNING":
                uploading = self._transition_job_locked(
                    job=job,
                    status="UPLOADING",
                    reason="artifacts reported by agent",
                    artifacts=artifacts,
                    expected_status="RUNNING",
                )
            elif job.get("status") == "UPLOADING":
                upload_artifacts = artifacts if artifacts is not None else job.get("artifacts", {})
                uploading = dict(job)
                uploading["artifacts"] = upload_artifacts
            else:
                raise InvalidJobTransition(
                    f"cannot finish {job_id} from {job.get('status')}; expected RUNNING or UPLOADING"
                )
            return self._transition_job_locked(
                job=uploading,
                status="DONE",
                reason=reason or "job completed successfully",
                artifacts=uploading.get("artifacts", {}),
                expected_status="UPLOADING",
                extra={"lease_token": None, "lease_expires_at": None},
            )

    def upload_artifacts(
        self,
        agent_id: str,
        job_id: str,
        artifact_payloads: dict[str, str],
        lease_token: str | None = None,
    ) -> dict:
        if not artifact_payloads:
            raise ArtifactUploadError("no artifacts provided")

        with self._job_lock(job_id):
            job = self.get_job(job_id)
            if job is None:
                raise FileNotFoundError(f"job not found: {job_id}")

            self._validate_claim_owner(job, agent_id, lease_token)

            current_status = job.get("status")
            if current_status not in {"RUNNING", "UPLOADING"}:
                raise InvalidJobTransition(f"cannot upload artifacts for {job_id} from {current_status}")

            saved_artifacts = dict(job.get("artifacts", {}))
            profile_dir = self.runtime_dir / "profiles" / job_id
            profile_dir.mkdir(parents=True, exist_ok=True)

            for name, encoded in artifact_payloads.items():
                if name not in ARTIFACT_FILENAMES:
                    raise ArtifactUploadError(f"unsupported artifact: {name}")
                try:
                    data = base64.b64decode(encoded.encode("ascii"), validate=True)
                except (UnicodeEncodeError, binascii.Error) as exc:
                    raise ArtifactUploadError(f"invalid base64 artifact: {name}") from exc
                if len(data) > MAX_ARTIFACT_BYTES:
                    raise ArtifactUploadError(f"artifact too large: {name}")

                path = profile_dir / ARTIFACT_FILENAMES[name]
                self._write_bytes_atomic(path, data)
                saved_artifacts[name] = str(path)

            return self._transition_job_locked(
                job=job,
                status="UPLOADING",
                reason="artifacts uploaded by agent",
                artifacts=saved_artifacts,
                expected_status=("RUNNING", "UPLOADING"),
            )

    def _write_job(self, job: dict) -> None:
        job["updated_at"] = self._now()
        self._write_json_atomic(self._job_file(job["job_id"]), job)

    def _append_event(self, job_id: str, status: str, reason: str) -> None:
        event = {
            "job_id": job_id,
            "status": status,
            "reason": reason,
            "created_at": self._now(),
        }
        with self._events_file(job_id).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event) + "\n")

    def _transition_job_locked(
        self,
        job: dict,
        status: str,
        reason: str,
        artifacts: dict[str, str] | None = None,
        error_message: str | None = None,
        expected_status: str | tuple[str, ...] | None = None,
        extra: dict | None = None,
    ) -> dict:
        job_id = str(job["job_id"])
        current_status = job.get("status")
        if expected_status is not None:
            expected = (expected_status,) if isinstance(expected_status, str) else expected_status
            if current_status not in expected:
                expected_text = ", ".join(expected)
                raise InvalidJobTransition(
                    f"cannot transition {job_id} from {current_status} to {status}; expected {expected_text}"
                )

        payload = dict(job)
        payload.update(
            {
                "status": status,
                "reason": reason,
                "artifacts": artifacts if artifacts is not None else job.get("artifacts", {}),
                "error_message": error_message,
                "updated_at": self._now(),
            }
        )
        if extra:
            payload.update(extra)
        self._write_json_atomic(self._job_file(job_id), payload)
        self._append_event(job_id, status, reason)
        return payload

    def _pending_job_ids_oldest_first(self) -> list[str]:
        pending_jobs: list[tuple[str, str]] = []
        for job_file in self.jobs_dir.glob("*/job.json"):
            try:
                job = json.loads(job_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if job.get("status") != "PENDING":
                continue
            pending_jobs.append((str(job.get("created_at", "")), job_file.parent.name))
        return [job_id for _, job_id in sorted(pending_jobs)]

    @staticmethod
    def _claim_attempts(job: dict) -> int:
        try:
            return int(job.get("claim_attempts", 0))
        except (TypeError, ValueError):
            return 0

    def _has_exhausted_claim_attempts(self, job: dict, max_claim_attempts: int) -> bool:
        return self._claim_attempts(job) >= max_claim_attempts

    def _claim_attempts_exhausted_message(self, job: dict, max_claim_attempts: int) -> str:
        return f"job was claimed {self._claim_attempts(job)} time(s); max allowed is {max_claim_attempts}"

    @staticmethod
    def _validate_claim_owner(job: dict, agent_id: str, lease_token: str | None) -> None:
        job_id = str(job["job_id"])
        claimed_by = job.get("claimed_by")
        if claimed_by != agent_id:
            raise InvalidJobTransition(f"job {job_id} was claimed by {claimed_by}, not {agent_id}")

        expected_token = job.get("lease_token")
        if not expected_token or lease_token != expected_token:
            raise InvalidJobTransition(f"job {job_id} lease token mismatch")

    @contextmanager
    def _job_lock(self, job_id: str):
        lock_file = self._job_dir(job_id) / "job.lock"
        lock_file.parent.mkdir(parents=True, exist_ok=True)

        if fcntl is not None:
            with lock_file.open("w", encoding="utf-8") as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            return

        while True:
            try:
                lock_fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                time.sleep(0.01)
        try:
            with os.fdopen(lock_fd, "w", encoding="utf-8") as stream:
                stream.write(str(os.getpid()))
            yield
        finally:
            if lock_file.exists():
                lock_file.unlink()

    @staticmethod
    def _is_pending_expired(job: dict, max_pending_age_seconds: int | None) -> bool:
        if max_pending_age_seconds is None:
            return False
        pending_since = job.get("spec", {}).get("scheduled_at") or job.get("created_at")
        if not pending_since:
            return False
        try:
            created = datetime.fromisoformat(str(pending_since).replace("Z", "+00:00"))
        except ValueError:
            return False
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_seconds = (datetime.now(timezone.utc) - created).total_seconds()
        return age_seconds > max_pending_age_seconds

    @staticmethod
    def _is_scheduled_for_future(job: dict) -> bool:
        scheduled_at = job.get("spec", {}).get("scheduled_at")
        if not scheduled_at:
            return False
        try:
            scheduled = datetime.fromisoformat(str(scheduled_at).replace("Z", "+00:00"))
        except ValueError:
            return False
        if scheduled.tzinfo is None:
            scheduled = scheduled.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < scheduled

    @staticmethod
    def _is_time_expired(value: str) -> bool:
        try:
            deadline = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return False
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > deadline

    @staticmethod
    def _lease_deadline(lease_seconds: int) -> str:
        return (datetime.now(timezone.utc) + timedelta(seconds=lease_seconds)).isoformat()

    def _job_dir(self, job_id: str) -> Path:
        return self.jobs_dir / job_id

    def _job_file(self, job_id: str) -> Path:
        return self._job_dir(job_id) / "job.json"

    def _events_file(self, job_id: str) -> Path:
        return self._job_dir(job_id) / "events.jsonl"

    def _continuous_session_dir(self, session_id: str) -> Path:
        return self.continuous_dir / session_id

    def _continuous_session_file(self, session_id: str) -> Path:
        return self._continuous_session_dir(session_id) / "session.json"

    def _write_continuous_session(self, session: dict) -> None:
        session["updated_at"] = self._now()
        self._write_json_atomic(self._continuous_session_file(session["session_id"]), session)

    def _hydrate_continuous_session(self, session: dict) -> dict:
        hydrated = dict(session)
        hydrated_jobs = []
        counts: dict[str, int] = {}

        for item in session.get("jobs", []):
            job_id = item.get("job_id")
            job = self.get_job(job_id) if job_id else None
            status = job.get("status", "MISSING") if job else "MISSING"
            counts[status] = counts.get(status, 0) + 1
            hydrated_jobs.append(
                {
                    **item,
                    "status": status,
                    "reason": job.get("reason") if job else "job metadata missing",
                    "artifacts": job.get("artifacts", {}) if job else {},
                    "created_at": job.get("created_at") if job else None,
                    "updated_at": job.get("updated_at") if job else None,
                }
            )

        if counts.get("FAILED"):
            status = "FAILED"
        elif counts.get("DONE") == len(hydrated_jobs) and hydrated_jobs:
            status = "DONE"
        elif counts.get("RUNNING") or counts.get("UPLOADING"):
            status = "RUNNING"
        elif counts.get("PENDING"):
            status = "SCHEDULED"
        else:
            status = "UNKNOWN"

        hydrated["status"] = status
        hydrated["status_counts"] = counts
        hydrated["jobs"] = hydrated_jobs
        return hydrated


    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _new_job_id() -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"job-{stamp}-{uuid4().hex[:6]}"

    @staticmethod
    def _new_continuous_session_id() -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"cont-{stamp}-{uuid4().hex[:6]}"

    @staticmethod
    def _write_json_atomic(path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            with temp_path.open("w", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, indent=2))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, path)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    @staticmethod
    def _write_bytes_atomic(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            with temp_path.open("wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, path)
        finally:
            if temp_path.exists():
                temp_path.unlink()
