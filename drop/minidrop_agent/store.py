from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from typing import Callable
from uuid import uuid4

from .job import JobEvent, JobSpec

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback for local editing.
    fcntl = None


class InvalidJobTransition(RuntimeError):
    pass


class JobStore:
    def __init__(self, runtime_dir: str, pid_exists: Callable[[int], bool] | None = None) -> None:
        self.runtime_dir = Path(runtime_dir).expanduser().resolve()
        self.jobs_dir = self.runtime_dir / "jobs"
        self.pid_exists = pid_exists or self._pid_exists

    def job_dir(self, job_id: str) -> Path:
        return self.jobs_dir / job_id

    def job_file(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "job.json"

    def events_file(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "events.jsonl"

    def read_job(self, job_id: str) -> dict | None:
        job_file = self.job_file(job_id)
        if not job_file.exists():
            return None
        return json.loads(job_file.read_text(encoding="utf-8"))

    def list_pending_specs(self, limit: int | None = None) -> list[JobSpec]:
        if not self.jobs_dir.exists():
            return []

        specs: list[JobSpec] = []
        for job_file in sorted(self.jobs_dir.glob("*/job.json")):
            job = json.loads(job_file.read_text(encoding="utf-8"))
            if job.get("status") != "PENDING":
                continue
            spec = job["spec"]
            specs.append(
                JobSpec(
                    job_id=spec["job_id"],
                    pid=int(spec["pid"]),
                    duration_seconds=int(spec["duration_seconds"]),
                    sample_frequency=int(spec["sample_frequency"]),
                    collector=spec.get("collector", "perf"),
                )
            )
            if limit is not None and len(specs) >= limit:
                break
        return specs

    def get_pending_spec(self, job_id: str) -> JobSpec | None:
        job = self.read_job(job_id)
        if job is None or job.get("status") != "PENDING":
            return None
        return self._spec_from_job(job)

    def claim_pending_spec(
        self,
        job_id: str | None = None,
        *,
        validate_pid: bool = False,
        max_pending_age_seconds: int | None = None,
        on_skip: Callable[[str, str, str | None], None] | None = None,
    ) -> JobSpec | None:
        if job_id is not None:
            return self._claim_one(
                job_id,
                validate_pid=validate_pid,
                max_pending_age_seconds=max_pending_age_seconds,
                on_skip=on_skip,
            )

        if not self.jobs_dir.exists():
            return None

        for job_file in sorted(self.jobs_dir.glob("*/job.json")):
            claimed = self._claim_one(
                job_file.parent.name,
                validate_pid=validate_pid,
                max_pending_age_seconds=max_pending_age_seconds,
                on_skip=on_skip,
            )
            if claimed is not None:
                return claimed
        return None

    def init_job(self, spec: JobSpec) -> None:
        self.job_dir(spec.job_id).mkdir(parents=True, exist_ok=True)
        self.write_job(spec=spec, status="PENDING", reason="job accepted by local agent")
        self.append_event(JobEvent.create(spec.job_id, "PENDING", "job accepted by local agent"))

    def transition(
        self,
        spec: JobSpec,
        status: str,
        reason: str,
        artifacts: dict[str, str] | None = None,
        expected_status: str | tuple[str, ...] | None = None,
    ) -> None:
        self.transition_job(
            spec.job_id,
            status,
            reason,
            artifacts=artifacts,
            expected_status=expected_status,
        )

    def fail(self, spec: JobSpec, reason: str, error_message: str) -> None:
        self.transition_job(
            spec.job_id,
            "FAILED",
            reason,
            error_message=error_message,
            expected_status=("PENDING", "RUNNING", "UPLOADING"),
        )

    def transition_job(
        self,
        job_id: str,
        status: str,
        reason: str,
        artifacts: dict[str, str] | None = None,
        error_message: str | None = None,
        expected_status: str | tuple[str, ...] | None = None,
    ) -> dict:
        with self._job_lock(job_id):
            job = self.read_job(job_id)
            if job is None:
                raise FileNotFoundError(f"job not found: {job_id}")
            return self._transition_job_locked(
                job=job,
                status=status,
                reason=reason,
                artifacts=artifacts,
                error_message=error_message,
                expected_status=expected_status,
            )

    def write_job(
        self,
        spec: JobSpec,
        status: str,
        reason: str,
        artifacts: dict[str, str] | None = None,
        error_message: str | None = None,
    ) -> None:
        existing = self.read_job(spec.job_id) or {}
        now = JobEvent.create(spec.job_id, status, reason).created_at
        payload = {
            "job_id": spec.job_id,
            "status": status,
            "reason": reason,
            "spec": spec.to_dict(),
            "artifacts": artifacts or {},
            "error_message": error_message,
            "created_at": existing.get("created_at") or now,
            "updated_at": now,
        }
        self._write_json_atomic(self.job_file(spec.job_id), payload)

    def append_event(self, event: JobEvent) -> None:
        with self.events_file(event.job_id).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event.to_dict()) + "\n")

    def _claim_one(
        self,
        job_id: str,
        *,
        validate_pid: bool = False,
        max_pending_age_seconds: int | None = None,
        on_skip: Callable[[str, str, str | None], None] | None = None,
    ) -> JobSpec | None:
        skip_notice: tuple[str, str, str | None] | None = None
        with self._job_lock(job_id):
            job = self.read_job(job_id)
            if job is None or job.get("status") != "PENDING":
                return None

            spec = self._spec_from_job(job)
            if self._is_pending_expired(job, max_pending_age_seconds):
                reason = "pending job expired before claim"
                error_message = f"job stayed PENDING for more than {max_pending_age_seconds} seconds"
                self._transition_job_locked(
                    job=job,
                    status="FAILED",
                    reason=reason,
                    error_message=error_message,
                    expected_status="PENDING",
                )
                skip_notice = (job_id, reason, error_message)
            elif validate_pid and not self.pid_exists(spec.pid):
                reason = "target process not found before claim"
                error_message = f"pid {spec.pid} does not exist"
                self._transition_job_locked(
                    job=job,
                    status="FAILED",
                    reason=reason,
                    error_message=error_message,
                    expected_status="PENDING",
                )
                skip_notice = (job_id, reason, error_message)
            if skip_notice is None:
                self._transition_job_locked(
                    job=job,
                    status="RUNNING",
                    reason="job claimed by local agent",
                    expected_status="PENDING",
                )
                return spec
        if skip_notice is not None and on_skip is not None:
            on_skip(*skip_notice)
        return None

    def _transition_job_locked(
        self,
        job: dict,
        status: str,
        reason: str,
        artifacts: dict[str, str] | None = None,
        error_message: str | None = None,
        expected_status: str | tuple[str, ...] | None = None,
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

        spec = self._spec_from_job(job)
        event = JobEvent.create(job_id, status, reason)
        payload = {
            "job_id": job_id,
            "status": status,
            "reason": reason,
            "spec": spec.to_dict(),
            "artifacts": artifacts if artifacts is not None else job.get("artifacts", {}),
            "error_message": error_message,
            "created_at": job.get("created_at") or event.created_at,
            "updated_at": event.created_at,
        }
        self._write_json_atomic(self.job_file(job_id), payload)
        self.append_event(event)
        return payload

    @contextmanager
    def _job_lock(self, job_id: str):
        lock_file = self.job_dir(job_id) / "job.lock"
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
    def _spec_from_job(job: dict) -> JobSpec:
        spec = job["spec"]
        return JobSpec(
            job_id=spec["job_id"],
            pid=int(spec["pid"]),
            duration_seconds=int(spec["duration_seconds"]),
            sample_frequency=int(spec["sample_frequency"]),
            collector=spec.get("collector", "perf"),
        )

    @staticmethod
    def _is_pending_expired(job: dict, max_pending_age_seconds: int | None) -> bool:
        if max_pending_age_seconds is None:
            return False
        created_at = job.get("created_at")
        if not created_at:
            return False
        try:
            created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
        except ValueError:
            return False
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_seconds = (datetime.now(timezone.utc) - created).total_seconds()
        return age_seconds > max_pending_age_seconds

    @staticmethod
    def _pid_exists(pid: int) -> bool:
        if pid <= 0:
            return False
        proc_path = Path("/proc") / str(pid)
        if Path("/proc").exists():
            return proc_path.exists()
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

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
