from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
import json
import os
from datetime import datetime, timezone
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
    "summary": "summary.json",
}

MAX_ARTIFACT_BYTES = 20 * 1024 * 1024


class ServerJobStore:
    def __init__(self, runtime_dir: str) -> None:
        self.runtime_dir = Path(runtime_dir).expanduser().resolve()
        self.jobs_dir = self.runtime_dir / "jobs"

    def create_job(
        self,
        pid: int,
        duration_seconds: int,
        sample_frequency: int,
        collector: str = "perf",
        target: dict | None = None,
    ) -> dict:
        job_id = self._new_job_id()
        created_at = self._now()
        job = {
            "job_id": job_id,
            "status": "PENDING",
            "reason": "job created by api server",
            "spec": {
                "job_id": job_id,
                "pid": pid,
                "duration_seconds": duration_seconds,
                "sample_frequency": sample_frequency,
                "collector": collector,
                "target": target or {},
            },
            "artifacts": {},
            "error_message": None,
            "created_at": created_at,
            "updated_at": created_at,
        }
        self._job_dir(job_id).mkdir(parents=True, exist_ok=True)
        self._write_job(job)
        self._append_event(job_id, "PENDING", "job created by api server")
        return job

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
    ) -> dict:
        skipped: list[dict] = []
        if not self.jobs_dir.exists():
            return {"job": None, "skipped": skipped}

        for job_id in self._pending_job_ids_oldest_first():
            with self._job_lock(job_id):
                job = self.get_job(job_id)
                if job is None or job.get("status") != "PENDING":
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
                    extra={"claimed_by": agent_id, "claimed_at": self._now()},
                )
                return {"job": claimed, "skipped": skipped}
        return {"job": None, "skipped": skipped}

    def finish_claimed_job(
        self,
        agent_id: str,
        job_id: str,
        status: str,
        artifacts: dict[str, str] | None = None,
        error_message: str | None = None,
        reason: str | None = None,
    ) -> dict:
        if status not in {"DONE", "FAILED"}:
            raise ValueError(f"unsupported finish status: {status}")

        with self._job_lock(job_id):
            job = self.get_job(job_id)
            if job is None:
                raise FileNotFoundError(f"job not found: {job_id}")

            claimed_by = job.get("claimed_by")
            if claimed_by is not None and claimed_by != agent_id:
                raise InvalidJobTransition(f"job {job_id} was claimed by {claimed_by}, not {agent_id}")

            if status == "FAILED":
                return self._transition_job_locked(
                    job=job,
                    status="FAILED",
                    reason=reason or "collector failed",
                    artifacts=artifacts,
                    error_message=error_message,
                    expected_status="RUNNING",
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
            )

    def upload_artifacts(
        self,
        agent_id: str,
        job_id: str,
        artifact_payloads: dict[str, str],
    ) -> dict:
        if not artifact_payloads:
            raise ArtifactUploadError("no artifacts provided")

        with self._job_lock(job_id):
            job = self.get_job(job_id)
            if job is None:
                raise FileNotFoundError(f"job not found: {job_id}")

            claimed_by = job.get("claimed_by")
            if claimed_by is not None and claimed_by != agent_id:
                raise InvalidJobTransition(f"job {job_id} was claimed by {claimed_by}, not {agent_id}")

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

    def _job_dir(self, job_id: str) -> Path:
        return self.jobs_dir / job_id

    def _job_file(self, job_id: str) -> Path:
        return self._job_dir(job_id) / "job.json"

    def _events_file(self, job_id: str) -> Path:
        return self._job_dir(job_id) / "events.jsonl"


    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _new_job_id() -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"job-{stamp}-{uuid4().hex[:6]}"

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
