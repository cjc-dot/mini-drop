from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

from .job import JobEvent, JobSpec


class JobStore:
    def __init__(self, runtime_dir: str) -> None:
        self.runtime_dir = Path(runtime_dir).expanduser().resolve()
        self.jobs_dir = self.runtime_dir / "jobs"

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

    def init_job(self, spec: JobSpec) -> None:
        self.job_dir(spec.job_id).mkdir(parents=True, exist_ok=True)
        self.write_job(spec=spec, status="PENDING", reason="job accepted by local agent")
        self.append_event(JobEvent.create(spec.job_id, "PENDING", "job accepted by local agent"))

    def transition(self, spec: JobSpec, status: str, reason: str, artifacts: dict[str, str] | None = None) -> None:
        self.write_job(spec=spec, status=status, reason=reason, artifacts=artifacts or {})
        self.append_event(JobEvent.create(spec.job_id, status, reason))

    def fail(self, spec: JobSpec, reason: str, error_message: str) -> None:
        self.write_job(spec=spec, status="FAILED", reason=reason, error_message=error_message)
        self.append_event(JobEvent.create(spec.job_id, "FAILED", reason))

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
