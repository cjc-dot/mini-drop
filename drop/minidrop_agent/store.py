from __future__ import annotations

import json
from pathlib import Path

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
        payload = {
            "job_id": spec.job_id,
            "status": status,
            "reason": reason,
            "spec": spec.to_dict(),
            "artifacts": artifacts or {},
            "error_message": error_message,
        }
        self.job_file(spec.job_id).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def append_event(self, event: JobEvent) -> None:
        with self.events_file(event.job_id).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event.to_dict()) + "\n")
