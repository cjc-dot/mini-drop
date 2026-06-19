from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


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
