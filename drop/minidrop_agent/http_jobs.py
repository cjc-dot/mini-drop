from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from minidrop_analysis.perf import PerfCollector, ProfileSummary

from .job import JobResult, JobSpec
from .process import ProcessInspector


class Collector(Protocol):
    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        ...


class ServerJobClient:
    def __init__(self, server_url: str) -> None:
        self.server_url = server_url.rstrip("/")

    def claim(self, agent_id: str, max_pending_age_seconds: int | None = 300) -> dict:
        return self._post_json(
            f"/api/agents/{quote(agent_id, safe='')}/jobs/claim",
            {"max_pending_age_seconds": max_pending_age_seconds},
        )

    def finish(
        self,
        agent_id: str,
        job_id: str,
        status: str,
        artifacts: dict[str, str] | None = None,
        error_message: str | None = None,
        reason: str | None = None,
    ) -> dict:
        return self._post_json(
            f"/api/agents/{quote(agent_id, safe='')}/jobs/{quote(job_id, safe='')}/finish",
            {
                "status": status,
                "artifacts": artifacts or {},
                "error_message": error_message,
                "reason": reason,
            },
        )

    def _post_json(self, path: str, payload: dict) -> dict:
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self.server_url}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=10) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"server rejected job request: HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"server job request failed: {exc.reason}") from exc


class HttpJobRunner:
    def __init__(
        self,
        runtime_dir: str = "~/mini-drop-runtime",
        server_url: str = "http://127.0.0.1:8000",
        agent_id: str = "local-agent",
        collector: Collector | None = None,
        client: ServerJobClient | None = None,
        process_inspector: ProcessInspector | None = None,
    ) -> None:
        self.runtime_dir = Path(runtime_dir).expanduser().resolve()
        self.agent_id = agent_id
        self.collector = collector or PerfCollector()
        self.client = client or ServerJobClient(server_url)
        self.process_inspector = process_inspector or ProcessInspector()

    def run_pending_once(
        self,
        job_id: str | None = None,
        *,
        validate_pid: bool = False,
        max_pending_age_seconds: int | None = None,
        on_skip=None,
    ) -> JobResult | None:
        if job_id is not None:
            raise RuntimeError("HTTP job runner does not support claiming a specific job yet")

        claim = self.client.claim(
            agent_id=self.agent_id,
            max_pending_age_seconds=max_pending_age_seconds,
        )
        for skipped in claim.get("skipped", []):
            if on_skip is not None:
                on_skip(skipped["job_id"], skipped["reason"], skipped.get("error_message"))

        job = claim.get("job")
        if job is None:
            return None

        spec = self._spec_from_job(job)
        output_dir = self.runtime_dir / "profiles" / spec.job_id
        job_file = self.runtime_dir / "jobs" / spec.job_id / "job.json"

        if validate_pid:
            validation_error = self._validate_target(spec)
            if validation_error is not None:
                reason, error_message = validation_error
                finished = self.client.finish(
                    agent_id=self.agent_id,
                    job_id=spec.job_id,
                    status="FAILED",
                    reason=reason,
                    error_message=error_message,
                )
                return JobResult(
                    job_id=spec.job_id,
                    status=finished.get("status", "FAILED"),
                    job_file=str(job_file),
                    output_dir=str(output_dir),
                    artifacts={},
                    error_message=error_message,
                )

        try:
            summary = self.collector.collect(
                pid=spec.pid,
                duration_seconds=spec.duration_seconds,
                sample_frequency=spec.sample_frequency,
                output_dir=str(output_dir),
            )
            finished = self.client.finish(
                agent_id=self.agent_id,
                job_id=spec.job_id,
                status="DONE",
                artifacts=summary.artifacts,
                reason="job completed successfully",
            )
            return JobResult(
                job_id=spec.job_id,
                status=finished.get("status", "DONE"),
                job_file=str(job_file),
                output_dir=str(output_dir),
                artifacts=summary.artifacts,
            )
        except Exception as exc:
            error_message = str(exc)
            finished = self.client.finish(
                agent_id=self.agent_id,
                job_id=spec.job_id,
                status="FAILED",
                reason="collector failed",
                error_message=error_message,
            )
            return JobResult(
                job_id=spec.job_id,
                status=finished.get("status", "FAILED"),
                job_file=str(job_file),
                output_dir=str(output_dir),
                artifacts={},
                error_message=error_message,
            )

    @staticmethod
    def _spec_from_job(job: dict) -> JobSpec:
        spec = job["spec"]
        return JobSpec(
            job_id=spec["job_id"],
            pid=int(spec["pid"]),
            duration_seconds=int(spec["duration_seconds"]),
            sample_frequency=int(spec["sample_frequency"]),
            collector=spec.get("collector", "perf"),
            target=spec.get("target") or None,
        )

    def _validate_target(self, spec: JobSpec) -> tuple[str, str] | None:
        current = self.process_inspector.inspect(spec.pid)
        if current is None:
            return "target process not found before collect", f"pid {spec.pid} does not exist"

        target = spec.target or {}
        expected_starttime = target.get("starttime")
        current_starttime = current.get("starttime")
        if expected_starttime is None or current_starttime is None:
            return None

        try:
            expected = int(expected_starttime)
            actual = int(current_starttime)
        except (TypeError, ValueError):
            return None

        if actual != expected:
            return "target process changed before collect", f"pid {spec.pid} starttime changed from {expected} to {actual}"
        return None
