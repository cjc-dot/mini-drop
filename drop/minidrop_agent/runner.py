from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from minidrop_analysis.perf import PerfCollector, ProfileSummary

from .job import JobResult, JobSpec
from .store import JobStore


class Collector(Protocol):
    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        ...


class LocalAgent:
    def __init__(self, runtime_dir: str = "~/mini-drop-runtime", collector: Collector | None = None) -> None:
        self.runtime_dir = Path(runtime_dir).expanduser().resolve()
        self.store = JobStore(str(self.runtime_dir))
        self.collector = collector or PerfCollector()

    def run(self, spec: JobSpec, initialize: bool = True, mark_running: bool = True) -> JobResult:
        output_dir = self.runtime_dir / "profiles" / spec.job_id
        if initialize:
            self.store.init_job(spec)

        try:
            if mark_running:
                self.store.transition(spec, "RUNNING", "collector started", expected_status="PENDING")
            summary = self.collector.collect(
                pid=spec.pid,
                duration_seconds=spec.duration_seconds,
                sample_frequency=spec.sample_frequency,
                output_dir=str(output_dir),
            )
            self.store.transition(
                spec,
                "UPLOADING",
                "local artifacts registered",
                artifacts=summary.artifacts,
                expected_status="RUNNING",
            )
            self.store.transition(
                spec,
                "DONE",
                "job completed successfully",
                artifacts=summary.artifacts,
                expected_status="UPLOADING",
            )
            return JobResult(
                job_id=spec.job_id,
                status="DONE",
                job_file=str(self.store.job_file(spec.job_id)),
                output_dir=str(output_dir),
                artifacts=summary.artifacts,
            )
        except Exception as exc:
            self.store.fail(spec, "collector failed", str(exc))
            return JobResult(
                job_id=spec.job_id,
                status="FAILED",
                job_file=str(self.store.job_file(spec.job_id)),
                output_dir=str(output_dir),
                artifacts={},
                error_message=str(exc),
            )

    def run_pending_once(
        self,
        job_id: str | None = None,
        *,
        validate_pid: bool = False,
        max_pending_age_seconds: int | None = None,
        max_claim_attempts: int = 3,
        on_skip: Callable[[str, str, str | None], None] | None = None,
    ) -> JobResult | None:
        spec = self.store.claim_pending_spec(
            job_id=job_id,
            validate_pid=validate_pid,
            max_pending_age_seconds=max_pending_age_seconds,
            on_skip=on_skip,
        )
        if spec is None:
            return None
        return self.run(spec, initialize=False, mark_running=False)
