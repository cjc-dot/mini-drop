from __future__ import annotations

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

    def run(self, spec: JobSpec) -> JobResult:
        output_dir = self.runtime_dir / "profiles" / spec.job_id
        self.store.init_job(spec)

        try:
            self.store.transition(spec, "RUNNING", "collector started")
            summary = self.collector.collect(
                pid=spec.pid,
                duration_seconds=spec.duration_seconds,
                sample_frequency=spec.sample_frequency,
                output_dir=str(output_dir),
            )
            self.store.transition(spec, "UPLOADING", "local artifacts registered", artifacts=summary.artifacts)
            self.store.transition(spec, "DONE", "job completed successfully", artifacts=summary.artifacts)
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
