from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone


TERMINAL_STATUSES = {"DONE", "FAILED"}


@dataclass(frozen=True)
class JobSpec:
    job_id: str
    pid: int
    duration_seconds: int
    sample_frequency: int
    collector: str = "perf"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class JobEvent:
    job_id: str
    status: str
    reason: str
    created_at: str

    @classmethod
    def create(cls, job_id: str, status: str, reason: str) -> "JobEvent":
        return cls(
            job_id=job_id,
            status=status,
            reason=reason,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class JobResult:
    job_id: str
    status: str
    job_file: str
    output_dir: str
    artifacts: dict[str, str]
    error_message: str | None = None
