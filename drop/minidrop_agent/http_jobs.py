from __future__ import annotations

import base64
import json
from pathlib import Path
import threading
import time
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from minidrop_analysis.perf import PerfCollector, ProfileSummary

from .job import JobResult, JobSpec
from .process import ProcessInspector


UPLOADABLE_ARTIFACTS = {
    "perf_script",
    "folded_stack",
    "flamegraph",
    "hotspots",
    "suggestions",
    "suggestions_markdown",
    "summary",
}


class Collector(Protocol):
    def collect(self, pid: int, duration_seconds: int, sample_frequency: int, output_dir: str) -> ProfileSummary:
        ...


DEFAULT_LEASE_SECONDS = 60


class ServerJobClient:
    def __init__(self, server_url: str) -> None:
        self.server_url = server_url.rstrip("/")

    def claim(
        self,
        agent_id: str,
        max_pending_age_seconds: int | None = 300,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> dict:
        return self._post_json(
            f"/api/agents/{quote(agent_id, safe='')}/jobs/claim",
            {
                "max_pending_age_seconds": max_pending_age_seconds,
                "lease_seconds": lease_seconds,
            },
        )

    def renew_lease(
        self,
        agent_id: str,
        job_id: str,
        lease_token: str,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> dict:
        return self._post_json(
            f"/api/agents/{quote(agent_id, safe='')}/jobs/{quote(job_id, safe='')}/lease",
            {
                "lease_token": lease_token,
                "lease_seconds": lease_seconds,
            },
        )

    def finish(
        self,
        agent_id: str,
        job_id: str,
        status: str,
        lease_token: str | None = None,
        artifacts: dict[str, str] | None = None,
        error_message: str | None = None,
        reason: str | None = None,
    ) -> dict:
        payload = {
            "status": status,
            "lease_token": lease_token,
            "error_message": error_message,
            "reason": reason,
        }
        if artifacts is not None:
            payload["artifacts"] = artifacts
        return self._post_json(
            f"/api/agents/{quote(agent_id, safe='')}/jobs/{quote(job_id, safe='')}/finish",
            payload,
        )

    def upload_artifacts(self, agent_id: str, job_id: str, lease_token: str, artifacts: dict[str, str]) -> dict:
        return self._post_json(
            f"/api/agents/{quote(agent_id, safe='')}/jobs/{quote(job_id, safe='')}/artifacts",
            {
                "encoding": "base64",
                "lease_token": lease_token,
                "artifacts": self._encode_uploadable_artifacts(artifacts),
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

    @staticmethod
    def _encode_uploadable_artifacts(artifacts: dict[str, str]) -> dict[str, str]:
        payloads = {}
        for name, artifact_path in artifacts.items():
            if name not in UPLOADABLE_ARTIFACTS:
                continue
            path = Path(artifact_path).expanduser()
            if not path.exists() or not path.is_file():
                continue
            try:
                payloads[name] = base64.b64encode(path.read_bytes()).decode("ascii")
            except OSError:
                continue
        return payloads


class HttpJobRunner:
    def __init__(
        self,
        runtime_dir: str = "~/mini-drop-runtime",
        server_url: str = "http://127.0.0.1:8000",
        agent_id: str = "local-agent",
        collector: Collector | None = None,
        client: ServerJobClient | None = None,
        process_inspector: ProcessInspector | None = None,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> None:
        self.runtime_dir = Path(runtime_dir).expanduser().resolve()
        self.agent_id = agent_id
        self.collector = collector or PerfCollector()
        self.client = client or ServerJobClient(server_url)
        self.process_inspector = process_inspector or ProcessInspector()
        self.lease_seconds = lease_seconds

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
            lease_seconds=self.lease_seconds,
        )
        for skipped in claim.get("skipped", []):
            if on_skip is not None:
                on_skip(skipped["job_id"], skipped["reason"], skipped.get("error_message"))

        job = claim.get("job")
        if job is None:
            return None

        spec = self._spec_from_job(job)
        lease_token = str(job.get("lease_token") or "")
        if not lease_token:
            raise RuntimeError(f"claimed job {spec.job_id} did not include a lease token")
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
                    lease_token=lease_token,
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

        lease_renewer = LeaseRenewer(
            client=self.client,
            agent_id=self.agent_id,
            job_id=spec.job_id,
            lease_token=lease_token,
            lease_seconds=self.lease_seconds,
        )
        lease_renewer.start()
        try:
            try:
                summary = self.collector.collect(
                    pid=spec.pid,
                    duration_seconds=spec.duration_seconds,
                    sample_frequency=spec.sample_frequency,
                    output_dir=str(output_dir),
                )
            except Exception as exc:
                return self._finish_failed(spec, job_file, output_dir, lease_token, "collector failed", str(exc))

            try:
                uploaded = self.client.upload_artifacts(
                    agent_id=self.agent_id,
                    job_id=spec.job_id,
                    lease_token=lease_token,
                    artifacts=summary.artifacts,
                )
                server_artifacts = uploaded.get("artifacts", {})
            except Exception as exc:
                return self._finish_failed(spec, job_file, output_dir, lease_token, "artifact upload failed", str(exc))

            try:
                finished = self.client.finish(
                    agent_id=self.agent_id,
                    job_id=spec.job_id,
                    status="DONE",
                    lease_token=lease_token,
                    reason="job completed successfully",
                )
            except Exception as exc:
                return JobResult(
                    job_id=spec.job_id,
                    status="FAILED",
                    job_file=str(job_file),
                    output_dir=str(output_dir),
                    artifacts=server_artifacts,
                    error_message=str(exc),
                )

            return JobResult(
                job_id=spec.job_id,
                status=finished.get("status", "DONE"),
                job_file=str(job_file),
                output_dir=str(output_dir),
                artifacts=server_artifacts,
            )
        finally:
            lease_renewer.stop()

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

    def _finish_failed(
        self,
        spec: JobSpec,
        job_file: Path,
        output_dir: Path,
        lease_token: str,
        reason: str,
        error_message: str,
    ) -> JobResult:
        finished = self.client.finish(
            agent_id=self.agent_id,
            job_id=spec.job_id,
            status="FAILED",
            lease_token=lease_token,
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


class LeaseRenewer:
    def __init__(
        self,
        client: ServerJobClient,
        agent_id: str,
        job_id: str,
        lease_token: str,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> None:
        self.client = client
        self.agent_id = agent_id
        self.job_id = job_id
        self.lease_token = lease_token
        self.lease_seconds = lease_seconds
        self.interval_seconds = max(1, lease_seconds // 2)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name=f"lease-renew-{self.job_id}", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop_event.wait(self.interval_seconds):
            try:
                self.client.renew_lease(
                    agent_id=self.agent_id,
                    job_id=self.job_id,
                    lease_token=self.lease_token,
                    lease_seconds=self.lease_seconds,
                )
            except RuntimeError:
                return
