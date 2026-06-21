from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from minidrop_analysis.latency_diff import compare_latency_reports, no_latency_baseline_report
from minidrop_analysis.report import build_diagnostic_report
from minidrop_analysis.structured_log import log_event

from .agent_store import AgentRegistry
from .process import ProcessInspector
from .store import ArtifactUploadError, ServerJobStore


class CreateJobRequest(BaseModel):
    pid: int = Field(gt=0)
    duration_seconds: int = Field(default=10, gt=0)
    sample_frequency: int = Field(default=99, gt=0)
    collector: Literal["perf", "ebpf_syscall", "ebpf_io_latency", "py_spy"] = "perf"


class CreateContinuousProfileRequest(BaseModel):
    pid: int = Field(gt=0)
    slice_duration_seconds: int = Field(default=5, gt=0)
    sample_frequency: int = Field(default=49, gt=0)
    collector: Literal["perf", "ebpf_syscall", "ebpf_io_latency", "py_spy"] = "perf"
    slice_count: int = Field(default=3, gt=0, le=20)
    interval_seconds: int = Field(default=0, ge=0)


class AgentHeartbeatRequest(BaseModel):
    hostname: str = Field(min_length=1)
    pid: int = Field(gt=0)
    version: str = Field(default="0.1.0", min_length=1)


class ClaimJobRequest(BaseModel):
    max_pending_age_seconds: int | None = Field(default=300, ge=0)
    lease_seconds: int = Field(default=60, gt=0)
    max_claim_attempts: int = Field(default=3, gt=0)


class RenewLeaseRequest(BaseModel):
    lease_token: str = Field(min_length=1)
    lease_seconds: int = Field(default=60, gt=0)


class FinishJobRequest(BaseModel):
    status: Literal["DONE", "FAILED"]
    lease_token: str | None = None
    artifacts: dict[str, str] | None = None
    error_message: str | None = None
    reason: str | None = None


class UploadArtifactsRequest(BaseModel):
    encoding: Literal["base64"] = "base64"
    lease_token: str = Field(min_length=1)
    artifacts: dict[str, str] = Field(default_factory=dict)


class RequeueExpiredLeasesRequest(BaseModel):
    max_claim_attempts: int = Field(default=3, gt=0)


def create_app(runtime_dir: str | None = None, process_inspector: ProcessInspector | None = None) -> FastAPI:
    resolved_runtime_dir = runtime_dir or os.environ.get("MINIDROP_RUNTIME", "~/mini-drop-runtime")
    runtime_root = Path(resolved_runtime_dir).expanduser().resolve()
    store = ServerJobStore(resolved_runtime_dir)
    agents = AgentRegistry(resolved_runtime_dir)
    inspector = process_inspector or ProcessInspector()
    app = FastAPI(title="Mini-Drop API Server")
    frontend_dir = Path(__file__).resolve().parents[2] / "web_frontend"

    if frontend_dir.exists():
        app.mount("/ui/static", StaticFiles(directory=str(frontend_dir)), name="ui-static")

    @app.middleware("http")
    async def log_http_request(request: Request, call_next):
        started_at = time.monotonic()
        try:
            response = await call_next(request)
        except Exception as exc:
            log_event(
                "apiserver",
                "http_request_failed",
                level="ERROR",
                method=request.method,
                path=request.url.path,
                duration_ms=round((time.monotonic() - started_at) * 1000, 2),
                error_type=type(exc).__name__,
                error_message=str(exc),
            )
            raise

        duration_ms = round((time.monotonic() - started_at) * 1000, 2)
        if not _is_noisy_successful_request(request.url.path, response.status_code):
            log_event(
                "apiserver",
                "http_request",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=duration_ms,
            )
        return response

    @app.get("/api/health")
    def health() -> dict:
        return {"service": "Mini-Drop API Server", "status": "running"}

    @app.get("/ui")
    @app.get("/ui/")
    def web_ui() -> FileResponse:
        index_file = frontend_dir / "index.html"
        if not index_file.exists():
            raise HTTPException(status_code=404, detail="web frontend not found")
        return FileResponse(index_file)

    @app.post("/api/jobs", status_code=201)
    def create_job(request: CreateJobRequest) -> dict:
        target = inspector.inspect(request.pid)
        if target is None:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "TARGET_PROCESS_NOT_FOUND",
                    "message": f"target pid {request.pid} does not exist",
                },
            )
        job = store.create_job(
            pid=request.pid,
            duration_seconds=request.duration_seconds,
            sample_frequency=request.sample_frequency,
            collector=request.collector,
            target=target,
        )
        log_event(
            "apiserver",
            "job_created",
            job_id=job["job_id"],
            pid=request.pid,
            collector=request.collector,
            duration_seconds=request.duration_seconds,
            sample_frequency=request.sample_frequency,
        )
        return job

    @app.post("/api/continuous-profiles", status_code=201)
    def create_continuous_profile(request: CreateContinuousProfileRequest) -> dict:
        target = inspector.inspect(request.pid)
        if target is None:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "TARGET_PROCESS_NOT_FOUND",
                    "message": f"target pid {request.pid} does not exist",
                },
            )
        session = store.create_continuous_profile(
            pid=request.pid,
            slice_duration_seconds=request.slice_duration_seconds,
            sample_frequency=request.sample_frequency,
            collector=request.collector,
            slice_count=request.slice_count,
            interval_seconds=request.interval_seconds,
            target=target,
        )
        log_event(
            "apiserver",
            "continuous_profile_created",
            session_id=session["session_id"],
            pid=request.pid,
            collector=request.collector,
            slice_count=request.slice_count,
            slice_duration_seconds=request.slice_duration_seconds,
        )
        return session

    @app.get("/api/continuous-profiles")
    def list_continuous_profiles() -> list[dict]:
        return store.list_continuous_profiles()

    @app.get("/api/continuous-profiles/{session_id}")
    def get_continuous_profile(session_id: str) -> dict:
        session = store.get_continuous_profile(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="continuous profile not found")
        return session

    @app.get("/api/jobs")
    def list_jobs() -> list[dict]:
        return store.list_jobs()

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str) -> dict:
        job = store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return job

    @app.get("/api/jobs/{job_id}/events")
    def get_events(job_id: str) -> list[dict]:
        if store.get_job(job_id) is None:
            raise HTTPException(status_code=404, detail="job not found")
        return store.get_events(job_id)

    @app.get("/api/jobs/{job_id}/artifacts/{artifact_name}")
    def get_job_artifact(
        job_id: str,
        artifact_name: Literal[
            "flamegraph",
            "hotspots",
            "suggestions",
            "suggestions_markdown",
            "ebpf_raw",
            "ebpf_syscalls",
            "ebpf_io_latency_raw",
            "ebpf_io_latency",
            "pyspy_speedscope",
            "pyspy_profile",
            "summary",
        ],
    ) -> FileResponse:
        job = store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        artifact_path = job.get("artifacts", {}).get(artifact_name)
        if artifact_path is None:
            raise HTTPException(status_code=404, detail="artifact not found")
        path = Path(artifact_path).expanduser().resolve()
        try:
            path.relative_to(runtime_root)
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="artifact outside runtime dir") from exc
        if not path.exists() or not path.is_file():
            raise HTTPException(status_code=404, detail="artifact file not found")
        return FileResponse(path)

    @app.get("/api/jobs/{job_id}/compare/ebpf-io-latency")
    def compare_ebpf_io_latency(job_id: str, baseline_job_id: str | None = None) -> dict:
        current_job = store.get_job(job_id)
        if current_job is None:
            raise HTTPException(status_code=404, detail="job not found")
        if "ebpf_io_latency" not in current_job.get("artifacts", {}):
            raise HTTPException(status_code=404, detail="current job has no ebpf_io_latency artifact")

        if baseline_job_id:
            baseline_job = store.get_job(baseline_job_id)
            if baseline_job is None:
                raise HTTPException(status_code=404, detail="baseline job not found")
            if "ebpf_io_latency" not in baseline_job.get("artifacts", {}):
                raise HTTPException(status_code=404, detail="baseline job has no ebpf_io_latency artifact")
        else:
            baseline_job = _find_previous_ebpf_latency_job(store.list_jobs(), current_job)
            if baseline_job is None:
                return no_latency_baseline_report(current_job_id=job_id)

        current_report = _load_json_artifact(current_job, "ebpf_io_latency", runtime_root)
        baseline_report = _load_json_artifact(baseline_job, "ebpf_io_latency", runtime_root)
        return compare_latency_reports(
            baseline=baseline_report,
            current=current_report,
            baseline_job_id=baseline_job["job_id"],
            current_job_id=job_id,
        )

    @app.get("/api/jobs/{job_id}/report")
    def get_diagnostic_report(job_id: str) -> dict:
        job = store.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")

        artifacts, warnings = _load_optional_json_artifacts(
            job=job,
            artifact_names=["hotspots", "suggestions", "ebpf_syscalls", "ebpf_io_latency", "pyspy_profile"],
            runtime_root=runtime_root,
        )
        baseline_diff = None
        if artifacts.get("ebpf_io_latency"):
            baseline_job = _find_previous_ebpf_latency_job(store.list_jobs(), job)
            if baseline_job is None:
                baseline_diff = no_latency_baseline_report(current_job_id=job_id)
            else:
                try:
                    baseline_report = _load_json_artifact(baseline_job, "ebpf_io_latency", runtime_root)
                    baseline_diff = compare_latency_reports(
                        baseline=baseline_report,
                        current=artifacts["ebpf_io_latency"],
                        baseline_job_id=baseline_job["job_id"],
                        current_job_id=job_id,
                    )
                except HTTPException as exc:
                    warnings.append(f"baseline diff unavailable: {exc.detail}")

        return build_diagnostic_report(
            job=job,
            artifacts=artifacts,
            baseline_diff=baseline_diff,
            data_quality=warnings,
        )

    @app.post("/api/agents/{agent_id}/heartbeat")
    def agent_heartbeat(agent_id: str, request: AgentHeartbeatRequest) -> dict:
        agent = agents.record_heartbeat(
            agent_id=agent_id,
            hostname=request.hostname,
            pid=request.pid,
            version=request.version,
        )
        if _is_meaningful_agent_heartbeat(agent):
            log_event(
                "apiserver",
                "agent_status_changed",
                agent_id=agent_id,
                status=agent.get("status"),
                reason=agent.get("reason"),
                heartbeat_count=agent.get("heartbeat_count"),
            )
        return agent

    @app.post("/api/agents/{agent_id}/jobs/claim")
    def claim_job(agent_id: str, request: ClaimJobRequest) -> dict:
        result = store.claim_pending_job(
            agent_id=agent_id,
            max_pending_age_seconds=request.max_pending_age_seconds,
            lease_seconds=request.lease_seconds,
            max_claim_attempts=request.max_claim_attempts,
        )
        job = result.get("job")
        skipped_count = len(result.get("skipped", []))
        if job is not None or skipped_count > 0:
            log_event(
                "apiserver",
                "job_claim_response",
                agent_id=agent_id,
                job_id=job.get("job_id") if job else None,
                status=job.get("status") if job else None,
                skipped_count=skipped_count,
            )
        return result

    @app.post("/api/agents/{agent_id}/jobs/{job_id}/lease")
    def renew_job_lease(agent_id: str, job_id: str, request: RenewLeaseRequest) -> dict:
        try:
            return store.renew_job_lease(
                agent_id=agent_id,
                job_id=job_id,
                lease_token=request.lease_token,
                lease_seconds=request.lease_seconds,
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="job not found") from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/agents/{agent_id}/jobs/{job_id}/finish")
    def finish_job(agent_id: str, job_id: str, request: FinishJobRequest) -> dict:
        try:
            job = store.finish_claimed_job(
                agent_id=agent_id,
                job_id=job_id,
                status=request.status,
                artifacts=request.artifacts,
                error_message=request.error_message,
                reason=request.reason,
                lease_token=request.lease_token,
            )
            log_event(
                "apiserver",
                "job_finished",
                agent_id=agent_id,
                job_id=job_id,
                status=job.get("status"),
                reason=job.get("reason"),
                artifact_count=len(job.get("artifacts", {})),
                error_message=job.get("error_message"),
            )
            return job
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="job not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/agents/{agent_id}/jobs/{job_id}/artifacts")
    def upload_job_artifacts(agent_id: str, job_id: str, request: UploadArtifactsRequest) -> dict:
        try:
            job = store.upload_artifacts(
                agent_id=agent_id,
                job_id=job_id,
                artifact_payloads=request.artifacts,
                lease_token=request.lease_token,
            )
            log_event(
                "apiserver",
                "job_artifacts_uploaded",
                agent_id=agent_id,
                job_id=job_id,
                uploaded_count=len(request.artifacts),
                stored_count=len(job.get("artifacts", {})),
            )
            return job
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="job not found") from exc
        except ArtifactUploadError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/maintenance/requeue-expired-leases")
    def requeue_expired_leases(request: RequeueExpiredLeasesRequest) -> dict:
        processed = store.requeue_expired_leases(max_claim_attempts=request.max_claim_attempts)
        return {"processed_count": len(processed), "processed": processed}

    @app.get("/api/agents")
    def list_agents(offline_after_seconds: int = 30) -> list[dict]:
        return agents.list_agents(offline_after_seconds=offline_after_seconds)

    @app.get("/api/agents/{agent_id}")
    def get_agent(agent_id: str, offline_after_seconds: int = 30) -> dict:
        agent = agents.get_agent(agent_id, offline_after_seconds=offline_after_seconds)
        if agent is None:
            raise HTTPException(status_code=404, detail="agent not found")
        return agent

    @app.get("/api/agents/{agent_id}/events")
    def get_agent_events(agent_id: str) -> list[dict]:
        if agents.get_agent(agent_id) is None:
            raise HTTPException(status_code=404, detail="agent not found")
        return agents.get_agent_events(agent_id)

    return app


def _load_json_artifact(job: dict, artifact_name: str, runtime_root: Path) -> dict:
    artifact_path = job.get("artifacts", {}).get(artifact_name)
    if artifact_path is None:
        raise HTTPException(status_code=404, detail=f"{artifact_name} artifact not found")
    path = Path(artifact_path).expanduser().resolve()
    try:
        path.relative_to(runtime_root)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail="artifact outside runtime dir") from exc
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="artifact file not found")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _load_optional_json_artifacts(
    job: dict,
    artifact_names: list[str],
    runtime_root: Path,
) -> tuple[dict[str, dict | None], list[str]]:
    artifacts: dict[str, dict | None] = {name: None for name in artifact_names}
    warnings: list[str] = []
    for artifact_name in artifact_names:
        artifact_path = job.get("artifacts", {}).get(artifact_name)
        if artifact_path is None:
            continue
        path = Path(artifact_path).expanduser().resolve()
        try:
            path.relative_to(runtime_root)
        except ValueError:
            warnings.append(f"{artifact_name} ignored: artifact outside runtime dir")
            continue
        if not path.exists() or not path.is_file():
            warnings.append(f"{artifact_name} ignored: artifact file not found")
            continue
        try:
            artifacts[artifact_name] = json.loads(path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            warnings.append(f"{artifact_name} ignored: invalid json at line {exc.lineno}")
    return artifacts, warnings


def _find_previous_ebpf_latency_job(jobs: list[dict], current_job: dict) -> dict | None:
    current_created_at = current_job.get("created_at", "")
    current_job_id = current_job.get("job_id")
    current_comm = current_job.get("spec", {}).get("target", {}).get("comm")

    for job in jobs:
        if job.get("job_id") == current_job_id:
            continue
        if job.get("status") != "DONE":
            continue
        if "ebpf_io_latency" not in job.get("artifacts", {}):
            continue
        if current_created_at and job.get("created_at", "") >= current_created_at:
            continue
        job_comm = job.get("spec", {}).get("target", {}).get("comm")
        if current_comm and job_comm and job_comm != current_comm:
            continue
        return job
    return None


def _is_noisy_successful_request(path: str, status_code: int) -> bool:
    if status_code != 200:
        return False
    if path == "/api/health":
        return True
    if path.startswith("/api/agents/") and path.endswith("/heartbeat"):
        return True
    return path.startswith("/api/agents/") and path.endswith("/jobs/claim")


def _is_meaningful_agent_heartbeat(agent: dict) -> bool:
    return agent.get("reason") in {"agent registered by heartbeat", "heartbeat recovered"}
