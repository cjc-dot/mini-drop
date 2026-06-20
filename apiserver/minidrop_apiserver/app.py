from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .agent_store import AgentRegistry
from .process import ProcessInspector
from .store import ArtifactUploadError, ServerJobStore


class CreateJobRequest(BaseModel):
    pid: int = Field(gt=0)
    duration_seconds: int = Field(default=10, gt=0)
    sample_frequency: int = Field(default=99, gt=0)
    collector: Literal["perf"] = "perf"


class AgentHeartbeatRequest(BaseModel):
    hostname: str = Field(min_length=1)
    pid: int = Field(gt=0)
    version: str = Field(default="0.1.0", min_length=1)


class ClaimJobRequest(BaseModel):
    max_pending_age_seconds: int | None = Field(default=300, ge=0)


class FinishJobRequest(BaseModel):
    status: Literal["DONE", "FAILED"]
    artifacts: dict[str, str] | None = None
    error_message: str | None = None
    reason: str | None = None


class UploadArtifactsRequest(BaseModel):
    encoding: Literal["base64"] = "base64"
    artifacts: dict[str, str] = Field(default_factory=dict)


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
        return store.create_job(
            pid=request.pid,
            duration_seconds=request.duration_seconds,
            sample_frequency=request.sample_frequency,
            collector=request.collector,
            target=target,
        )

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
        artifact_name: Literal["flamegraph", "hotspots", "suggestions", "suggestions_markdown", "summary"],
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

    @app.post("/api/agents/{agent_id}/heartbeat")
    def agent_heartbeat(agent_id: str, request: AgentHeartbeatRequest) -> dict:
        return agents.record_heartbeat(
            agent_id=agent_id,
            hostname=request.hostname,
            pid=request.pid,
            version=request.version,
        )

    @app.post("/api/agents/{agent_id}/jobs/claim")
    def claim_job(agent_id: str, request: ClaimJobRequest) -> dict:
        return store.claim_pending_job(
            agent_id=agent_id,
            max_pending_age_seconds=request.max_pending_age_seconds,
        )

    @app.post("/api/agents/{agent_id}/jobs/{job_id}/finish")
    def finish_job(agent_id: str, job_id: str, request: FinishJobRequest) -> dict:
        try:
            return store.finish_claimed_job(
                agent_id=agent_id,
                job_id=job_id,
                status=request.status,
                artifacts=request.artifacts,
                error_message=request.error_message,
                reason=request.reason,
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="job not found") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/api/agents/{agent_id}/jobs/{job_id}/artifacts")
    def upload_job_artifacts(agent_id: str, job_id: str, request: UploadArtifactsRequest) -> dict:
        try:
            return store.upload_artifacts(
                agent_id=agent_id,
                job_id=job_id,
                artifact_payloads=request.artifacts,
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="job not found") from exc
        except ArtifactUploadError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

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
