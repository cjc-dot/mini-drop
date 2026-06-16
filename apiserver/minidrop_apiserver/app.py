from __future__ import annotations

import os
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .agent_store import AgentRegistry
from .store import ServerJobStore


class CreateJobRequest(BaseModel):
    pid: int = Field(gt=0)
    duration_seconds: int = Field(default=10, gt=0)
    sample_frequency: int = Field(default=99, gt=0)
    collector: Literal["perf"] = "perf"


class AgentHeartbeatRequest(BaseModel):
    hostname: str = Field(min_length=1)
    pid: int = Field(gt=0)
    version: str = Field(default="0.1.0", min_length=1)


def create_app(runtime_dir: str | None = None) -> FastAPI:
    resolved_runtime_dir = runtime_dir or os.environ.get("MINIDROP_RUNTIME", "~/mini-drop-runtime")
    store = ServerJobStore(resolved_runtime_dir)
    agents = AgentRegistry(resolved_runtime_dir)
    app = FastAPI(title="Mini-Drop API Server")

    @app.get("/api/health")
    def health() -> dict:
        return {"service": "Mini-Drop API Server", "status": "running"}

    @app.post("/api/jobs", status_code=201)
    def create_job(request: CreateJobRequest) -> dict:
        return store.create_job(
            pid=request.pid,
            duration_seconds=request.duration_seconds,
            sample_frequency=request.sample_frequency,
            collector=request.collector,
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

    @app.post("/api/agents/{agent_id}/heartbeat")
    def agent_heartbeat(agent_id: str, request: AgentHeartbeatRequest) -> dict:
        return agents.record_heartbeat(
            agent_id=agent_id,
            hostname=request.hostname,
            pid=request.pid,
            version=request.version,
        )

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
