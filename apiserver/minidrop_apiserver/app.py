from __future__ import annotations

import os
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .store import ServerJobStore


class CreateJobRequest(BaseModel):
    pid: int = Field(gt=0)
    duration_seconds: int = Field(default=10, gt=0)
    sample_frequency: int = Field(default=99, gt=0)
    collector: Literal["perf"] = "perf"


def create_app(runtime_dir: str | None = None) -> FastAPI:
    store = ServerJobStore(runtime_dir or os.environ.get("MINIDROP_RUNTIME", "~/mini-drop-runtime"))
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

    return app
