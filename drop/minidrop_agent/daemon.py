from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Protocol

from .heartbeat import HeartbeatClient, HeartbeatResult
from .job import JobResult
from .runner import LocalAgent


class PendingJobRunner(Protocol):
    def run_pending_once(
        self,
        job_id: str | None = None,
        *,
        validate_pid: bool = False,
        max_pending_age_seconds: int | None = None,
        max_claim_attempts: int = 3,
        on_skip: Callable[[str, str, str | None], None] | None = None,
    ) -> JobResult | None:
        ...


class HeartbeatSender(Protocol):
    def send_once(self, agent_id: str, version: str = "0.1.0") -> HeartbeatResult:
        ...


class AgentDaemon:
    def __init__(
        self,
        runtime_dir: str = "~/mini-drop-runtime",
        server_url: str = "http://127.0.0.1:8000",
        agent_id: str = "local-agent",
        heartbeat_interval_seconds: int = 5,
        poll_interval_seconds: int = 2,
        max_pending_age_seconds: int | None = 300,
        max_claim_attempts: int = 3,
        validate_pid: bool = True,
        version: str = "0.1.0",
        agent: PendingJobRunner | None = None,
        heartbeat_client: HeartbeatSender | None = None,
        on_job_result: Callable[[JobResult], None] | None = None,
        on_job_skip: Callable[[str, str, str | None], None] | None = None,
        sleep_fn=time.sleep,
    ) -> None:
        self.agent_id = agent_id
        self.heartbeat_interval_seconds = heartbeat_interval_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self.max_pending_age_seconds = max_pending_age_seconds
        self.max_claim_attempts = max_claim_attempts
        self.validate_pid = validate_pid
        self.version = version
        self.agent = agent or LocalAgent(runtime_dir=runtime_dir)
        self.heartbeat_client = heartbeat_client or HeartbeatClient(server_url)
        self.on_job_result = on_job_result
        self.on_job_skip = on_job_skip
        self.sleep_fn = sleep_fn
        self._stop_event = threading.Event()
        self._heartbeat_thread: threading.Thread | None = None

    def stop(self) -> None:
        self._stop_event.set()

    def run_once(self) -> JobResult | None:
        self.send_heartbeat_once()
        return self.agent.run_pending_once(
            validate_pid=self.validate_pid,
            max_pending_age_seconds=self.max_pending_age_seconds,
            max_claim_attempts=self.max_claim_attempts,
            on_skip=self.on_job_skip,
        )

    def send_heartbeat_once(self) -> HeartbeatResult:
        try:
            return self.heartbeat_client.send_once(agent_id=self.agent_id, version=self.version)
        except RuntimeError as exc:
            return HeartbeatResult(
                agent_id=self.agent_id,
                server_url=getattr(self.heartbeat_client, "server_url", ""),
                status="FAILED",
                response={},
                error_message=str(exc),
            )

    def run_forever(self, max_jobs: int | None = None) -> int:
        completed_jobs = 0
        self._start_heartbeat_thread()
        try:
            while not self._stop_event.is_set():
                result = self.agent.run_pending_once(
                    validate_pid=self.validate_pid,
                    max_pending_age_seconds=self.max_pending_age_seconds,
                    max_claim_attempts=self.max_claim_attempts,
                    on_skip=self.on_job_skip,
                )
                if result is not None:
                    if self.on_job_result is not None:
                        self.on_job_result(result)
                    completed_jobs += 1
                    if max_jobs is not None and completed_jobs >= max_jobs:
                        break
                    continue
                self._sleep_until_stopped(self.poll_interval_seconds)
        finally:
            self.stop()
            self._join_heartbeat_thread()
        return completed_jobs

    def _start_heartbeat_thread(self) -> None:
        if self._heartbeat_thread is not None and self._heartbeat_thread.is_alive():
            return
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, name="minidrop-heartbeat", daemon=True)
        self._heartbeat_thread.start()

    def _join_heartbeat_thread(self) -> None:
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=2)

    def _heartbeat_loop(self) -> None:
        while not self._stop_event.is_set():
            self.send_heartbeat_once()
            self._sleep_until_stopped(self.heartbeat_interval_seconds)

    def _sleep_until_stopped(self, seconds: int) -> None:
        if seconds <= 0:
            return
        end_time = time.monotonic() + seconds
        while not self._stop_event.is_set():
            remaining = end_time - time.monotonic()
            if remaining <= 0:
                return
            self.sleep_fn(min(remaining, 0.2))
