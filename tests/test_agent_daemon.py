from __future__ import annotations

from minidrop_agent.daemon import AgentDaemon
from minidrop_agent.heartbeat import HeartbeatResult
from minidrop_agent.job import JobResult


class FakeAgent:
    def __init__(self, result: JobResult | None) -> None:
        self.result = result
        self.calls = 0
        self.last_validate_pid = None
        self.last_max_pending_age_seconds = None

    def run_pending_once(
        self,
        job_id: str | None = None,
        *,
        validate_pid: bool = False,
        max_pending_age_seconds: int | None = None,
        on_skip=None,
    ) -> JobResult | None:
        self.calls += 1
        self.last_validate_pid = validate_pid
        self.last_max_pending_age_seconds = max_pending_age_seconds
        if on_skip is not None and self.result is None:
            on_skip("job-skip", "target process not found before claim", "pid 999999 does not exist")
        return self.result


class FakeHeartbeatClient:
    server_url = "http://server"

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def send_once(self, agent_id: str, version: str = "0.1.0") -> HeartbeatResult:
        self.calls += 1
        if self.fail:
            raise RuntimeError("server unavailable")
        return HeartbeatResult(
            agent_id=agent_id,
            server_url=self.server_url,
            status="ONLINE",
            response={"status": "ONLINE"},
        )


def test_daemon_run_once_sends_heartbeat_and_runs_pending_job() -> None:
    result = JobResult(
        job_id="job-test",
        status="DONE",
        job_file="/tmp/job.json",
        output_dir="/tmp/profile",
        artifacts={},
    )
    agent = FakeAgent(result)
    heartbeat = FakeHeartbeatClient()
    daemon = AgentDaemon(agent=agent, heartbeat_client=heartbeat)

    assert daemon.run_once() == result
    assert heartbeat.calls == 1
    assert agent.calls == 1
    assert agent.last_validate_pid is True
    assert agent.last_max_pending_age_seconds == 300


def test_daemon_heartbeat_failure_does_not_block_pending_job() -> None:
    result = JobResult(
        job_id="job-test",
        status="DONE",
        job_file="/tmp/job.json",
        output_dir="/tmp/profile",
        artifacts={},
    )
    agent = FakeAgent(result)
    heartbeat = FakeHeartbeatClient(fail=True)
    daemon = AgentDaemon(agent=agent, heartbeat_client=heartbeat)

    assert daemon.run_once() == result
    assert heartbeat.calls == 1
    assert agent.calls == 1


def test_daemon_passes_pending_queue_guard_options_to_agent() -> None:
    agent = FakeAgent(None)
    skipped = []
    daemon = AgentDaemon(
        agent=agent,
        heartbeat_client=FakeHeartbeatClient(),
        validate_pid=False,
        max_pending_age_seconds=None,
        on_job_skip=lambda job_id, reason, error: skipped.append((job_id, reason, error)),
    )

    assert daemon.run_once() is None
    assert agent.last_validate_pid is False
    assert agent.last_max_pending_age_seconds is None
    assert skipped == [("job-skip", "target process not found before claim", "pid 999999 does not exist")]
