from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from minidrop_apiserver.agent_store import AgentRegistry
from minidrop_agent import heartbeat as heartbeat_module
from minidrop_agent.heartbeat import HeartbeatClient, HeartbeatResult


def test_record_agent_heartbeat_persists_online_agent(tmp_path: Path) -> None:
    registry = AgentRegistry(str(tmp_path))

    agent = registry.record_heartbeat(
        agent_id="agent-1",
        hostname="vm",
        pid=1234,
        version="0.1.0",
    )

    assert agent["status"] == "ONLINE"
    assert agent["hostname"] == "vm"
    assert agent["heartbeat_count"] == 1

    saved = registry.get_agent("agent-1")
    assert saved is not None
    assert saved["status"] == "ONLINE"
    assert saved["seconds_since_last_heartbeat"] >= 0

    events = registry.get_agent_events("agent-1")
    assert [event["status"] for event in events] == ["ONLINE"]


def test_record_agent_heartbeat_atomic_snapshot_write_leaves_no_temp_file(tmp_path: Path) -> None:
    registry = AgentRegistry(str(tmp_path))
    registry.record_heartbeat(agent_id="agent-1", hostname="vm", pid=1234, version="0.1.0")
    agent_dir = tmp_path / "agents" / "agent-1"

    assert (agent_dir / "agent.json").exists()
    assert list(agent_dir.glob(".*.tmp")) == []


def test_list_agents_marks_stale_agent_offline(tmp_path: Path) -> None:
    registry = AgentRegistry(str(tmp_path))
    agent = registry.record_heartbeat(
        agent_id="agent-1",
        hostname="vm",
        pid=1234,
        version="0.1.0",
    )

    stale = dict(agent)
    stale["last_heartbeat_at"] = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat()
    agent_file = tmp_path / "agents" / "agent-1" / "agent.json"
    agent_file.write_text(json.dumps(stale), encoding="utf-8")

    agents = registry.list_agents(offline_after_seconds=30)

    assert agents[0]["status"] == "OFFLINE"
    assert agents[0]["reason"] == "heartbeat timeout"
    assert registry.get_agent_events("agent-1")[-1]["status"] == "OFFLINE"


def test_heartbeat_after_timeout_records_recovery(tmp_path: Path) -> None:
    registry = AgentRegistry(str(tmp_path))
    agent = registry.record_heartbeat(
        agent_id="agent-1",
        hostname="vm",
        pid=1234,
        version="0.1.0",
    )
    stale = dict(agent)
    stale["last_heartbeat_at"] = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat()
    (tmp_path / "agents" / "agent-1" / "agent.json").write_text(json.dumps(stale), encoding="utf-8")

    assert registry.get_agent("agent-1", offline_after_seconds=30)["status"] == "OFFLINE"
    recovered = registry.record_heartbeat("agent-1", "vm", 1234, "0.1.0")

    assert recovered["status"] == "ONLINE"
    assert recovered["reason"] == "heartbeat recovered"
    assert [event["status"] for event in registry.get_agent_events("agent-1")] == ["ONLINE", "OFFLINE", "ONLINE"]


class _FakeHttpResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> "_FakeHttpResponse":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self) -> bytes:
        return self.payload


def test_heartbeat_client_uses_unknown_when_status_is_missing(monkeypatch) -> None:
    def fake_urlopen(request, timeout):
        return _FakeHttpResponse(b'{"agent_id": "agent-1"}')

    monkeypatch.setattr(heartbeat_module, "urlopen", fake_urlopen)

    result = HeartbeatClient("http://server").send_once("agent-1")

    assert result.status == "UNKNOWN"
    assert result.response == {"agent_id": "agent-1"}


def test_heartbeat_loop_continues_after_single_failure(monkeypatch) -> None:
    client = HeartbeatClient("http://server")
    calls = {"count": 0}

    def fake_send_once(agent_id: str, version: str = "0.1.0") -> HeartbeatResult:
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("network unavailable")
        return HeartbeatResult(agent_id=agent_id, server_url="http://server", status="ONLINE", response={"status": "ONLINE"})

    monkeypatch.setattr(client, "send_once", fake_send_once)
    monkeypatch.setattr(heartbeat_module.time, "sleep", lambda seconds: None)

    results = client.send_loop(agent_id="agent-1", interval_seconds=5, count=2)

    assert [result.status for result in results] == ["FAILED", "ONLINE"]
    assert results[0].error_message == "network unavailable"
