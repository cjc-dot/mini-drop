from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from minidrop_apiserver.agent_store import AgentRegistry


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
