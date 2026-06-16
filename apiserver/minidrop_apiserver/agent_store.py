from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


class AgentRegistry:
    def __init__(self, runtime_dir: str) -> None:
        self.runtime_dir = Path(runtime_dir).expanduser().resolve()
        self.agents_dir = self.runtime_dir / "agents"

    def record_heartbeat(self, agent_id: str, hostname: str, pid: int, version: str) -> dict:
        existing = self._read_agent(agent_id)
        previous_status = self._effective_status(existing, offline_after_seconds=30) if existing else None
        now = self._now()

        agent = {
            "agent_id": agent_id,
            "status": "ONLINE",
            "reason": self._heartbeat_reason(previous_status),
            "hostname": hostname,
            "pid": pid,
            "version": version,
            "first_seen_at": existing.get("first_seen_at") if existing else now,
            "last_heartbeat_at": now,
            "updated_at": now,
            "heartbeat_count": int(existing.get("heartbeat_count", 0)) + 1 if existing else 1,
        }
        self._agent_dir(agent_id).mkdir(parents=True, exist_ok=True)
        self._write_agent(agent)
        self._append_agent_event(agent_id, self._heartbeat_event_status(previous_status), agent["reason"])
        return agent

    def list_agents(self, offline_after_seconds: int = 30) -> list[dict]:
        if not self.agents_dir.exists():
            return []

        agents = []
        for agent_file in self.agents_dir.glob("*/agent.json"):
            agent = json.loads(agent_file.read_text(encoding="utf-8"))
            agents.append(self._refresh_liveness(agent, offline_after_seconds))
        return sorted(agents, key=lambda agent: agent.get("last_heartbeat_at", ""), reverse=True)

    def get_agent(self, agent_id: str, offline_after_seconds: int = 30) -> dict | None:
        agent = self._read_agent(agent_id)
        if agent is None:
            return None
        return self._refresh_liveness(agent, offline_after_seconds)

    def get_agent_events(self, agent_id: str) -> list[dict]:
        events_file = self._agent_events_file(agent_id)
        if not events_file.exists():
            return []
        return [json.loads(line) for line in events_file.read_text(encoding="utf-8").splitlines() if line]

    def _refresh_liveness(self, agent: dict, offline_after_seconds: int) -> dict:
        result = dict(agent)
        elapsed = self._seconds_since(result["last_heartbeat_at"])
        result["offline_after_seconds"] = offline_after_seconds
        result["seconds_since_last_heartbeat"] = int(elapsed)

        effective_status = "OFFLINE" if elapsed > offline_after_seconds else "ONLINE"
        if effective_status == "OFFLINE":
            result["status"] = "OFFLINE"
            result["reason"] = "heartbeat timeout"
            if agent.get("status") != "OFFLINE":
                stored = dict(agent)
                stored["status"] = "OFFLINE"
                stored["reason"] = "heartbeat timeout"
                stored["updated_at"] = self._now()
                self._write_agent(stored)
                self._append_agent_event(agent["agent_id"], "OFFLINE", "heartbeat timeout")
        else:
            result["status"] = "ONLINE"
            result["reason"] = "heartbeat fresh"

        return result

    def _read_agent(self, agent_id: str) -> dict | None:
        agent_file = self._agent_file(agent_id)
        if not agent_file.exists():
            return None
        return json.loads(agent_file.read_text(encoding="utf-8"))

    def _write_agent(self, agent: dict) -> None:
        self._write_json_atomic(self._agent_file(agent["agent_id"]), agent)

    def _append_agent_event(self, agent_id: str, status: str, reason: str) -> None:
        event = {
            "agent_id": agent_id,
            "status": status,
            "reason": reason,
            "created_at": self._now(),
        }
        with self._agent_events_file(agent_id).open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event) + "\n")

    def _agent_dir(self, agent_id: str) -> Path:
        return self.agents_dir / agent_id

    def _agent_file(self, agent_id: str) -> Path:
        return self._agent_dir(agent_id) / "agent.json"

    def _agent_events_file(self, agent_id: str) -> Path:
        return self._agent_dir(agent_id) / "events.jsonl"

    def _effective_status(self, agent: dict, offline_after_seconds: int) -> str:
        return "OFFLINE" if self._seconds_since(agent["last_heartbeat_at"]) > offline_after_seconds else "ONLINE"

    @staticmethod
    def _heartbeat_reason(previous_status: str | None) -> str:
        if previous_status is None:
            return "agent registered by heartbeat"
        if previous_status == "OFFLINE":
            return "heartbeat recovered"
        return "heartbeat received"

    @staticmethod
    def _heartbeat_event_status(previous_status: str | None) -> str:
        if previous_status in {None, "OFFLINE"}:
            return "ONLINE"
        return "HEARTBEAT"

    @staticmethod
    def _seconds_since(timestamp: str) -> float:
        value = datetime.fromisoformat(timestamp)
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - value).total_seconds()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _write_json_atomic(path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
        try:
            with temp_path.open("w", encoding="utf-8") as stream:
                stream.write(json.dumps(payload, indent=2))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, path)
        finally:
            if temp_path.exists():
                temp_path.unlink()
