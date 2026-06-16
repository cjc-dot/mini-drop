from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import asdict, dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class HeartbeatResult:
    agent_id: str
    server_url: str
    status: str
    response: dict


class HeartbeatClient:
    def __init__(self, server_url: str) -> None:
        self.server_url = server_url.rstrip("/")

    def send_once(self, agent_id: str, version: str = "0.1.0") -> HeartbeatResult:
        payload = {
            "hostname": socket.gethostname(),
            "pid": os.getpid(),
            "version": version,
        }
        body = json.dumps(payload).encode("utf-8")
        request = Request(
            f"{self.server_url}/api/agents/{agent_id}/heartbeat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urlopen(request, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"heartbeat rejected: HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise RuntimeError(f"heartbeat failed: {exc.reason}") from exc

        return HeartbeatResult(
            agent_id=agent_id,
            server_url=self.server_url,
            status=data["status"],
            response=data,
        )

    def send_loop(self, agent_id: str, interval_seconds: int, count: int, version: str = "0.1.0") -> list[HeartbeatResult]:
        results = []
        sent = 0
        while count == 0 or sent < count:
            results.append(self.send_once(agent_id=agent_id, version=version))
            sent += 1
            if count != 0 and sent >= count:
                break
            time.sleep(interval_seconds)
        return results


def result_to_dict(result: HeartbeatResult) -> dict:
    return asdict(result)
