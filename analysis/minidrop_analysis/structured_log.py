from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import socket
import sys
from typing import TextIO


def log_event(
    component: str,
    event: str,
    *,
    level: str = "INFO",
    stream: TextIO | None = None,
    **fields,
) -> dict:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "component": component,
        "event": event,
        "hostname": socket.gethostname(),
        "process_id": os.getpid(),
    }
    record.update({key: value for key, value in fields.items() if value is not None})
    output = stream or sys.stdout
    print(json.dumps(record, ensure_ascii=False, sort_keys=True, default=str), file=output, flush=True)
    return record
