from __future__ import annotations

from io import StringIO
import json

from minidrop_analysis.structured_log import log_event


def test_log_event_emits_json_line_with_common_fields() -> None:
    stream = StringIO()

    record = log_event(
        "agent",
        "job_finished",
        stream=stream,
        job_id="job-test",
        status="DONE",
        ignored_none=None,
    )

    line = stream.getvalue().strip()
    parsed = json.loads(line)
    assert parsed == record
    assert parsed["component"] == "agent"
    assert parsed["event"] == "job_finished"
    assert parsed["level"] == "INFO"
    assert parsed["job_id"] == "job-test"
    assert parsed["status"] == "DONE"
    assert "ignored_none" not in parsed
    assert "ts" in parsed
    assert "hostname" in parsed
    assert "process_id" in parsed
