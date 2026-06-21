from __future__ import annotations

import json

from minidrop_agent.cli import _print_job_result, _print_skip
from minidrop_agent.job import JobResult


def test_print_job_result_emits_structured_log_and_human_message(capsys) -> None:
    result = JobResult(
        job_id="job-test",
        status="DONE",
        job_file="/tmp/job.json",
        output_dir="/tmp/profile",
        artifacts={"summary": "/tmp/summary.json"},
    )

    _print_job_result(result)

    lines = capsys.readouterr().out.splitlines()
    log = json.loads(lines[0])
    assert log["component"] == "agent"
    assert log["event"] == "job_finished"
    assert log["job_id"] == "job-test"
    assert log["status"] == "DONE"
    assert log["artifact_count"] == 1
    assert lines[1] == "Job job-test finished with status DONE"


def test_print_skip_emits_structured_log_and_human_message(capsys) -> None:
    _print_skip("job-skip", "expired", "too old")

    lines = capsys.readouterr().out.splitlines()
    log = json.loads(lines[0])
    assert log["component"] == "agent"
    assert log["event"] == "job_skipped"
    assert log["job_id"] == "job-skip"
    assert log["reason"] == "expired"
    assert log["error_message"] == "too old"
    assert lines[1] == "Skipped job-skip: expired (too old)"
