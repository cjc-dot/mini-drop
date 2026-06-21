from __future__ import annotations

import argparse
import json

from minidrop_analysis.structured_log import log_event

from .daemon import AgentDaemon
from .heartbeat import HeartbeatClient, result_to_dict
from .http_jobs import HttpJobRunner
from .job import JobResult
from .job import JobSpec
from .runner import LocalAgent


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return number


def _non_negative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("value must be zero or positive")
    return number


def _print_skip(job_id: str, reason: str, error: str | None) -> None:
    log_event(
        "agent",
        "job_skipped",
        job_id=job_id,
        reason=reason,
        error_message=error,
    )
    print(f"Skipped {job_id}: {reason}" + (f" ({error})" if error else ""), flush=True)


def _print_job_result(result: JobResult) -> None:
    log_event(
        "agent",
        "job_finished",
        job_id=result.job_id,
        status=result.status,
        output_dir=result.output_dir,
        artifact_count=len(result.artifacts),
        error_message=result.error_message,
    )
    print(f"Job {result.job_id} finished with status {result.status}", flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="minidrop_agent")
    subcommands = parser.add_subparsers(dest="command", required=True)

    run = subcommands.add_parser("run", help="run one local profiling job")
    run.add_argument("--pid", required=True, type=_positive_int)
    run.add_argument("--duration", default=10, type=_positive_int)
    run.add_argument("--frequency", default=99, type=_positive_int)
    run.add_argument("--job-id", required=True)
    run.add_argument("--runtime-dir", default="~/mini-drop-runtime")
    run.add_argument("--collector", default="perf", choices=["perf"])

    run_pending = subcommands.add_parser("run-pending", help="run one pending job from the runtime job store")
    run_pending.add_argument("--runtime-dir", default="~/mini-drop-runtime")
    run_pending.add_argument("--job-id", default=None)
    run_pending.add_argument("--max-pending-age", default=300, type=_non_negative_int)
    run_pending.add_argument("--disable-pid-check", action="store_true")

    heartbeat = subcommands.add_parser("heartbeat", help="send heartbeat messages to the API server")
    heartbeat.add_argument("--server-url", default="http://127.0.0.1:8000")
    heartbeat.add_argument("--agent-id", default="local-agent")
    heartbeat.add_argument("--interval", default=5, type=_positive_int)
    heartbeat.add_argument("--count", default=1, type=_non_negative_int)
    heartbeat.add_argument("--version", default="0.1.0")

    daemon = subcommands.add_parser("daemon", help="run heartbeat and pending-job polling loops")
    daemon.add_argument("--runtime-dir", default="~/mini-drop-runtime")
    daemon.add_argument("--server-url", default="http://127.0.0.1:8000")
    daemon.add_argument("--agent-id", default="local-agent")
    daemon.add_argument("--heartbeat-interval", default=5, type=_positive_int)
    daemon.add_argument("--poll-interval", default=2, type=_positive_int)
    daemon.add_argument("--max-jobs", default=0, type=_non_negative_int)
    daemon.add_argument("--max-pending-age", default=300, type=_non_negative_int)
    daemon.add_argument("--max-claim-attempts", default=3, type=_positive_int)
    daemon.add_argument("--disable-pid-check", action="store_true")
    daemon.add_argument("--version", default="0.1.0")
    daemon.add_argument("--job-source", default="local", choices=["local", "server"])
    daemon.add_argument("--lease-seconds", default=60, type=_positive_int)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "run":
        spec = JobSpec(
            job_id=args.job_id,
            pid=args.pid,
            duration_seconds=args.duration,
            sample_frequency=args.frequency,
            collector=args.collector,
        )
        result = LocalAgent(runtime_dir=args.runtime_dir).run(spec)
        _print_job_result(result)
        print(f"Job metadata: {result.job_file}")
        return 0 if result.status == "DONE" else 1

    if args.command == "run-pending":
        result = LocalAgent(runtime_dir=args.runtime_dir).run_pending_once(
            job_id=args.job_id,
            validate_pid=not args.disable_pid_check,
            max_pending_age_seconds=args.max_pending_age or None,
            on_skip=_print_skip,
        )
        if result is None:
            print("No pending job found")
            return 0
        _print_job_result(result)
        print(f"Job metadata: {result.job_file}")
        return 0 if result.status == "DONE" else 1

    if args.command == "heartbeat":
        try:
            results = HeartbeatClient(args.server_url).send_loop(
                agent_id=args.agent_id,
                interval_seconds=args.interval,
                count=args.count,
                version=args.version,
            )
        except KeyboardInterrupt:
            print("Heartbeat stopped by user")
            return 130
        for result in results:
            print(json.dumps(result_to_dict(result), indent=2))
        return 0

    if args.command == "daemon":
        pending_agent = None
        if args.job_source == "server":
            pending_agent = HttpJobRunner(
                runtime_dir=args.runtime_dir,
                server_url=args.server_url,
                agent_id=args.agent_id,
                lease_seconds=args.lease_seconds,
            )
        daemon = AgentDaemon(
            runtime_dir=args.runtime_dir,
            server_url=args.server_url,
            agent_id=args.agent_id,
            heartbeat_interval_seconds=args.heartbeat_interval,
            poll_interval_seconds=args.poll_interval,
            max_pending_age_seconds=args.max_pending_age or None,
            max_claim_attempts=args.max_claim_attempts,
            validate_pid=not args.disable_pid_check,
            version=args.version,
            agent=pending_agent,
            on_job_result=_print_job_result,
            on_job_skip=_print_skip,
        )
        try:
            completed_jobs = daemon.run_forever(max_jobs=args.max_jobs or None)
        except KeyboardInterrupt:
            daemon.stop()
            print("Agent daemon stopped by user")
            return 130
        print(f"Agent daemon stopped after completing {completed_jobs} job(s)")
        return 0

    raise AssertionError(f"unhandled command: {args.command}")
