from __future__ import annotations

import argparse
import json

from .heartbeat import HeartbeatClient, result_to_dict
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

    heartbeat = subcommands.add_parser("heartbeat", help="send heartbeat messages to the API server")
    heartbeat.add_argument("--server-url", default="http://127.0.0.1:8000")
    heartbeat.add_argument("--agent-id", default="local-agent")
    heartbeat.add_argument("--interval", default=5, type=_positive_int)
    heartbeat.add_argument("--count", default=1, type=_non_negative_int)
    heartbeat.add_argument("--version", default="0.1.0")

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
        print(f"Job {result.job_id} finished with status {result.status}")
        print(f"Job metadata: {result.job_file}")
        return 0 if result.status == "DONE" else 1

    if args.command == "run-pending":
        result = LocalAgent(runtime_dir=args.runtime_dir).run_pending_once(job_id=args.job_id)
        if result is None:
            print("No pending job found")
            return 0
        print(f"Job {result.job_id} finished with status {result.status}")
        print(f"Job metadata: {result.job_file}")
        return 0 if result.status == "DONE" else 1

    if args.command == "heartbeat":
        results = HeartbeatClient(args.server_url).send_loop(
            agent_id=args.agent_id,
            interval_seconds=args.interval,
            count=args.count,
            version=args.version,
        )
        for result in results:
            print(json.dumps(result_to_dict(result), indent=2))
        return 0

    raise AssertionError(f"unhandled command: {args.command}")
