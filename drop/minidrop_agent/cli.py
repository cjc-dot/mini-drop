from __future__ import annotations

import argparse

from .job import JobSpec
from .runner import LocalAgent


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
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

    raise AssertionError(f"unhandled command: {args.command}")
