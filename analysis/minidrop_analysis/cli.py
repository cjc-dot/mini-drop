from __future__ import annotations

import argparse

from .perf import PerfCollector


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="minidrop_analysis")
    subcommands = parser.add_subparsers(dest="command", required=True)

    collect = subcommands.add_parser("collect", help="collect a perf profile for a target PID")
    collect.add_argument("--pid", required=True, type=_positive_int)
    collect.add_argument("--duration", default=10, type=_positive_int)
    collect.add_argument("--frequency", default=99, type=_positive_int)
    collect.add_argument("--output", required=True)
    collect.add_argument("--perf-bin", default="perf")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "collect":
        collector = PerfCollector(perf_bin=args.perf_bin)
        summary = collector.collect(
            pid=args.pid,
            duration_seconds=args.duration,
            sample_frequency=args.frequency,
            output_dir=args.output,
        )
        print(f"Generated: {summary.artifacts['flamegraph']}")
        return 0

    raise AssertionError(f"unhandled command: {args.command}")
