from __future__ import annotations

import argparse

from .ebpf import EbpfSyscallCollector
from .ebpf_latency import EbpfIoLatencyCollector
from .perf import PerfCollector


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="minidrop_analysis")
    subcommands = parser.add_subparsers(dest="command", required=True)

    collect = subcommands.add_parser("collect", help="collect a profile for a target PID")
    collect.add_argument("--pid", required=True, type=_positive_int)
    collect.add_argument("--duration", default=10, type=_positive_int)
    collect.add_argument("--frequency", default=99, type=_positive_int)
    collect.add_argument("--output", required=True)
    collect.add_argument("--collector", default="perf", choices=["perf", "ebpf_syscall", "ebpf_io_latency"])
    collect.add_argument("--perf-bin", default="perf")
    collect.add_argument("--bpftrace-bin", default="bpftrace")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "collect":
        if args.collector == "perf":
            collector = PerfCollector(perf_bin=args.perf_bin)
        elif args.collector == "ebpf_syscall":
            collector = EbpfSyscallCollector(bpftrace_bin=args.bpftrace_bin)
        elif args.collector == "ebpf_io_latency":
            collector = EbpfIoLatencyCollector(bpftrace_bin=args.bpftrace_bin)
        else:
            raise AssertionError(f"unhandled collector: {args.collector}")
        summary = collector.collect(
            pid=args.pid,
            duration_seconds=args.duration,
            sample_frequency=args.frequency,
            output_dir=args.output,
        )
        print(f"Generated: {summary.artifacts['summary']}")
        return 0

    raise AssertionError(f"unhandled command: {args.command}")
