from __future__ import annotations

import argparse
import json
from pathlib import Path

from .ebpf import EbpfSyscallCollector
from .ebpf_latency import EbpfIoLatencyCollector
from .latency_diff import compare_latency_reports
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

    compare_latency = subcommands.add_parser("compare-latency", help="compare two eBPF IO latency reports")
    compare_latency.add_argument("--baseline", required=True, help="baseline ebpf_io_latency.json")
    compare_latency.add_argument("--current", required=True, help="current ebpf_io_latency.json")
    compare_latency.add_argument("--output", required=True, help="output ebpf_io_latency_diff.json")
    compare_latency.add_argument("--baseline-job-id", default=None)
    compare_latency.add_argument("--current-job-id", default=None)

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

    if args.command == "compare-latency":
        baseline_path = Path(args.baseline).expanduser().resolve()
        current_path = Path(args.current).expanduser().resolve()
        output_path = Path(args.output).expanduser().resolve()
        diff_report = compare_latency_reports(
            baseline=json.loads(baseline_path.read_text(encoding="utf-8-sig")),
            current=json.loads(current_path.read_text(encoding="utf-8-sig")),
            baseline_job_id=args.baseline_job_id,
            current_job_id=args.current_job_id,
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(diff_report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Generated: {output_path}")
        return 0

    raise AssertionError(f"unhandled command: {args.command}")
