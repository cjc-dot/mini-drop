from __future__ import annotations

from minidrop_analysis.ebpf import EbpfSyscallCollector
from minidrop_analysis.ebpf_latency import EbpfIoLatencyCollector
from minidrop_analysis.perf import PerfCollector


def build_collector(collector: str):
    if collector == "perf":
        return PerfCollector()
    if collector == "ebpf_syscall":
        return EbpfSyscallCollector()
    if collector == "ebpf_io_latency":
        return EbpfIoLatencyCollector()
    raise ValueError(f"unsupported collector: {collector}")
