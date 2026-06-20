from minidrop_agent.collectors import build_collector
from minidrop_analysis.ebpf import EbpfSyscallCollector
from minidrop_analysis.perf import PerfCollector


def test_build_collector_returns_perf_collector() -> None:
    assert isinstance(build_collector("perf"), PerfCollector)


def test_build_collector_returns_ebpf_syscall_collector() -> None:
    assert isinstance(build_collector("ebpf_syscall"), EbpfSyscallCollector)


def test_build_collector_rejects_unknown_collector() -> None:
    try:
        build_collector("missing")
    except ValueError as exc:
        assert "unsupported collector" in str(exc)
    else:
        raise AssertionError("build_collector should reject unsupported collectors")
