from __future__ import annotations

from pathlib import Path


def test_ebpf_demo_script_is_wired_to_makefile() -> None:
    root = Path(__file__).resolve().parents[1]
    makefile = (root / "Makefile").read_text(encoding="utf-8")
    script = root / "scripts" / "ebpf_demo.sh"

    assert script.exists()
    assert "ebpf-demo: build-latency-workload" in makefile
    assert "bash scripts/ebpf_demo.sh" in makefile
    assert "BASELINE_DELAY_US=$(BASELINE_DELAY_US)" in makefile
    assert "CURRENT_DELAY_US=$(CURRENT_DELAY_US)" in makefile
    assert "EBPF_DEMO_RUN_AGENT=$(EBPF_DEMO_RUN_AGENT)" in makefile


def test_ebpf_demo_script_captures_baseline_current_and_diff() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "ebpf_demo.sh").read_text(encoding="utf-8")

    assert "set -euo pipefail" in script
    assert "collector\": \"ebpf_io_latency\"" in script
    assert "BASELINE_DELAY_US" in script
    assert "CURRENT_DELAY_US" in script
    assert "run_latency_capture \"baseline\"" in script
    assert "run_latency_capture \"current\"" in script
    assert "/compare/ebpf-io-latency?baseline_job_id=" in script
    assert "comparison_available" in script
    assert "/api/jobs/${CURRENT_JOB_ID}/report" in script
    assert 'event.get("event")' in script
    assert "event.get('event')" not in script
    assert "jq" not in script


def test_latency_workload_accepts_delay_parameter() -> None:
    root = Path(__file__).resolve().parents[1]
    workload = (root / "workloads" / "io_latency_hotspot.c").read_text(encoding="utf-8")

    assert "parse_delay_us" in workload
    assert "writer_delay_us" in workload
    assert "args.delay_us" in workload
    assert "usleep(args->delay_us)" in workload
