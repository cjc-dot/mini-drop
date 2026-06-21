from __future__ import annotations

from pathlib import Path


def test_full_demo_script_is_wired_to_make_demo() -> None:
    root = Path(__file__).resolve().parents[1]
    makefile = (root / "Makefile").read_text(encoding="utf-8")
    script = root / "scripts" / "full_demo.sh"

    assert script.exists()
    assert "DEMO_RUN_AGENT ?= 0" in makefile
    assert "demo: build-workload build-latency-workload" in makefile
    assert "$(MAKE) doctor REQUIRE_DOCKER=1" in makefile
    assert "bash scripts/full_demo.sh" in makefile
    assert "local-demo: build-workload" in makefile


def test_full_demo_runs_perf_and_ebpf_demo_scripts() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "full_demo.sh").read_text(encoding="utf-8")

    assert "set -euo pipefail" in script
    assert "health_check" in script
    assert "require_external_agent" in script
    assert "No ONLINE Agent is visible" in script
    assert 'E2E_RUN_AGENT="${DEMO_RUN_AGENT}"' in script
    assert 'DURATION="${DURATION}"' in script
    assert 'FREQUENCY="${FREQUENCY}"' in script
    assert 'bash "${ROOT_DIR}/scripts/e2e_demo.sh"' in script
    assert 'EBPF_DEMO_RUN_AGENT="${DEMO_RUN_AGENT}"' in script
    assert 'DIFF_OUTPUT="${DIFF_OUTPUT}"' in script
    assert 'BASELINE_DELAY_US="${BASELINE_DELAY_US}"' in script
    assert 'CURRENT_DELAY_US="${CURRENT_DELAY_US}"' in script
    assert 'bash "${ROOT_DIR}/scripts/ebpf_demo.sh"' in script
    assert "Mini-Drop full demo passed" in script
    assert "jq" not in script


def test_final_demo_keeps_old_local_demo_available() -> None:
    root = Path(__file__).resolve().parents[1]
    makefile = (root / "Makefile").read_text(encoding="utf-8")

    local_demo_block = makefile.split("local-demo: build-workload", maxsplit=1)[1].split("e2e-demo:", maxsplit=1)[0]
    assert "$(MINIDROP_RUNTIME)/builds/cpu_hotspot" in local_demo_block
    assert "$(MAKE) collect PID=$$pid PROFILE_ID=demo" in local_demo_block
