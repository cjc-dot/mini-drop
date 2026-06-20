from __future__ import annotations

from pathlib import Path


def test_e2e_demo_script_is_wired_to_makefile() -> None:
    root = Path(__file__).resolve().parents[1]
    makefile = (root / "Makefile").read_text(encoding="utf-8")
    script = root / "scripts" / "e2e_demo.sh"

    assert script.exists()
    assert "e2e-demo: build-workload" in makefile
    assert "bash scripts/e2e_demo.sh" in makefile


def test_e2e_demo_script_runs_server_agent_and_checks_report() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "e2e_demo.sh").read_text(encoding="utf-8")

    assert "set -euo pipefail" in script
    assert "curl -fsS" in script
    assert "python\" -m minidrop_apiserver" not in script
    assert '"${PYTHON}" -m minidrop_apiserver' in script
    assert '"${PYTHON}" -m minidrop_agent daemon' in script
    assert 'STATUS=$(printf' in script
    assert '[[ "${STATUS}" != "DONE" ]]' in script
    assert "/api/jobs/${JOB_ID}/report" in script
    assert "jq" not in script
