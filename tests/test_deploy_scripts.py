from pathlib import Path


def test_sudoers_setup_script_requires_root_and_uses_visudo() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "deploy" / "setup_sudoers.sh").read_text(encoding="utf-8")

    assert "id -u" in script
    assert "SUDO_USER" in script
    assert "NOPASSWD" in script
    assert "perf" in script
    assert "bpftrace" in script
    assert "py-spy" in script
    assert "visudo -cf" in script
    assert "/etc/sudoers.d/mini-drop-tools" in script


def test_tool_check_script_checks_perf_and_bpftrace_nopasswd() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "deploy" / "check_tools.sh").read_text(encoding="utf-8")

    assert "check_command gcc" in script
    assert "check_command python3" in script
    assert "check_command perf" in script
    assert "check_command bpftrace" in script
    assert "check_command py-spy" in script
    assert "sudo -n" in script
