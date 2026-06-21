from pathlib import Path


def test_sudoers_setup_script_requires_root_and_uses_visudo() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "deploy" / "setup_sudoers.sh").read_text(encoding="utf-8")

    assert "id -u" in script
    assert "SUDO_USER" in script
    assert "MINIDROP_PERF_BIN" in script
    assert "MINIDROP_BPFTRACE_BIN" in script
    assert "MINIDROP_PY_SPY_BIN" in script
    assert "configured tool path is not executable" in script
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


def test_doctor_script_checks_clone_environment_without_mutating_system() -> None:
    root = Path(__file__).resolve().parents[1]
    script = (root / "deploy" / "doctor.sh").read_text(encoding="utf-8")

    assert "check_command python3" in script
    assert "check_command gcc" in script
    assert "check_command perf" in script
    assert "check_command bpftrace" in script
    assert "check_command py-spy" in script
    assert "check_nopasswd perf" in script
    assert "check_nopasswd bpftrace" in script
    assert "check_nopasswd py-spy" in script
    assert "find_host_perf_bin" in script
    assert 'require_docker="${MINIDROP_REQUIRE_DOCKER:-0}"' in script
    assert "docker_issue()" in script
    assert "docker ps" in script
    assert "docker compose version" in script
    assert "sport = :8000" in script
    assert "sudo apt install" in script
    assert "sudo usermod -aG docker" in script
    assert "apt install -y" not in script.replace("sudo apt install -y", "")


def test_docker_compose_defines_api_and_privileged_agent_services() -> None:
    root = Path(__file__).resolve().parents[1]
    compose = (root / "docker-compose.yml").read_text(encoding="utf-8")

    assert "apiserver:" in compose
    assert "agent:" in compose
    assert "mini-drop-runtime:" in compose
    assert "network_mode: host" in compose
    assert "pid: host" in compose
    assert "privileged: true" in compose
    assert "${HOST_PERF_BIN:-/usr/bin/perf}:/opt/minidrop-tools/perf:ro" in compose
    assert "MINIDROP_PERF_BIN: /opt/minidrop-tools/perf" in compose
    assert "minidrop_apiserver" in compose
    assert "minidrop_agent" in compose
    assert "/api/health" in compose


def test_dockerfile_installs_runtime_tools_and_copies_project_modules() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")

    assert "FROM ubuntu:22.04" in dockerfile
    assert "bpftrace" in dockerfile
    assert "libpython3.10" in dockerfile
    assert "libtraceevent1" in dockerfile
    assert "linux-tools-generic" in dockerfile
    assert "python3 -m pip install -r requirements.txt" in dockerfile
    assert "COPY analysis ./analysis" in dockerfile
    assert "COPY apiserver ./apiserver" in dockerfile
    assert "COPY drop ./drop" in dockerfile
    assert "COPY web_frontend ./web_frontend" in dockerfile


def test_makefile_exposes_compose_targets() -> None:
    root = Path(__file__).resolve().parents[1]
    makefile = (root / "Makefile").read_text(encoding="utf-8")

    assert "compose-up:" in makefile
    assert "setup-python:" in makefile
    assert "$(PYTHON) -m pip install -r requirements.txt" in makefile
    assert "doctor:" in makefile
    assert "REQUIRE_DOCKER ?= 0" in makefile
    assert "MINIDROP_REQUIRE_DOCKER=$(REQUIRE_DOCKER) bash deploy/doctor.sh" in makefile
    assert "HOST_KERNEL ?= $(shell uname -r)" in makefile
    assert "HOST_PERF_BIN ?=" in makefile
    assert "HOST_BPFTRACE_BIN ?=" in makefile
    assert "HOST_PY_SPY_BIN ?=" in makefile
    assert "MINIDROP_PY_SPY_BIN=\"$(HOST_PY_SPY_BIN)\"" in makefile
    assert "doctor-fix: setup-sudoers" in makefile
    assert "/usr/lib/linux-tools-$(HOST_KERNEL)/perf" in makefile
    assert "/usr/lib/linux-tools/$(HOST_KERNEL)/perf" in makefile
    assert "compose-config:" in makefile
    assert "HOST_KERNEL=$(HOST_KERNEL) HOST_PERF_BIN=$(HOST_PERF_BIN) docker compose config" in makefile
    assert "HOST_KERNEL=$(HOST_KERNEL) HOST_PERF_BIN=$(HOST_PERF_BIN) docker compose up --build" in makefile
    assert "compose-down:" in makefile
    assert "HOST_KERNEL=$(HOST_KERNEL) HOST_PERF_BIN=$(HOST_PERF_BIN) docker compose down" in makefile
    assert "compose-logs:" in makefile
