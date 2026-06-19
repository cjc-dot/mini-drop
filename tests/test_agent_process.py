from __future__ import annotations

from pathlib import Path

from minidrop_agent.process import ProcessInspector


def test_process_inspector_reads_proc_metadata(tmp_path: Path) -> None:
    process_dir = tmp_path / "1234"
    process_dir.mkdir()
    (process_dir / "comm").write_text("cpu_hotspot\n", encoding="utf-8")
    (process_dir / "cmdline").write_bytes(b"/bin/cpu_hotspot\0--work\0")
    stat_values = ["S"] + ["0"] * 18 + ["12345"]
    (process_dir / "stat").write_text(f"1234 (cpu hot) {' '.join(stat_values)}", encoding="utf-8")

    metadata = ProcessInspector(proc_root=str(tmp_path)).inspect(1234)

    assert metadata == {
        "pid": 1234,
        "comm": "cpu_hotspot",
        "cmdline": "/bin/cpu_hotspot --work",
        "starttime": 12345,
    }


def test_process_inspector_returns_none_for_missing_pid(tmp_path: Path) -> None:
    assert ProcessInspector(proc_root=str(tmp_path)).inspect(9999) is None
