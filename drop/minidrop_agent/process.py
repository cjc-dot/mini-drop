from __future__ import annotations

from pathlib import Path


class ProcessInspector:
    def __init__(self, proc_root: str = "/proc") -> None:
        self.proc_root = Path(proc_root)

    def inspect(self, pid: int) -> dict | None:
        if pid <= 0:
            return None
        if not self.proc_root.exists():
            return {"pid": pid}

        process_dir = self.proc_root / str(pid)
        if not process_dir.exists():
            return None

        return {
            "pid": pid,
            "comm": self._read_text(process_dir / "comm"),
            "cmdline": self._read_cmdline(process_dir / "cmdline"),
            "starttime": self._read_starttime(process_dir / "stat"),
        }

    @staticmethod
    def _read_text(path: Path) -> str | None:
        try:
            return path.read_text(encoding="utf-8", errors="replace").strip() or None
        except OSError:
            return None

    @staticmethod
    def _read_cmdline(path: Path) -> str | None:
        try:
            raw = path.read_bytes()
        except OSError:
            return None
        parts = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
        return " ".join(parts) or None

    @staticmethod
    def _read_starttime(path: Path) -> int | None:
        try:
            stat = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        fields = stat.rsplit(") ", 1)
        if len(fields) != 2:
            return None
        values = fields[1].split()
        if len(values) < 20:
            return None
        try:
            return int(values[19])
        except ValueError:
            return None
