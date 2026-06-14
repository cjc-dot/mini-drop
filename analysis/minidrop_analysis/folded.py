from __future__ import annotations

from collections import Counter
import re


_OFFSET_RE = re.compile(r"\+0x[0-9a-fA-F]+$")


def collapse_perf_script(text: str) -> Counter[str]:
    stacks: Counter[str] = Counter()
    current: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line:
            _flush_stack(stacks, current)
            current = []
            continue

        if raw_line[0].isspace():
            symbol = _parse_symbol(line)
            if symbol:
                current.append(symbol)

    _flush_stack(stacks, current)
    return stacks


def format_folded(stacks: Counter[str]) -> str:
    lines = [f"{stack} {count}" for stack, count in sorted(stacks.items())]
    return "\n".join(lines) + ("\n" if lines else "")


def _flush_stack(stacks: Counter[str], frames: list[str]) -> None:
    if not frames:
        return
    stacks[";".join(reversed(frames))] += 1


def _parse_symbol(line: str) -> str:
    parts = line.split()
    if len(parts) < 2:
        return ""

    symbol = _OFFSET_RE.sub("", parts[1])
    if symbol in {"[unknown]", "0"}:
        return ""
    return symbol
