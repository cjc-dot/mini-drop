from __future__ import annotations

from collections import Counter
from html import escape


FRAME_HEIGHT = 18
WIDTH = 1200
PADDING_TOP = 28
PADDING_LEFT = 10
PADDING_RIGHT = 10
BACKGROUND = "#eeeecc"


def render_flamegraph_svg(stacks: Counter[str], title: str = "Mini-Drop Flame Graph") -> str:
    root = _build_tree(stacks)
    total = root["value"]
    max_depth = _max_depth(root)
    height = PADDING_TOP + (max_depth + 1) * FRAME_HEIGHT + 20

    lines = [
        '<?xml version="1.0" standalone="no"?>',
        f'<svg version="1.1" width="{WIDTH}" height="{height}" xmlns="http://www.w3.org/2000/svg">',
        f'<rect x="0" y="0" width="100%" height="100%" fill="{BACKGROUND}" />',
        "<style>",
        "text { font-family: Arial, sans-serif; font-size: 12px; fill: #111; }",
        ".title { font-size: 18px; font-weight: 700; }",
        ".frame:hover { stroke: #111; stroke-width: 1; }",
        "</style>",
        f'<text class="title" x="{WIDTH / 2}" y="20" text-anchor="middle">{escape(title)}</text>',
    ]

    usable_width = WIDTH - PADDING_LEFT - PADDING_RIGHT
    _render_children(lines, root, PADDING_LEFT, PADDING_TOP, usable_width, total, 0, max_depth)
    lines.append("</svg>")
    return "\n".join(lines) + "\n"


def _build_tree(stacks: Counter[str]) -> dict:
    root = {"name": "root", "value": 0, "children": {}}
    for stack, count in stacks.items():
        if count <= 0:
            continue
        root["value"] += count
        node = root
        for frame in stack.split(";"):
            node = node["children"].setdefault(frame, {"name": frame, "value": 0, "children": {}})
            node["value"] += count
    return root


def _max_depth(node: dict) -> int:
    if not node["children"]:
        return 0
    return 1 + max(_max_depth(child) for child in node["children"].values())


def _render_children(
    lines: list[str],
    node: dict,
    x: float,
    y: float,
    width: float,
    total: int,
    depth: int,
    max_depth: int,
) -> None:
    child_x = x
    for child in sorted(node["children"].values(), key=lambda item: (-item["value"], item["name"])):
        child_width = width * child["value"] / node["value"] if node["value"] else 0
        frame_y = y + (max_depth - depth) * FRAME_HEIGHT
        _render_frame(lines, child, child_x, frame_y, child_width, total, depth)
        _render_children(lines, child, child_x, y, child_width, total, depth + 1, max_depth)
        child_x += child_width


def _render_frame(lines: list[str], node: dict, x: float, y: float, width: float, total: int, depth: int) -> None:
    if width < 0.5:
        return

    color = _color_for(node["name"], depth)
    pct = 100.0 * node["value"] / total if total else 0.0
    label = f"{node['name']} ({node['value']} samples, {pct:.1f}%)"
    text = node["name"] if width > 45 else ""

    lines.append(f'<g><title>{escape(label)}</title>')
    lines.append(
        f'<rect class="frame" x="{x:.2f}" y="{y:.2f}" width="{max(width - 1, 0):.2f}" '
        f'height="{FRAME_HEIGHT - 1}" fill="{color}" />'
    )
    if text:
        lines.append(f'<text x="{x + 3:.2f}" y="{y + 13:.2f}">{escape(text[:80])}</text>')
    lines.append("</g>")


def _color_for(name: str, depth: int) -> str:
    seed = sum(ord(ch) for ch in name) + depth * 37
    hue = 28 + seed % 28
    saturation = 78 + seed % 12
    lightness = 48 + seed % 16
    return f"hsl({hue}, {saturation}%, {lightness}%)"
