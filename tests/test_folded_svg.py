from collections import Counter

from minidrop_analysis.folded import collapse_perf_script, format_folded
from minidrop_analysis.svg import render_flamegraph_svg


PERF_SCRIPT = """
cpu_hotspot 1234 100.000000: cycles:
        7f00 hot_func (/tmp/cpu_hotspot)
        7f01 main (/tmp/cpu_hotspot)
        7f02 __libc_start_call_main (/usr/lib/libc.so)

cpu_hotspot 1234 100.010000: cycles:
        7f00 hot_func (/tmp/cpu_hotspot)
        7f01 main (/tmp/cpu_hotspot)
        7f02 __libc_start_call_main (/usr/lib/libc.so)

cpu_hotspot 1234 100.020000: cycles:
        7f10 cold_func (/tmp/cpu_hotspot)
        7f01 main (/tmp/cpu_hotspot)
        7f02 __libc_start_call_main (/usr/lib/libc.so)
"""


def test_collapse_perf_script_counts_stacks() -> None:
    stacks = collapse_perf_script(PERF_SCRIPT)

    assert stacks["__libc_start_call_main;main;hot_func"] == 2
    assert stacks["__libc_start_call_main;main;cold_func"] == 1


def test_collapse_perf_script_normalizes_symbol_offsets() -> None:
    stacks = collapse_perf_script(
        """
cpu_hotspot 1234 100.000000: cycles:
        7f00 hot_func+0x1d (/tmp/cpu_hotspot)
        7f01 main+0x13 (/tmp/cpu_hotspot)

cpu_hotspot 1234 100.010000: cycles:
        7f00 hot_func+0x2a (/tmp/cpu_hotspot)
        7f01 main+0x13 (/tmp/cpu_hotspot)
"""
    )

    assert stacks["main;hot_func"] == 2


def test_format_folded_outputs_count_suffix() -> None:
    folded = format_folded(Counter({"main;hot_func": 3}))

    assert folded == "main;hot_func 3\n"


def test_render_flamegraph_svg_contains_frames() -> None:
    svg = render_flamegraph_svg(Counter({"main;hot_func": 3, "main;cold_func": 1}))

    assert "<svg" in svg
    assert 'fill="#eeeecc"' in svg
    assert "hot_func" in svg
    assert "cold_func" in svg
