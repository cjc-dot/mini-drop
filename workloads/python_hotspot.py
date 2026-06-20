from __future__ import annotations

import math
import os
import time


def hot_python_loop(rounds: int = 12000) -> float:
    total = 0.0
    for index in range(rounds):
        total += math.sqrt((index % 97) + 1) * math.sin(index % 31)
    return total


def cold_python_loop(rounds: int = 1000) -> int:
    total = 0
    for index in range(rounds):
        total += index % 7
    return total


def main() -> None:
    print(f"python_hotspot started, pid={os.getpid()}", flush=True)
    sink = 0.0
    while True:
        sink += hot_python_loop()
        sink += cold_python_loop()
        if sink > 1e12:
            sink = 0.0
        time.sleep(0.001)


if __name__ == "__main__":
    main()
