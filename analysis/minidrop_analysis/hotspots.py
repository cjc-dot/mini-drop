from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Hotspot:
    function: str
    self_samples: int
    inclusive_samples: int
    self_percent: float
    inclusive_percent: float

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_hotspots(stacks: Counter[str], limit: int = 20) -> dict:
    total_samples = sum(count for count in stacks.values() if count > 0)
    self_samples: Counter[str] = Counter()
    inclusive_samples: Counter[str] = Counter()

    for stack, count in stacks.items():
        if count <= 0:
            continue
        frames = [frame for frame in stack.split(";") if frame]
        if not frames:
            continue

        for frame in frames:
            inclusive_samples[frame] += count
        self_samples[frames[-1]] += count

    functions = set(inclusive_samples) | set(self_samples)
    hotspots = [
        Hotspot(
            function=function,
            self_samples=self_samples[function],
            inclusive_samples=inclusive_samples[function],
            self_percent=_percent(self_samples[function], total_samples),
            inclusive_percent=_percent(inclusive_samples[function], total_samples),
        )
        for function in functions
    ]
    hotspots.sort(key=lambda item: (-item.self_samples, -item.inclusive_samples, item.function))

    return {
        "total_samples": total_samples,
        "limit": limit,
        "hotspots": [hotspot.to_dict() for hotspot in hotspots[:limit]],
    }


def _percent(samples: int, total_samples: int) -> float:
    if total_samples <= 0:
        return 0.0
    return round(samples * 100.0 / total_samples, 2)
