"""Prometheus metrics — the operational interface a production WAF is run on.

The gateway's /statusz gives a JSON snapshot; dashboards and alerting need
scrapeable time series with latency histograms. This module is that interface.

Dependency-free on purpose. The exposition format is simple text, and the data
plane deliberately carries a minimal dependency tree (the whole T4/supply-chain
story in the threat model). A hand-rolled registry is safe here because the
gateway is a single-process asyncio app: metric updates happen on the event
loop with no preemption, so no locking is needed, and the label sets are fixed
and tiny (a handful of decisions and stages), so there is no cardinality risk.

If an operator prefers prometheus_client, the metric names and semantics here
match it exactly, so a swap is mechanical.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeVar

__all__ = ["Counter", "Gauge", "Histogram", "Registry", "REGISTRY", "render"]


def _fmt_labels(labels: dict[str, str]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{_escape(v)}"' for k, v in sorted(labels.items()))
    return "{" + inner + "}"


def _escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


@dataclass(slots=True)
class Counter:
    name: str
    help: str
    _values: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        self._values[key] = self._values.get(key, 0.0) + amount

    def _lines(self) -> list[str]:
        out = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        if not self._values:
            out.append(f"{self.name}_total 0")
        for key, val in sorted(self._values.items()):
            out.append(f"{self.name}_total{_fmt_labels(dict(key))} {val:g}")
        return out


@dataclass(slots=True)
class Gauge:
    name: str
    help: str
    _values: dict[tuple[tuple[str, str], ...], float] = field(default_factory=dict)

    def set(self, value: float, **labels: str) -> None:
        self._values[tuple(sorted(labels.items()))] = value

    def _lines(self) -> list[str]:
        out = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} gauge"]
        if not self._values:
            out.append(f"{self.name} 0")
        for key, val in sorted(self._values.items()):
            out.append(f"{self.name}{_fmt_labels(dict(key))} {val:g}")
        return out


#: Default buckets (seconds), sized for the 10 ms p99 budget the cascade targets.
DEFAULT_BUCKETS = (0.0005, 0.001, 0.0025, 0.005, 0.0075, 0.01, 0.025,
                   0.05, 0.1, 0.25, 0.5, 1.0)


@dataclass(slots=True)
class _HistRec:
    counts: list[int]
    total: float = 0.0
    n: int = 0


@dataclass(slots=True)
class Histogram:
    name: str
    help: str
    buckets: tuple[float, ...] = DEFAULT_BUCKETS
    _data: dict[tuple[tuple[str, str], ...], _HistRec] = field(default_factory=dict)

    def observe(self, value: float, **labels: str) -> None:
        key = tuple(sorted(labels.items()))
        rec = self._data.get(key)
        if rec is None:
            rec = _HistRec(counts=[0] * len(self.buckets))
            self._data[key] = rec
        for i, le in enumerate(self.buckets):
            if value <= le:
                rec.counts[i] += 1
        rec.total += value
        rec.n += 1

    def _lines(self) -> list[str]:
        out = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} histogram"]
        for key, rec in sorted(self._data.items()):
            lbl = dict(key)
            for i, le in enumerate(self.buckets):
                b = {**lbl, "le": _g(le)}
                out.append(f"{self.name}_bucket{_fmt_labels(b)} {rec.counts[i]}")
            out.append(f"{self.name}_bucket{_fmt_labels({**lbl, 'le': '+Inf'})} {rec.n}")
            out.append(f"{self.name}_sum{_fmt_labels(lbl)} {rec.total:g}")
            out.append(f"{self.name}_count{_fmt_labels(lbl)} {rec.n}")
        return out


def _g(x: float) -> str:
    return repr(x)


Metric = Counter | Gauge | Histogram
_M = TypeVar("_M", Counter, Gauge, Histogram)


class Registry:
    def __init__(self) -> None:
        self._metrics: list[Metric] = []

    def register(self, metric: _M) -> _M:
        self._metrics.append(metric)
        return metric

    def render(self) -> str:
        lines: list[str] = []
        for m in self._metrics:
            lines.extend(m._lines())
        return "\n".join(lines) + "\n"


REGISTRY = Registry()


def render() -> str:
    return REGISTRY.render()
