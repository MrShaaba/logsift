"""Jinja environment, template filters and SVG chart geometry shared by UI and report."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from importlib import resources
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from logsift.insights.flowlogs import fmt_bytes
from logsift.profile import fmt_value

PLAIN_INT_HINTS = (
    "port",
    "version",
    "account",
    "_id",
    "id",
    "year",
    "flags",
    "protocol",
    "start",
    "end",
)


def is_plain_int_column(name: str) -> bool:
    """Columns whose integers are identifiers, not quantities: no thousands separator."""
    n = name.lower()
    return any(h in n for h in PLAIN_INT_HINTS)


def fmt_cell(v: Any, column: str = "") -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v) if is_plain_int_column(column) else f"{v:,}"
    if isinstance(v, float):
        return fmt_value(v)
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(v, date):
        return v.isoformat()
    return str(v)


def fmt_size(n: int) -> str:
    return fmt_bytes(n)


@dataclass
class Bar:
    x: float
    y: float
    w: float
    h: float
    label: str


@dataclass
class TimelineGeometry:
    width: int
    height: int
    accepted: list[Bar]
    rejected: list[Bar]
    ticks: list[tuple[float, str]]
    max_value: int
    bucket: str


def timeline_geometry(tl: dict[str, Any], width: int = 880, height: int = 170) -> TimelineGeometry:
    labels: list[str] = tl["labels"]
    acc: list[int] = tl["series"]["accepted"]
    rej: list[int] = tl["series"]["rejected"]
    n = max(1, len(labels))
    pad_left, pad_bottom, pad_top = 40, 24, 8
    plot_w = width - pad_left - 8
    plot_h = height - pad_bottom - pad_top
    max_value = max([a + r for a, r in zip(acc, rej, strict=True)] or [1]) or 1
    slot = plot_w / n
    bar_w = max(1.0, slot * 0.8)
    accepted: list[Bar] = []
    rejected: list[Bar] = []
    for i, (label, a, r) in enumerate(zip(labels, acc, rej, strict=True)):
        x = pad_left + i * slot + (slot - bar_w) / 2
        ha = plot_h * a / max_value
        hr = plot_h * r / max_value
        base = pad_top + plot_h
        accepted.append(Bar(x, base - ha, bar_w, ha, f"{label}: {a:,} accepted"))
        rejected.append(Bar(x, base - ha - hr, bar_w, hr, f"{label}: {r:,} rejected"))
    step = max(1, n // 10)
    ticks = [(pad_left + i * slot + slot / 2, labels[i]) for i in range(0, n, step)]
    return TimelineGeometry(width, height, accepted, rejected, ticks, max_value, tl["bucket"])


def histogram_bars(counts: list[int], width: int = 140, height: int = 30) -> list[Bar]:
    if not counts:
        return []
    n = len(counts)
    peak = max(counts) or 1
    slot = width / n
    bar_w = max(1.0, slot - 1)
    return [
        Bar(i * slot, height - height * c / peak, bar_w, height * c / peak, f"{c:,}")
        for i, c in enumerate(counts)
    ]


def make_env() -> Environment:
    env = Environment(
        loader=PackageLoader("logsift.web", "templates"),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["cell"] = fmt_cell
    env.filters["size"] = fmt_size
    env.filters["num"] = lambda v: f"{v:,}" if isinstance(v, int) else fmt_value(v)
    env.globals["timeline_geometry"] = timeline_geometry
    env.globals["histogram_bars"] = histogram_bars
    return env


def static_text(name: str) -> str:
    return resources.files("logsift.web").joinpath("static", name).read_text(encoding="utf-8")
