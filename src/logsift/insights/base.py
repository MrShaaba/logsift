"""Shared finding types and the small helpers every rule module uses."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from logsift.sql import lit


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}


@dataclass
class Table:
    title: str
    columns: list[str]
    rows: list[tuple[Any, ...]]

    def to_dicts(self) -> list[dict[str, Any]]:
        return [dict(zip(self.columns, row, strict=False)) for row in self.rows]


@dataclass
class Finding:
    id: str
    rule: str
    title: str
    severity: Severity
    summary: str
    explanation: str
    likely_cause: str
    row_count: int
    # SQL WHERE fragment over the flow table selecting the rows behind this finding.
    row_filter: str
    tables: list[Table] = field(default_factory=list)
    # Optional series for a chart: {"labels": [...], "series": {"name": [...]}}
    chart: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule": self.rule,
            "title": self.title,
            "severity": str(self.severity),
            "summary": self.summary,
            "explanation": self.explanation,
            "likely_cause": self.likely_cause,
            "row_count": self.row_count,
            "tables": [{"title": t.title, "rows": t.to_dicts()} for t in self.tables],
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], -f.row_count, f.title))


# ------------------------------------------------------------------ text helpers


def fmt_bytes(n: int | float | None) -> str:
    if n is None:
        return "0 B"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} TB"


def utc(epoch: int) -> datetime:
    return datetime.fromtimestamp(epoch, UTC).replace(tzinfo=None)


def fmt_ts(ts: datetime | None) -> str:
    return ts.strftime("%Y-%m-%d %H:%M") if ts else "?"


def plural(n: int, word: str) -> str:
    if n == 1:
        return f"{n:,} {word}"
    return f"{n:,} {word}{'es' if word.endswith('s') else 's'}"


def span(first: datetime | None, last: datetime | None) -> str:
    return f"between {fmt_ts(first)} and {fmt_ts(last)}" if first else "in this file"


def ts(value: datetime) -> str:
    """A TIMESTAMP literal."""
    return f"TIMESTAMP {lit(value.strftime('%Y-%m-%d %H:%M:%S.%f'))}"


def pick_bucket(span_seconds: float) -> tuple[str, int]:
    """Timeline bucket size that keeps the chart to about 150 bars."""
    for name, secs in (
        ("minute", 60),
        ("5 minutes", 300),
        ("15 minutes", 900),
        ("hour", 3600),
        ("6 hours", 21600),
        ("day", 86400),
    ):
        if span_seconds / secs <= 150:
            return name, secs
    return "day", 86400
