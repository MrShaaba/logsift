"""Shared types for comparing a "before" and an "after" file: the cutover validator.

A plug-in implements ``cutover_checks(ctx)`` over a :class:`DiffContext`, which holds both
files' canonical tables (``b`` and ``a``) trimmed to the same length of time, and returns
:class:`Change` objects, each with a verdict and evidence. ``logsift.diff`` builds the
context and the report; this module has no dependency on the dataset so plug-ins can
import it freely.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

import duckdb

from logsift.insights.base import Table, ts
from logsift.sql import q


class Verdict(StrEnum):
    CLEAN = "clean"
    REVIEW = "review"
    REGRESSION = "regression"


VERDICT_ORDER = {Verdict.CLEAN: 0, Verdict.REVIEW: 1, Verdict.REGRESSION: 2}


def worst(verdicts: list[Verdict]) -> Verdict:
    return max(verdicts, key=lambda v: VERDICT_ORDER[v], default=Verdict.CLEAN)


@dataclass
class Health:
    """What "bad" means for a format, for the totals check and the timeline."""

    bad: str  # SQL boolean over the canonical table
    good_label: str
    bad_label: str
    unit: str  # "flows", "requests", "queries", "calls"
    ok: str = "TRUE"  # rows that count at all (flow logs skip NODATA and SKIPDATA)


@dataclass
class Alignment:
    """The two windows that were compared: the same number of minutes from each start."""

    column: str
    before_start: datetime
    before_end: datetime
    after_start: datetime
    after_end: datetime
    minutes: int
    before_full: tuple[datetime, datetime]
    after_full: tuple[datetime, datetime]

    @property
    def trimmed(self) -> str:
        """Which file was cut short to match the other, or ""."""
        if self.before_full[1] > self.before_end:
            return "before"
        if self.after_full[1] > self.after_end:
            return "after"
        return ""

    def where(self, side: str) -> str:
        start, end = (
            (self.before_start, self.before_end)
            if side == "before"
            else (self.after_start, self.after_end)
        )
        return f"{q(self.column)} >= {ts(start)} AND {q(self.column)} < {ts(end)}"


@dataclass
class Change:
    """One thing the cutover changed (or, for a clean check, did not)."""

    id: str
    check: str
    title: str
    verdict: Verdict
    summary: str
    explanation: str
    before: float
    after: float
    unit: str
    tables: list[Table] = field(default_factory=list)
    # WHERE fragments over the canonical table of each file selecting the rows behind the
    # change, already restricted to the aligned window. "" when there are none.
    before_filter: str = ""
    after_filter: str = ""
    # Which file's rows are the evidence to show first.
    evidence: str = "after"
    rows: int = 0

    @property
    def delta(self) -> float:
        return self.after - self.before

    @property
    def change_text(self) -> str:
        return describe_change(self.before, self.after)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "check": self.check,
            "title": self.title,
            "verdict": str(self.verdict),
            "summary": self.summary,
            "explanation": self.explanation,
            "before": self.before,
            "after": self.after,
            "unit": self.unit,
            "rows": self.rows,
            "tables": [{"title": t.title, "rows": t.to_dicts()} for t in self.tables],
        }


def describe_change(before: float, after: float) -> str:
    """ "up 3.2x", "down 40%", "unchanged", "new", "gone"."""
    if before == after:
        return "unchanged"
    if before == 0:
        return "new"
    if after == 0:
        return "gone"
    ratio = after / before
    if ratio >= 2:
        return f"up {ratio:.1f}x"
    if ratio >= 1:
        return f"up {100 * (ratio - 1):.0f}%"
    return f"down {100 * (1 - ratio):.0f}%"


def pct(n: float, of: float) -> str:
    return f"{100.0 * n / of:.1f}%" if of else "0%"


@dataclass
class DiffContext:
    """Both files' canonical tables, as ``b`` and ``a``, cut to the aligned windows."""

    con: duckdb.DuckDBPyConnection
    table: str
    columns: set[str]
    align: Alignment
    health: Health | None

    @property
    def minutes(self) -> int:
        return self.align.minutes

    def has(self, *cols: str) -> bool:
        return all(c in self.columns for c in cols)

    def sql(self, query: str) -> list[tuple[Any, ...]]:
        return self.con.execute(query).fetchall()

    def one(self, query: str) -> tuple[Any, ...]:
        row = self.con.execute(query).fetchone()
        return row if row is not None else ()

    def count(self, side: str, where: str = "TRUE") -> int:
        return int(self.one(f"SELECT count(*) FROM {side_table(side)} WHERE {where}")[0])

    def window(self, side: str) -> str:
        return self.align.where(side)

    def per_minute(self, n: float) -> float:
        return n / max(1, self.minutes)


def side_table(side: str) -> str:
    return "b" if side == "before" else "a"


def minutes_between(first: datetime, last: datetime) -> int:
    return max(1, int((last - first).total_seconds() // 60) + 1)


def end_of(start: datetime, minutes: int) -> datetime:
    return start + timedelta(minutes=minutes)
