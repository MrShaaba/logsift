"""Compare a "before" and an "after" file of the same format: the cutover validator.

Both files are loaded as datasets, their canonical tables are copied into one in-memory
database cut to the same number of minutes from each file's first record, the format's
plug-in runs its cutover checks over the pair, and the result is a report with one
verdict per change and one overall: clean, review or regression.
"""

from __future__ import annotations

import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import duckdb

from logsift.cutover import (
    VERDICT_ORDER,
    Alignment,
    Change,
    DiffContext,
    Health,
    Verdict,
    describe_change,
    end_of,
    minutes_between,
    pct,
    side_table,
    worst,
)
from logsift.dataset import Dataset
from logsift.explore import RowQuery, fetch_page
from logsift.insights.base import Table, pick_bucket
from logsift.sql import q

EVIDENCE_ROWS = 25
VOLUME_REVIEW = 0.5  # rows per minute changed by half or more
BAD_SHARE_REVIEW = 1.25  # the bad share grew by a quarter
BAD_SHARE_REGRESSION = 2.0  # ... or doubled, with at least this many bad rows after
BAD_MIN_ROWS = 20


class DiffError(ValueError):
    """The two files cannot be compared."""


@dataclass
class SampleRows:
    columns: list[str]
    rows: list[tuple[Any, ...]]
    total: int


@dataclass
class CutoverReport:
    before: Dataset
    after: Dataset
    alignment: Alignment
    changes: list[Change]
    health: Health | None
    timeline: dict[str, Any] | None = None
    totals: dict[str, int] = field(default_factory=dict)

    @property
    def verdict(self) -> Verdict:
        return worst([c.verdict for c in self.changes])

    @property
    def regressions(self) -> list[Change]:
        return [c for c in self.changes if c.verdict == Verdict.REGRESSION]

    @property
    def reviews(self) -> list[Change]:
        return [c for c in self.changes if c.verdict == Verdict.REVIEW]

    @property
    def clean(self) -> list[Change]:
        return [c for c in self.changes if c.verdict == Verdict.CLEAN]

    def change(self, change_id: str) -> Change | None:
        return next((c for c in self.changes if c.id == change_id), None)

    def evidence(
        self, change: Change, side: str | None = None, limit: int = EVIDENCE_ROWS
    ) -> SampleRows:
        """The first rows behind a change from one file (its evidence side by default)."""
        side = side or change.evidence
        where = change.before_filter if side == "before" else change.after_filter
        ds = self.before if side == "before" else self.after
        if not where:
            return SampleRows([], [], 0)
        page = fetch_page(ds.cursor(), ds.table, RowQuery(where=where), 1, limit)
        return SampleRows(page.columns, page.rows, page.total)

    def to_dict(self) -> dict[str, Any]:
        al = self.alignment
        return {
            "verdict": str(self.verdict),
            "format": self.before.format.label,
            "before": {"name": self.before.name, "rows": self.before.rows, **_span(al.before_full)},
            "after": {"name": self.after.name, "rows": self.after.rows, **_span(al.after_full)},
            "window_minutes": al.minutes,
            "compared": {
                "before": _span((al.before_start, al.before_end)),
                "after": _span((al.after_start, al.after_end)),
                "trimmed": al.trimmed,
            },
            "totals": self.totals,
            "changes": [c.to_dict() for c in self.changes],
        }


def _span(span: tuple[datetime, datetime]) -> dict[str, str]:
    return {"start": span[0].isoformat(sep=" "), "end": span[1].isoformat(sep=" ")}


# ------------------------------------------------------------------- comparing


def compare(before: Dataset, after: Dataset, workdir: Path | str | None = None) -> CutoverReport:
    """Run the format's cutover checks over the two files."""
    if before.format.plugin != after.format.plugin or not before.has_rules or not after.has_rules:
        raise DiffError(
            f"the files are not the same recognised format ({before.format.label} and "
            f"{after.format.label}); a cutover diff needs two files of one format with rules"
        )
    plugin = before.plugin
    column = plugin.time_column
    b_cols = {c for c, _ in before.columns}
    a_cols = {c for c, _ in after.columns}
    if not column or column not in b_cols or column not in a_cols:
        raise DiffError(f"the {before.format.label} format has no time column to align on")
    alignment = align(before, after, column)
    con = duckdb.connect()
    with tempfile.TemporaryDirectory(dir=str(workdir) if workdir else None) as tmp:
        for side, ds in (("before", before), ("after", after)):
            path = Path(tmp) / f"{side}-{uuid.uuid4().hex[:8]}.parquet"
            ds.cursor().execute(
                f"COPY (SELECT * FROM {q(ds.table)} WHERE {alignment.where(side)}) "
                f"TO {_lit_path(path)} (FORMAT PARQUET)"
            )
            con.execute(
                f"CREATE TABLE {side_table(side)} AS SELECT * FROM read_parquet({_lit_path(path)})"
            )
    columns = b_cols & a_cols
    health = plugin.health(columns)
    ctx = DiffContext(con, before.table, columns, alignment, health)
    changes = totals_checks(ctx)
    changes += plugin.cutover_checks(ctx)
    changes.sort(key=lambda c: (-VERDICT_ORDER[c.verdict], -abs(c.delta)))
    report = CutoverReport(before, after, alignment, changes, health)
    report.totals = {
        "before_rows": ctx.count("before"),
        "after_rows": ctx.count("after"),
    }
    report.timeline = timeline(ctx)
    con.close()
    return report


def _lit_path(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def align(before: Dataset, after: Dataset, column: str) -> Alignment:
    """The same number of minutes from each file's first record, whichever is shorter."""
    spans: dict[str, tuple[datetime, datetime]] = {}
    for side, ds in (("before", before), ("after", after)):
        row = (
            ds.cursor()
            .execute(f"SELECT min({q(column)}), max({q(column)}) FROM {q(ds.table)}")
            .fetchone()
        )
        if not row or row[0] is None:
            raise DiffError(f"the {side} file has no values in its {column} column")
        spans[side] = (row[0], row[1])
    minutes = min(minutes_between(*spans["before"]), minutes_between(*spans["after"]))
    return Alignment(
        column=column,
        before_start=spans["before"][0],
        before_end=end_of(spans["before"][0], minutes),
        after_start=spans["after"][0],
        after_end=end_of(spans["after"][0], minutes),
        minutes=minutes,
        before_full=spans["before"],
        after_full=spans["after"],
    )


# ---------------------------------------------------------------- common checks


def totals_checks(ctx: DiffContext) -> list[Change]:
    """Volume and bad-share changes every format gets."""
    h = ctx.health
    unit = h.unit if h else "rows"
    ok = h.ok if h else "TRUE"
    b_rows, a_rows = ctx.count("before", ok), ctx.count("after", ok)
    b_rate, a_rate = ctx.per_minute(b_rows), ctx.per_minute(a_rows)
    changes: list[Change] = []
    ratio = a_rows / b_rows if b_rows else (2.0 if a_rows else 1.0)
    if ratio <= 1 - VOLUME_REVIEW or ratio >= 1 + 2 * VOLUME_REVIEW:
        verdict = Verdict.REVIEW
        note = (
            "A change of this size usually means traffic moved somewhere this file does not "
            "see, the capture changed, or the two windows are not comparable."
        )
    elif abs(ratio - 1) < 0.25:
        verdict = Verdict.CLEAN
        note = "The two windows carry a similar amount of traffic, so the rest compares fairly."
    else:
        verdict = Verdict.CLEAN
        note = (
            "The windows differ in size but not by enough to distrust the comparison; the "
            "checks below compare shares and destinations, not raw totals."
        )
    changes.append(
        Change(
            "volume",
            "volume",
            f"Volume: {a_rate:,.1f} {unit} a minute after, {b_rate:,.1f} before "
            f"({describe_change(b_rows, a_rows)})",
            verdict,
            f"{b_rows:,} {unit} in the before window and {a_rows:,} in the after window, "
            f"{ctx.minutes} minutes each. {note}",
            "Counts are compared over the same number of minutes from each file's first "
            "record, so a longer file is cut to the shorter one's length.",
            b_rows,
            a_rows,
            unit,
            [],
            ctx.window("before"),
            ctx.window("after"),
            rows=a_rows,
        )
    )
    if h is None:
        return changes
    b_bad, a_bad = (
        ctx.count("before", f"({ok}) AND ({h.bad})"),
        ctx.count("after", f"({ok}) AND ({h.bad})"),
    )
    b_share = b_bad / b_rows if b_rows else 0.0
    a_share = a_bad / a_rows if a_rows else 0.0
    growth = a_share / b_share if b_share else (float("inf") if a_share else 1.0)
    if a_bad >= BAD_MIN_ROWS and growth >= BAD_SHARE_REGRESSION:
        verdict = Verdict.REGRESSION
        note = f"The share of {h.bad_label} {unit} doubled or worse; the checks below say where."
    elif a_bad >= BAD_MIN_ROWS and growth >= BAD_SHARE_REVIEW:
        verdict = Verdict.REVIEW
        note = f"More of the traffic is {h.bad_label} than before; the checks below say where."
    elif b_share and a_share <= b_share / 2:
        verdict = Verdict.CLEAN
        note = f"Fewer {h.bad_label} {unit} than before: an improvement."
    else:
        verdict = Verdict.CLEAN
        note = f"About the same share of {h.bad_label} {unit} as before."
    changes.append(
        Change(
            "bad-share",
            "bad_share",
            f"{h.bad_label.capitalize()} {unit}: {pct(a_bad, a_rows)} after, "
            f"{pct(b_bad, b_rows)} before ({describe_change(b_bad, a_bad)})",
            verdict,
            f"{a_bad:,} of {a_rows:,} {unit} were {h.bad_label} after against {b_bad:,} of "
            f"{b_rows:,} before. {note}",
            f"{h.bad_label.capitalize()} against {h.good_label} is the first number to watch "
            "after any change; the per-destination checks say which traffic moved between "
            "the two.",
            b_bad,
            a_bad,
            unit,
            [],
            f"({h.ok}) AND ({h.bad}) AND {ctx.window('before')}",
            f"({h.ok}) AND ({h.bad}) AND {ctx.window('after')}",
            rows=a_bad,
        )
    )
    return changes


def timeline(ctx: DiffContext) -> dict[str, Any] | None:
    """Good against bad per bucket, for both files on a shared "minutes since start" axis."""
    h = ctx.health
    if h is None:
        return None
    name, secs = pick_bucket(ctx.minutes * 60)
    col = q(ctx.align.column)
    series: dict[str, dict[str, list[int]]] = {}
    for side in ("before", "after"):
        start = ctx.align.before_start if side == "before" else ctx.align.after_start
        rows = ctx.sql(
            f"SELECT floor(epoch({col} - {q_ts(start)}) / {secs}) AS slot, "
            f"count(*) FILTER (WHERE ({h.ok}) AND NOT ({h.bad})), "
            f"count(*) FILTER (WHERE ({h.ok}) AND ({h.bad})) "
            f"FROM {side_table(side)} WHERE {col} IS NOT NULL GROUP BY 1 ORDER BY 1"
        )
        by_slot = {int(r[0]): (int(r[1]), int(r[2])) for r in rows}
        n = max(1, -(-ctx.minutes * 60 // secs))
        series[side] = {
            "accepted": [by_slot.get(i, (0, 0))[0] for i in range(n)],
            "rejected": [by_slot.get(i, (0, 0))[1] for i in range(n)],
        }
    n = len(series["before"]["accepted"])
    labels = [_offset_label(i * secs) for i in range(n)]
    return {
        "bucket": name,
        "labels": labels,
        "before": series["before"],
        "after": series["after"],
        "good": h.good_label,
        "bad": h.bad_label,
        "unit": h.unit,
        "title": f"{h.good_label.capitalize()} against {h.bad_label} {h.unit}",
    }


def q_ts(value: datetime) -> str:
    return f"TIMESTAMP '{value.strftime('%Y-%m-%d %H:%M:%S.%f')}'"


def _offset_label(seconds: int) -> str:
    minutes = seconds // 60
    if minutes < 60:
        return f"+{minutes}m"
    hours, rest = divmod(minutes, 60)
    return f"+{hours}h{rest:02d}"


__all__ = [
    "EVIDENCE_ROWS",
    "Change",
    "CutoverReport",
    "DiffError",
    "SampleRows",
    "Table",
    "Verdict",
    "align",
    "compare",
]
