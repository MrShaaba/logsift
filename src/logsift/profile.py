"""Per-column profile and a short plain-English summary of a table."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

import duckdb

from logsift.sql import q

HIST_BINS = 16
TOP_N = 6

KINDS = {
    "BIGINT": "integer",
    "INTEGER": "integer",
    "SMALLINT": "integer",
    "HUGEINT": "integer",
    "DOUBLE": "number",
    "FLOAT": "number",
    "DECIMAL": "number",
    "BOOLEAN": "boolean",
    "DATE": "date",
    "TIMESTAMP": "timestamp",
    "TIMESTAMP WITH TIME ZONE": "timestamp",
}


@dataclass
class ColumnProfile:
    name: str
    sql_type: str
    kind: str
    count: int
    missing: int
    distinct: int
    min: Any = None
    max: Any = None
    mean: float | None = None
    median: float | None = None
    top: list[tuple[str, int]] = field(default_factory=list)
    histogram: list[int] = field(default_factory=list)
    hist_labels: tuple[str, str] = ("", "")

    @property
    def missing_pct(self) -> float:
        total = self.count + self.missing
        return 100.0 * self.missing / total if total else 0.0

    @property
    def missing_label(self) -> str:
        pct = self.missing_pct
        if self.missing == 0:
            return "0%"
        return f"{pct:.0f}%" if pct >= 1 else "<1%"

    @property
    def is_numeric(self) -> bool:
        return self.kind in ("integer", "number")

    @property
    def is_temporal(self) -> bool:
        return self.kind in ("date", "timestamp")


@dataclass
class Profile:
    table: str
    rows: int
    columns: list[ColumnProfile]
    summary: list[str]


def _kind(sql_type: str) -> str:
    base = sql_type.split("(")[0].upper()
    return KINDS.get(base, "text")


def fmt_value(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, float):
        return f"{v:,.2f}".rstrip("0").rstrip(".") if abs(v) < 1e15 else f"{v:.3g}"
    if isinstance(v, int):
        return f"{v:,}"
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(v, date):
        return v.isoformat()
    return str(v)


def profile_column(
    con: duckdb.DuckDBPyConnection, table: str, name: str, sql_type: str, rows: int
) -> ColumnProfile:
    kind = _kind(sql_type)
    col = q(name)
    base = f"SELECT count({col}), count(*) - count({col}), count(DISTINCT {col}) FROM {q(table)}"
    count, missing, distinct = con.execute(base).fetchone()  # type: ignore[misc]
    prof = ColumnProfile(name, sql_type, kind, int(count), int(missing), int(distinct))
    if count == 0:
        return prof

    if kind in ("integer", "number"):
        mn, mx, mean, median = con.execute(
            f"SELECT min({col}), max({col}), avg({col}), quantile_cont({col}, 0.5) FROM {q(table)}"
        ).fetchone()  # type: ignore[misc]
        prof.min, prof.max = mn, mx
        prof.mean = float(mean) if mean is not None else None
        prof.median = float(median) if median is not None else None
        prof.histogram = _numeric_histogram(con, table, col, float(mn), float(mx))
        prof.hist_labels = (fmt_value(mn), fmt_value(mx))
    elif kind in ("date", "timestamp"):
        mn, mx = con.execute(f"SELECT min({col}), max({col}) FROM {q(table)}").fetchone()  # type: ignore[misc]
        prof.min, prof.max = mn, mx
        epoch = f"epoch({col})"
        lo, hi = con.execute(f"SELECT min({epoch}), max({epoch}) FROM {q(table)}").fetchone()  # type: ignore[misc]
        prof.histogram = _numeric_histogram(con, table, epoch, float(lo), float(hi))
        prof.hist_labels = (fmt_value(mn), fmt_value(mx))
    elif kind == "boolean":
        t, f = con.execute(
            f"SELECT count(*) FILTER (WHERE {col}), count(*) FILTER (WHERE NOT {col}) "
            f"FROM {q(table)}"
        ).fetchone()  # type: ignore[misc]
        prof.top = [("true", int(t)), ("false", int(f))]
        prof.histogram = [int(t), int(f)]

    if kind != "boolean":
        top = con.execute(
            f"SELECT {col}, count(*) AS n FROM {q(table)} WHERE {col} IS NOT NULL "
            f"GROUP BY 1 ORDER BY n DESC, 1 LIMIT {TOP_N}"
        ).fetchall()
        prof.top = [(fmt_value(v), int(n)) for v, n in top]
        if kind == "text":
            prof.histogram = [int(n) for _, n in top]
            if prof.min is None:
                lens = con.execute(
                    f"SELECT min(length({col})), max(length({col})) FROM {q(table)}"
                ).fetchone()
                if lens:
                    prof.min, prof.max = lens
    return prof


def _numeric_histogram(
    con: duckdb.DuckDBPyConnection, table: str, expr: str, lo: float, hi: float
) -> list[int]:
    if hi <= lo:
        n = con.execute(f"SELECT count({expr}) FROM {q(table)}").fetchone()
        return [int(n[0]) if n else 0]
    sql = (
        f"SELECT least(floor(({expr} - {lo!r}) / ({hi!r} - {lo!r}) * {HIST_BINS}), "
        f"{HIST_BINS - 1})::INTEGER AS b, count(*) FROM {q(table)} "
        f"WHERE {expr} IS NOT NULL GROUP BY b"
    )
    counts = dict(con.execute(sql).fetchall())
    return [int(counts.get(i, 0)) for i in range(HIST_BINS)]


def profile_table(con: duckdb.DuckDBPyConnection, table: str) -> Profile:
    cols = [(r[0], r[1]) for r in con.execute(f"DESCRIBE {q(table)}").fetchall()]
    rows = int(con.execute(f"SELECT count(*) FROM {q(table)}").fetchone()[0])  # type: ignore[index]
    profiles = [profile_column(con, table, n, t, rows) for n, t in cols if n != "row_no"]
    return Profile(table, rows, profiles, summarise(rows, profiles))


def summarise(rows: int, cols: list[ColumnProfile]) -> list[str]:
    """A few plain sentences describing the shape of the table."""
    out: list[str] = []
    by_kind: dict[str, list[str]] = {}
    for c in cols:
        by_kind.setdefault(c.kind, []).append(c.name)
    kinds = ", ".join(f"{len(names)} {kind}" for kind, names in by_kind.items())
    out.append(f"{rows:,} rows and {len(cols)} columns ({kinds}).")

    temporal = [c for c in cols if c.is_temporal and c.min is not None]
    if temporal:
        c = temporal[0]
        out.append(f"{c.name} runs from {fmt_value(c.min)} to {fmt_value(c.max)}.")

    ids = [c.name for c in cols if rows > 1 and c.distinct == rows and c.missing == 0]
    if ids:
        out.append(f"{_join(ids)} {'is' if len(ids) == 1 else 'are'} unique per row, like an id.")

    cats = [c for c in cols if c.kind == "text" and 1 < c.distinct <= 12 and c.count > 0]
    if cats:
        bits = [f"{c.name} ({c.distinct} values)" for c in cats[:4]]
        out.append(f"Low-cardinality text columns that work as categories: {_join(bits)}.")

    missing = sorted((c for c in cols if c.missing), key=lambda c: -c.missing)
    if missing:
        bits = [f"{c.name} ({c.missing_label})" for c in missing[:3]]
        out.append(f"Most missing values: {_join(bits)}.")
    else:
        out.append("No missing values.")

    constant = [c.name for c in cols if c.distinct == 1 and c.count == rows and rows > 1]
    if constant:
        out.append(f"{_join(constant)} never {'changes' if len(constant) == 1 else 'change'}.")
    return out


def _join(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]
