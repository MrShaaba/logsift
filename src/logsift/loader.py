"""Sniff a delimited file and load it into DuckDB.

The loader never trusts DuckDB's own dialect sniffer: it works out the delimiter and
header itself from the first few kilobytes, loads every column as text with explicit
column names, then infers a type per column and casts. Anything that does not fit is
counted and reported as a warning instead of failing the whole load.
"""

from __future__ import annotations

import csv
import gzip
import io
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

import duckdb

SAMPLE_BYTES = 256 * 1024
SAMPLE_LINES = 200
DELIMITERS: dict[str, str] = {
    ",": "comma",
    "\t": "tab",
    ";": "semicolon",
    "|": "pipe",
    " ": "space",
}
CAST_THRESHOLD = 0.995
INFER_SAMPLE_ROWS = 50_000

NUMERIC_RE = re.compile(r"^[-+]?(\d+\.?\d*|\.\d+)([eE][-+]?\d+)?$")
LEADING_ZERO_RE = re.compile(r"^0\d+$")
DATE_LIKE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2})?")


@dataclass
class Sniff:
    """What the first few kilobytes of a file look like."""

    delimiter: str
    has_header: bool
    columns: list[str]
    rows: list[list[str]] = field(default_factory=list)
    gzip: bool = False
    bom: bool = False
    field_counts: Counter[int] = field(default_factory=Counter)

    @property
    def delimiter_name(self) -> str:
        return DELIMITERS.get(self.delimiter, repr(self.delimiter))


@dataclass
class ColumnType:
    name: str
    sql_type: str
    bad_values: int = 0


@dataclass
class LoadResult:
    table: str
    rows: int
    columns: list[ColumnType]
    rejected_lines: int
    warnings: list[str]
    notes: list[str]


def is_gzip(path: Path) -> bool:
    with path.open("rb") as fh:
        return fh.read(2) == b"\x1f\x8b"


def open_text(path: Path) -> IO[str]:
    """Open a possibly gzipped file as UTF-8 text, dropping a byte order mark."""
    raw: IO[bytes] = gzip.open(path, "rb") if is_gzip(path) else path.open("rb")  # noqa: SIM115
    return io.TextIOWrapper(raw, encoding="utf-8-sig", errors="replace", newline="")


def _head_lines(path: Path) -> tuple[list[str], bool]:
    with open_text(path) as fh:
        head = fh.read(SAMPLE_BYTES)
    complete = len(head) < SAMPLE_BYTES
    lines = head.splitlines()
    if not complete and lines:
        lines = lines[:-1]  # the last line may be cut mid-way
    lines = [ln for ln in lines if ln.strip()]
    return lines[:SAMPLE_LINES], complete


def _parse(lines: list[str], delimiter: str) -> list[list[str]]:
    reader = csv.reader(lines, delimiter=delimiter, quotechar='"', doublequote=True)
    return [row for row in reader if row]


def detect_delimiter(lines: list[str]) -> tuple[str, Counter[int]]:
    """Pick the delimiter that splits the sample into the most consistent field count."""
    best: tuple[float, int, int, str] | None = None
    best_counts: Counter[int] = Counter()
    for order, delim in enumerate(DELIMITERS):
        try:
            rows = _parse(lines, delim)
        except csv.Error:
            continue
        counts = Counter(len(r) for r in rows)
        if not counts:
            continue
        fields, hits = counts.most_common(1)[0]
        if fields < 2:
            continue
        consistency = hits / len(rows)
        if consistency < 0.5:
            continue
        # Higher consistency wins; then more fields; then the earlier candidate in the list.
        key = (round(consistency, 2), fields, -order, delim)
        if best is None or key > best:
            best, best_counts = key, counts
    if best is None:
        return ",", Counter({1: len(lines)})
    return best[3], best_counts


def _looks_numeric(value: str) -> bool:
    return bool(NUMERIC_RE.match(value.strip()))


def detect_header(rows: list[list[str]]) -> bool:
    """Decide whether the first parsed row is a header line."""
    if not rows:
        return False
    first = rows[0]
    if any(cell.startswith("@") for cell in first):
        return True
    if len(rows) == 1:
        return not any(_looks_numeric(c) for c in first)
    body = rows[1:]
    votes = 0
    for i, cell in enumerate(first):
        column = [r[i] for r in body if i < len(r) and r[i].strip()]
        if not column:
            continue
        numeric_share = sum(_looks_numeric(c) for c in column) / len(column)
        if numeric_share > 0.8:
            votes += -1 if _looks_numeric(cell) else 1
    if votes != 0:
        return votes > 0
    # All-text file: a header has distinct, non-empty, reasonably short names.
    cells = [c.strip() for c in first]
    return all(cells) and len(set(cells)) == len(cells) and all(len(c) <= 64 for c in cells)


def _clean_name(name: str, index: int, seen: set[str]) -> str:
    base = name.strip().strip('"') or f"column_{index + 1}"
    candidate = base
    n = 2
    while candidate in seen:
        candidate = f"{base}_{n}"
        n += 1
    seen.add(candidate)
    return candidate


def sniff(path: Path) -> Sniff:
    path = Path(path)
    gz = is_gzip(path)
    with gzip.open(path, "rb") if gz else path.open("rb") as fh:
        bom = fh.read(3) == b"\xef\xbb\xbf"
    lines, _ = _head_lines(path)
    delimiter, counts = detect_delimiter(lines)
    rows = _parse(lines, delimiter) if lines else []
    width = counts.most_common(1)[0][0] if counts else 1
    has_header = detect_header(rows)
    seen: set[str] = set()
    if has_header and rows:
        columns = [_clean_name(c, i, seen) for i, c in enumerate(rows[0])]
        width = max(width, len(columns))
        columns += [_clean_name("", i, seen) for i in range(len(columns), width)]
        body = rows[1:]
    else:
        columns = [_clean_name("", i, seen) for i in range(width)]
        body = rows
    return Sniff(
        delimiter=delimiter,
        has_header=has_header,
        columns=columns,
        rows=body[:50],
        gzip=gz,
        bom=bom,
        field_counts=counts,
    )


def _q(ident: str) -> str:
    return '"' + ident.replace('"', '""') + '"'


def _lit(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def load_text(
    con: duckdb.DuckDBPyConnection,
    path: Path,
    sn: Sniff,
    table: str = "raw_text",
    null_strings: tuple[str, ...] = ("",),
) -> int:
    """Load every column as VARCHAR into ``table``. Returns the number of rejected lines."""
    cols = ", ".join(f"{_lit(c)}: 'VARCHAR'" for c in sn.columns)
    nulls = ", ".join(_lit(n) for n in null_strings)
    con.execute(f"DROP TABLE IF EXISTS {_q(table)}")
    con.execute(
        f"""
        CREATE TABLE {_q(table)} AS
        SELECT * FROM read_csv(
            {_lit(str(path))},
            delim={_lit(sn.delimiter)},
            header={"true" if sn.has_header else "false"},
            columns={{{cols}}},
            auto_detect=false,
            quote='"',
            escape='"',
            nullstr=[{nulls}],
            null_padding=true,
            ignore_errors=true,
            store_rejects=true
        )
        """
    )
    return con.execute("SELECT count(*) FROM reject_errors").fetchone()[0]  # type: ignore[index]


INT_RE = "^[-+]?[0-9]+$"
DATE_RE = "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"
BOOL_WORDS = ("true", "false", "t", "f", "yes", "no", "y", "n")


def infer_types(con: duckdb.DuckDBPyConnection, table: str, columns: list[str]) -> list[ColumnType]:
    """Infer one SQL type per column from a sample of non-null values.

    DuckDB will happily cast "7.50" to an integer and a full timestamp to a date, so
    integers and dates are checked against a pattern as well as a cast.
    """
    if not columns:
        return []
    bools = ", ".join(_lit(b) for b in BOOL_WORDS)
    exprs: list[str] = []
    for c in columns:
        q = _q(c)
        exprs += [
            f"count({q})",
            f"count(*) FILTER (WHERE regexp_matches(trim({q}), {_lit(INT_RE)}))",
            f"count(try_cast({q} AS DOUBLE))",
            f"count(*) FILTER (WHERE regexp_matches(trim({q}), {_lit(DATE_RE)}) "
            f"AND try_cast({q} AS DATE) IS NOT NULL)",
            f"count(try_cast({q} AS TIMESTAMP))",
            f"count(*) FILTER (WHERE regexp_matches(trim({q}), '^0[0-9]+$'))",
            f"count(*) FILTER (WHERE lower(trim({q})) IN ({bools}))",
        ]
    sql = (
        f"SELECT {', '.join(exprs)} FROM (SELECT * FROM {_q(table)} "
        f"USING SAMPLE reservoir({INFER_SAMPLE_ROWS} ROWS) REPEATABLE (7))"
    )
    row = con.execute(sql).fetchone() or ()
    per_col = 7
    result: list[ColumnType] = []
    for i, c in enumerate(columns):
        total, ints, doubles, dates, stamps, leading_zero, boolish = row[
            i * per_col : (i + 1) * per_col
        ]
        result.append(
            ColumnType(c, _pick_type(total, ints, doubles, dates, stamps, leading_zero, boolish))
        )
    return result


def _pick_type(
    total: int, ints: int, doubles: int, dates: int, stamps: int, leading_zero: int, boolish: int
) -> str:
    if total == 0:
        return "VARCHAR"

    def ok(n: int) -> bool:
        return n / total >= CAST_THRESHOLD

    if ok(boolish) and ints == 0:
        return "BOOLEAN"
    if leading_zero == 0:
        if ok(ints):
            return "BIGINT"
        if ok(doubles):
            return "DOUBLE"
    if ok(dates):
        return "DATE"
    if ok(stamps):
        return "TIMESTAMP"
    return "VARCHAR"


def materialise(
    con: duckdb.DuckDBPyConnection,
    source: str,
    target: str,
    types: list[ColumnType],
) -> None:
    """Create ``target`` from ``source`` with each column cast to its inferred type."""
    selects: list[str] = []
    for t in types:
        q = _q(t.name)
        if t.sql_type == "VARCHAR":
            selects.append(q)
        elif t.sql_type == "BOOLEAN":
            selects.append(
                f"CASE lower(trim({q})) WHEN 'true' THEN true WHEN 't' THEN true "
                f"WHEN 'yes' THEN true WHEN 'y' THEN true WHEN 'false' THEN false "
                f"WHEN 'f' THEN false WHEN 'no' THEN false WHEN 'n' THEN false END AS {q}"
            )
        else:
            selects.append(f"try_cast({q} AS {t.sql_type}) AS {q}")
    con.execute(f"DROP TABLE IF EXISTS {_q(target)}")
    con.execute(f"CREATE TABLE {_q(target)} AS SELECT {', '.join(selects)} FROM {_q(source)}")
    # Count values that were present but could not be read as the chosen type.
    checks = [
        f"count(*) FILTER (WHERE s.{_q(t.name)} IS NOT NULL AND t.{_q(t.name)} IS NULL)"
        for t in types
        if t.sql_type != "VARCHAR"
    ]
    if checks:
        sql = (
            f"SELECT {', '.join(checks)} FROM (SELECT row_number() OVER () AS rn, * "
            f"FROM {_q(source)}) s JOIN (SELECT row_number() OVER () AS rn, * "
            f"FROM {_q(target)}) t USING (rn)"
        )
        counts = con.execute(sql).fetchone() or ()
        typed = [t for t in types if t.sql_type != "VARCHAR"]
        for t, n in zip(typed, counts, strict=True):
            t.bad_values = int(n)


def load(
    con: duckdb.DuckDBPyConnection,
    path: Path,
    sn: Sniff | None = None,
    *,
    table: str = "raw",
    null_strings: tuple[str, ...] = ("",),
) -> LoadResult:
    """Sniff (if needed), load as text, infer types, and materialise a typed table."""
    path = Path(path)
    sn = sn or sniff(path)
    warnings: list[str] = []
    notes: list[str] = []
    if sn.gzip:
        notes.append("File is gzip compressed and was decompressed on the fly.")
    if sn.bom:
        notes.append("File starts with a UTF-8 byte order mark, which was ignored.")
    if not sn.has_header:
        notes.append("No header row detected, so columns are named column_1, column_2 and so on.")
    if len(sn.field_counts) > 1:
        common = sn.field_counts.most_common(1)[0][0]
        odd = sum(n for k, n in sn.field_counts.items() if k != common)
        warnings.append(
            f"{odd} of the first {sum(sn.field_counts.values())} lines do not have "
            f"{common} fields like the rest."
        )

    rejected = load_text(con, path, sn, table="raw_text", null_strings=null_strings)
    if rejected:
        examples = con.execute(
            "SELECT line, error_type, csv_line FROM reject_errors ORDER BY line LIMIT 3"
        ).fetchall()
        shown = "; ".join(f"line {ln}: {err.lower()} ({text[:60]})" for ln, err, text in examples)
        warnings.append(f"{rejected} lines could not be parsed and were skipped. {shown}")

    types = infer_types(con, "raw_text", sn.columns)
    materialise(con, "raw_text", table, types)
    con.execute('DROP TABLE "raw_text"')
    for t in types:
        if t.bad_values:
            warnings.append(
                f"Column {t.name}: {t.bad_values} values could not be read as "
                f"{t.sql_type.lower()} and were left blank."
            )
    rows = con.execute(f"SELECT count(*) FROM {_q(table)}").fetchone()[0]  # type: ignore[index]
    return LoadResult(table, int(rows), types, rejected, warnings, notes)
