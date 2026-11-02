"""Sniff a delimited file and stream it into DuckDB.

The loader never trusts DuckDB's own dialect sniffer: it works out the delimiter and
header itself from the first few kilobytes, infers a type per column from the first
chunk, then streams the file through DuckDB chunk by chunk, casting as it goes. A chunk
is a few megabytes of whole lines staged in a temporary file, so a file far larger than
memory loads in bounded memory, progress (rows and bytes) is reported after every chunk,
and a load can stop after the first N rows and be resumed later from the same offset.
Anything that does not fit its type is counted and reported as a warning instead of
failing the whole load.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import re
import tempfile
import uuid
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

import duckdb

from logsift.sql import lit, q

SAMPLE_BYTES = 256 * 1024
SAMPLE_LINES = 200
DELIMITERS: dict[str, str] = {
    ",": "comma",
    "\t": "tab",
    ";": "semicolon",
    "|": "pipe",
    " ": "space",
}
# A JSON-lines file is read as one text column per line; this byte never occurs in JSON.
JSON_LINES_DELIMITER = "\x01"
JSON_LINES_COLUMN = "line"
CAST_THRESHOLD = 0.995
INFER_SAMPLE_ROWS = 50_000
# Whole lines are read in chunks of about this many bytes and staged in a temp file.
CHUNK_BYTES = 16 * 1024 * 1024
REJECT_EXAMPLES = 3

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
    # One JSON object per line: loaded as a single text column named "line".
    json_lines: bool = False

    @property
    def delimiter_name(self) -> str:
        return DELIMITERS.get(self.delimiter, repr(self.delimiter))

    @property
    def layout(self) -> str:
        """How the file is laid out, for the UI: "comma-delimited" or "JSON lines"."""
        return "JSON lines" if self.json_lines else f"{self.delimiter_name}-delimited"


@dataclass
class ColumnType:
    name: str
    sql_type: str
    bad_values: int = 0


@dataclass
class LoadProgress:
    """How far a load has got, reported after every chunk."""

    rows: int = 0
    bytes_read: int = 0
    total_bytes: int = 0
    # reading | building | ready | failed
    phase: str = "reading"
    error: str = ""

    @property
    def fraction(self) -> float:
        if self.phase == "ready":
            return 1.0
        if not self.total_bytes:
            return 0.0
        return min(1.0, self.bytes_read / self.total_bytes)


ProgressFn = Callable[[LoadProgress], None]


@dataclass
class LoadResult:
    table: str
    rows: int
    columns: list[ColumnType]
    rejected_lines: int
    warnings: list[str]
    notes: list[str]
    # Where the stream stopped: uncompressed bytes into the file, lines after the header,
    # and bytes of the file on disk consumed (compressed size for gzip).
    offset: int = 0
    lines: int = 0
    bytes_read: int = 0
    # False when a row limit stopped the load before the end of the file.
    complete: bool = True
    sniff_warnings: list[str] = field(default_factory=list)
    reject_examples: list[tuple[int, str, str]] = field(default_factory=list)

    def refresh_warnings(self) -> None:
        """Rebuild ``warnings`` from the counts, after each pass over the file."""
        out = list(self.sniff_warnings)
        if self.rejected_lines:
            shown = "; ".join(
                f"line {ln}: {err.lower()} ({text[:60]})" for ln, err, text in self.reject_examples
            )
            out.append(f"{self.rejected_lines} lines could not be parsed and were skipped. {shown}")
        for t in self.columns:
            if t.bad_values:
                out.append(
                    f"Column {t.name}: {t.bad_values} values could not be read as "
                    f"{t.sql_type.lower()} and were left blank."
                )
        self.warnings = out


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


def looks_like_json_lines(lines: list[str]) -> bool:
    """True when nearly every sampled line is a JSON object on its own."""
    if not lines:
        return False
    shaped = [ln.lstrip().startswith("{") and ln.rstrip().endswith("}") for ln in lines]
    if sum(shaped) / len(lines) < 0.8:
        return False
    try:
        return all(isinstance(json.loads(ln), dict) for ln in lines if ln.lstrip().startswith("{"))
    except ValueError:
        return False


def sniff(path: Path) -> Sniff:
    path = Path(path)
    gz = is_gzip(path)
    with gzip.open(path, "rb") if gz else path.open("rb") as fh:
        bom = fh.read(3) == b"\xef\xbb\xbf"
    lines, _ = _head_lines(path)
    if looks_like_json_lines(lines):
        return Sniff(
            delimiter=JSON_LINES_DELIMITER,
            has_header=False,
            columns=[JSON_LINES_COLUMN],
            rows=[[ln] for ln in lines[:50]],
            gzip=gz,
            bom=bom,
            field_counts=Counter({1: len(lines)}),
            json_lines=True,
        )
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
    bools = ", ".join(lit(b) for b in BOOL_WORDS)
    exprs: list[str] = []
    for c in columns:
        qc = q(c)
        exprs += [
            f"count({qc})",
            f"count(*) FILTER (WHERE regexp_matches(trim({qc}), {lit(INT_RE)}))",
            f"count(try_cast({qc} AS DOUBLE))",
            f"count(*) FILTER (WHERE regexp_matches(trim({qc}), {lit(DATE_RE)}) "
            f"AND try_cast({qc} AS DATE) IS NOT NULL)",
            f"count(try_cast({qc} AS TIMESTAMP))",
            f"count(*) FILTER (WHERE regexp_matches(trim({qc}), '^0[0-9]+$'))",
            f"count(*) FILTER (WHERE lower(trim({qc})) IN ({bools}))",
        ]
    sql = (
        f"SELECT {', '.join(exprs)} FROM (SELECT * FROM {q(table)} "
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


def cast_expr(t: ColumnType) -> str:
    """The expression that reads the text column ``t.name`` as its inferred type."""
    qc = q(t.name)
    if t.sql_type == "VARCHAR":
        return qc
    if t.sql_type == "BOOLEAN":
        return (
            f"CASE lower(trim({qc})) WHEN 'true' THEN true WHEN 't' THEN true "
            f"WHEN 'yes' THEN true WHEN 'y' THEN true WHEN 'false' THEN false "
            f"WHEN 'f' THEN false WHEN 'no' THEN false WHEN 'n' THEN false END"
        )
    return f"try_cast({qc} AS {t.sql_type})"


# ------------------------------------------------------------------ streaming


class ChunkReader:
    """Read a possibly gzipped file as chunks of whole lines, resumable by byte offset.

    ``offset`` counts uncompressed bytes from the start of the file, so a later reader can
    pick up exactly where this one stopped. ``bytes_read`` is how much of the file on disk
    has been consumed, for progress reporting.
    """

    def __init__(
        self, path: Path, sn: Sniff, offset: int = 0, chunk_bytes: int = CHUNK_BYTES
    ) -> None:
        self.size = path.stat().st_size
        self.chunk_bytes = chunk_bytes
        self.raw = path.open("rb")
        self.fh: IO[bytes] = gzip.GzipFile(fileobj=self.raw) if sn.gzip else self.raw
        self.gzip = sn.gzip
        # JSON strings may hold escaped quotes, and a line is always one record there.
        self.balance_quotes = not sn.json_lines
        self.truncated = False
        if offset:
            self.fh.seek(offset)
        else:
            if sn.bom:
                self.fh.read(3)
            if sn.has_header:
                self.fh.readline()
            offset = self.fh.tell()
        self.offset = offset

    def read(self, max_lines: int | None = None) -> list[bytes]:
        """The next chunk of lines, at most ``max_lines`` of them; empty at the end."""
        lines = self.fh.readlines(self.chunk_bytes)
        # Never split a quoted field that spans lines across two chunks.
        while lines and self.balance_quotes and _odd_quotes(lines):
            more = self.fh.readline()
            if not more:
                break
            lines.append(more)
        if max_lines is not None and len(lines) > max_lines:
            keep = max_lines
            while keep < len(lines) and self.balance_quotes and _odd_quotes(lines[:keep]):
                keep += 1
            lines = lines[:keep]
            self.offset += sum(len(ln) for ln in lines)
            self.fh.seek(self.offset)
            self.truncated = True
            return lines
        self.offset += sum(len(ln) for ln in lines)
        return lines

    def at_end(self) -> bool:
        return not self.fh.peek(1)  # type: ignore[attr-defined]

    @property
    def bytes_read(self) -> int:
        pos = self.raw.tell() if self.gzip else self.offset
        return min(pos, self.size)

    def close(self) -> None:
        if self.gzip:
            self.fh.close()
        self.raw.close()


def _odd_quotes(lines: list[bytes]) -> bool:
    return sum(ln.count(b'"') for ln in lines) % 2 == 1


def read_csv_sql(
    path: Path, sn: Sniff, null_strings: tuple[str, ...], *, parallel: bool = True
) -> str:
    """A ``read_csv`` call that reads ``path`` as text columns named after the sniff.

    DuckDB's parallel reader cannot pad short lines when a quoted field spans lines, so a
    chunk holding such a field is read serially.
    """
    cols = ", ".join(f"{lit(c)}: 'VARCHAR'" for c in sn.columns)
    nulls = ", ".join(lit(n) for n in null_strings)
    quoting = "quote='', escape=''" if sn.json_lines else "quote='\"', escape='\"'"
    return (
        f"read_csv({lit(str(path))}, delim={lit(sn.delimiter)}, header=false, "
        f"columns={{{cols}}}, auto_detect=false, {quoting}, nullstr=[{nulls}], "
        f"null_padding=true, ignore_errors=true, store_rejects=true, "
        f"parallel={'true' if parallel else 'false'})"
    )


# DuckDB would otherwise move the casts into the CSV reader, where a value that does not
# fit rejects the whole line instead of being left blank and counted.
PUSHDOWN_OPTIMIZERS = "type_pushdown,scalar_fn_pushdown"


def _create_table(
    con: duckdb.DuckDBPyConnection, res: LoadResult, sn: Sniff, source: str | None
) -> None:
    """Infer the column types from the first chunk and create the empty typed table."""
    if source is None:
        res.columns = [ColumnType(c, "VARCHAR") for c in sn.columns]
    else:
        con.execute(f"CREATE TEMP TABLE head AS SELECT * FROM {source} LIMIT {INFER_SAMPLE_ROWS}")
        res.columns = infer_types(con, "head", sn.columns)
        con.execute("DROP TABLE head")
    decl = ", ".join(f"{q(t.name)} {t.sql_type}" for t in res.columns)
    con.execute(f"CREATE TABLE {q(res.table)} ({decl})")


def _collect_rejects(con: duckdb.DuckDBPyConnection, res: LoadResult, first_line: int) -> None:
    # Each chunk is scanned more than once (types, insert, bad-value counts) and every
    # scan records the same rejects, so count each line once.
    rows = con.execute(
        "SELECT DISTINCT line, error_type, csv_line FROM reject_errors ORDER BY line"
    ).fetchall()
    if not rows:
        return
    res.rejected_lines += len(rows)
    for ln, err, text in rows:
        if len(res.reject_examples) >= REJECT_EXAMPLES:
            break
        res.reject_examples.append((first_line + int(ln) - 1, str(err), str(text or "")))
    con.execute("DELETE FROM reject_errors")


def _stream(
    con: duckdb.DuckDBPyConnection,
    path: Path,
    sn: Sniff,
    res: LoadResult,
    *,
    null_strings: tuple[str, ...],
    limit: int | None,
    progress: ProgressFn | None,
    chunk_bytes: int,
    workdir: Path | None,
) -> None:
    """Append rows to ``res.table`` from ``res.offset`` until the end of the file or ``limit``."""
    reader = ChunkReader(path, sn, res.offset, chunk_bytes)
    prog = LoadProgress(rows=res.rows, bytes_read=reader.bytes_read, total_bytes=reader.size)
    chunk = Path(workdir or tempfile.gettempdir()) / f"logsift-{uuid.uuid4().hex[:12]}.part"
    header_lines = 1 if sn.has_header else 0
    con.execute(f"SET disabled_optimizers = {lit(PUSHDOWN_OPTIMIZERS)}")
    try:
        while True:
            remaining = None if limit is None else max(0, limit - res.rows)
            if remaining == 0:
                res.complete = reader.at_end()
                break
            lines = reader.read(remaining)
            if not lines:
                if not res.columns:
                    _create_table(con, res, sn, None)
                res.complete = True
                break
            chunk.write_bytes(b"".join(lines))
            multiline = any(ln.count(b'"') % 2 for ln in lines)
            source = read_csv_sql(chunk, sn, null_strings, parallel=not multiline)
            if not res.columns:
                _create_table(con, res, sn, source)
            casts = ", ".join(cast_expr(t) for t in res.columns)
            inserted = con.execute(f"INSERT INTO {q(res.table)} SELECT {casts} FROM {source}")
            res.rows += int((inserted.fetchone() or (0,))[0])
            typed = [t for t in res.columns if t.sql_type != "VARCHAR"]
            if typed:
                checks = ", ".join(
                    f"count(*) FILTER (WHERE {q(t.name)} IS NOT NULL AND {cast_expr(t)} IS NULL)"
                    for t in typed
                )
                counts = con.execute(f"SELECT {checks} FROM {source}").fetchone() or ()
                for t, n in zip(typed, counts, strict=True):
                    t.bad_values += int(n)
            _collect_rejects(con, res, header_lines + res.lines + 1)
            res.lines += len(lines)
            res.offset = reader.offset
            res.bytes_read = reader.bytes_read
            prog.rows, prog.bytes_read = res.rows, res.bytes_read
            if progress:
                progress(prog)
            if reader.truncated:
                res.complete = False
                break
        if res.complete:
            res.bytes_read = reader.size
            prog.bytes_read = reader.size
            if progress:
                progress(prog)
    finally:
        con.execute("RESET disabled_optimizers")
        chunk.unlink(missing_ok=True)
        reader.close()
    res.refresh_warnings()


def load(
    con: duckdb.DuckDBPyConnection,
    path: Path,
    sn: Sniff | None = None,
    *,
    table: str = "raw",
    null_strings: tuple[str, ...] = ("",),
    limit: int | None = None,
    progress: ProgressFn | None = None,
    chunk_bytes: int = CHUNK_BYTES,
    workdir: Path | None = None,
) -> LoadResult:
    """Sniff (if needed), then stream the file into a typed table chunk by chunk.

    With ``limit`` the load stops after about that many rows and ``complete`` is False;
    :func:`load_more` picks it up again from the same place.
    """
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
    res = LoadResult(table, 0, [], 0, [], notes, sniff_warnings=warnings)
    con.execute(f"DROP TABLE IF EXISTS {q(table)}")
    _stream(
        con,
        path,
        sn,
        res,
        null_strings=null_strings,
        limit=limit,
        progress=progress,
        chunk_bytes=chunk_bytes,
        workdir=workdir,
    )
    return res


def load_more(
    con: duckdb.DuckDBPyConnection,
    path: Path,
    sn: Sniff,
    res: LoadResult,
    *,
    null_strings: tuple[str, ...] = ("",),
    limit: int | None = None,
    progress: ProgressFn | None = None,
    chunk_bytes: int = CHUNK_BYTES,
    workdir: Path | None = None,
) -> LoadResult:
    """Continue a load that stopped at a row limit, appending to the same table."""
    if res.complete:
        return res
    _stream(
        con,
        Path(path),
        sn,
        res,
        null_strings=null_strings,
        limit=limit,
        progress=progress,
        chunk_bytes=chunk_bytes,
        workdir=workdir,
    )
    return res
