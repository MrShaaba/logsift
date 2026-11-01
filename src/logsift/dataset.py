"""A loaded file: its DuckDB connection, detected format, profile and findings."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any

import duckdb

from logsift.explore import table_columns
from logsift.formats import FormatInfo, FormatPlugin, detect_format, plugin_for
from logsift.loader import LoadResult, Sniff, load, sniff
from logsift.profile import Profile, profile_table

if TYPE_CHECKING:
    from logsift.insights.base import Finding


@dataclass
class Dataset:
    id: str
    name: str
    path: Path
    size_bytes: int
    con: duckdb.DuckDBPyConnection
    sniff: Sniff
    format: FormatInfo
    load: LoadResult
    # The canonical table the format's plug-in built ("flow", "lb", "trail", ...), or
    # "raw" when the format has none or building it failed.
    table: str
    canonical_columns: list[str] = field(default_factory=list)
    build_error: str = ""

    @classmethod
    def open(cls, path: Path | str, name: str | None = None) -> Dataset:
        path = Path(path)
        con = duckdb.connect()
        sn = sniff(path)
        fmt = detect_format(sn)
        nulls = ("", "-") if fmt.dash_means_missing else ("",)
        result = load(con, path, sn, table="raw", null_strings=nulls)
        ds = cls(
            id=uuid.uuid4().hex[:10],
            name=name or path.name,
            path=path,
            size_bytes=path.stat().st_size,
            con=con,
            sniff=sn,
            format=fmt,
            load=result,
            table="raw",
        )
        if fmt.table:
            try:
                ds.canonical_columns = ds.plugin.build_table(con, fmt, "raw")
                ds.table = fmt.table
            except duckdb.Error as exc:  # pragma: no cover - defensive
                ds.build_error = str(exc).splitlines()[0]
                ds.load.warnings.append(f"Could not build the {fmt.table} table: {ds.build_error}")
        return ds

    @property
    def plugin(self) -> FormatPlugin:
        return plugin_for(self.format.plugin)

    @property
    def has_rules(self) -> bool:
        """True once the format's canonical table is in place; findings run over it."""
        return self.table != "raw"

    @property
    def rows(self) -> int:
        return self.load.rows

    @property
    def columns(self) -> list[tuple[str, str]]:
        return [c for c in table_columns(self.con, self.table) if c[0] != "row_no"]

    def cursor(self) -> duckdb.DuckDBPyConnection:
        """A per-call cursor so requests on other threads do not share state."""
        return self.con.cursor()

    @cached_property
    def profile(self) -> Profile:
        return profile_table(self.cursor(), self.table)

    @cached_property
    def findings(self) -> list[Finding]:
        return self.plugin.findings(self) if self.has_rules else []

    @cached_property
    def timeline(self) -> dict[str, Any] | None:
        return self.plugin.timeline(self) if self.has_rules else None

    def finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.id == finding_id), None)

    def close(self) -> None:
        self.con.close()
