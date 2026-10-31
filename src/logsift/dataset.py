"""A loaded file: its DuckDB connection, detected format, profile and findings."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any

import duckdb

from logsift.explore import table_columns
from logsift.flow import build_flow_table
from logsift.formats import FormatInfo, detect_format
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
    table: str
    flow_columns: list[str] = field(default_factory=list)
    flow_error: str = ""

    @classmethod
    def open(cls, path: Path | str, name: str | None = None) -> Dataset:
        path = Path(path)
        con = duckdb.connect()
        sn = sniff(path)
        fmt = detect_format(sn)
        nulls = ("", "-") if fmt.is_flow_log else ("",)
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
        if fmt.is_flow_log:
            try:
                ds.flow_columns = build_flow_table(con, fmt, "raw", "flow")
                ds.table = "flow"
            except duckdb.Error as exc:  # pragma: no cover - defensive
                ds.flow_error = str(exc).splitlines()[0]
                ds.load.warnings.append(f"Could not build the flow table: {ds.flow_error}")
        return ds

    @property
    def is_flow_log(self) -> bool:
        return self.table == "flow"

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
        if not self.is_flow_log:
            return []
        from logsift.insights.flowlogs import run_rules

        return run_rules(self)

    @cached_property
    def timeline(self) -> dict[str, Any] | None:
        if not self.is_flow_log:
            return None
        from logsift.insights.flowlogs import build_timeline

        return build_timeline(self)

    def finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.id == finding_id), None)

    def close(self) -> None:
        self.con.close()
