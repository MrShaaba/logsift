"""A loaded file: its DuckDB connection, detected format, profile and findings.

A dataset is opened either in full or as a sample of the first N rows. A sampled dataset
can run the full pass later, on a background thread, which appends the rest of the file
to the raw table, rebuilds the format's canonical table and refreshes the findings. With
a :class:`~logsift.store.Store` the tables live in an on-disk database and the dataset is
written down so a restart restores it without reloading the file.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any

import duckdb

from logsift.explore import table_columns
from logsift.formats import Format, FormatInfo, FormatPlugin, detect_format, plugin_for
from logsift.loader import (
    CHUNK_BYTES,
    ColumnType,
    LoadProgress,
    LoadResult,
    ProgressFn,
    Sniff,
    load,
    load_more,
    sniff,
)
from logsift.profile import Profile, profile_table
from logsift.sql import q
from logsift.store import Store

if TYPE_CHECKING:
    from logsift.insights.base import Finding

# How many rows the web UI loads before showing the first profile and findings.
SAMPLE_ROWS = 250_000
CACHED = ("profile", "findings", "timeline")
META_VERSION = 1


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
    store: Store | None = None
    created: float = field(default_factory=time.time)
    chunk_bytes: int = CHUNK_BYTES
    # The full pass, while it runs; "ready" otherwise.
    status: LoadProgress = field(default_factory=lambda: LoadProgress(phase="ready"))
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _worker: threading.Thread | None = field(default=None, repr=False)

    @classmethod
    def open(
        cls,
        path: Path | str,
        name: str | None = None,
        *,
        store: Store | None = None,
        limit: int | None = None,
        progress: ProgressFn | None = None,
        chunk_bytes: int = CHUNK_BYTES,
    ) -> Dataset:
        """Sniff, detect, load (the first ``limit`` rows, or everything) and build the table."""
        path = Path(path)
        ds_id = uuid.uuid4().hex[:10]
        con = store.connect(ds_id) if store else duckdb.connect()
        sn = sniff(path)
        fmt = detect_format(sn)
        result = load(
            con,
            path,
            sn,
            table="raw",
            null_strings=_nulls(fmt),
            limit=limit,
            progress=progress,
            chunk_bytes=chunk_bytes,
            workdir=store.tmp if store else None,
        )
        ds = cls(
            id=ds_id,
            name=name or path.name,
            path=path,
            size_bytes=path.stat().st_size,
            con=con,
            sniff=sn,
            format=fmt,
            load=result,
            table="raw",
            store=store,
            chunk_bytes=chunk_bytes,
        )
        ds._build(con)
        ds.status = LoadProgress(result.rows, result.bytes_read, ds.size_bytes, phase="ready")
        ds.persist()
        return ds

    # ------------------------------------------------------------------ basics

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
        return [c for c in table_columns(self.cursor(), self.table) if c[0] != "row_no"]

    @property
    def is_sample(self) -> bool:
        """True while only the first rows of the file are loaded."""
        return not self.load.complete

    @property
    def loading(self) -> bool:
        return self.status.phase in ("reading", "building")

    @property
    def fraction_loaded(self) -> float:
        if self.load.complete:
            return 1.0
        if not self.size_bytes:
            return 0.0
        return min(1.0, self.load.bytes_read / self.size_bytes)

    @property
    def source_available(self) -> bool:
        return self.path.is_file()

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

    # --------------------------------------------------------------- full pass

    def start_full_pass(self) -> bool:
        """Load the rest of the file on a background thread. False when there is nothing to do."""
        with self._lock:
            if self.loading or self.load.complete or not self.source_available:
                return False
            self.status = LoadProgress(
                self.load.rows, self.load.bytes_read, self.size_bytes, phase="reading"
            )
            self._worker = threading.Thread(target=self.run_full_pass, daemon=True)
            self._worker.start()
        return True

    def wait(self, timeout: float | None = None) -> None:
        """Block until a running full pass has finished."""
        if self._worker is not None:
            self._worker.join(timeout)

    def run_full_pass(self, progress: ProgressFn | None = None) -> None:
        """Load the rest of the file, rebuild the format's table and refresh the findings.

        Runs on the calling thread; :meth:`start_full_pass` wraps it in a worker. Progress
        is kept in ``status`` for the UI to poll and passed to ``progress`` when given.
        """
        if self.load.complete:
            return
        status = self.status
        if status.phase != "reading":
            status = self.status = LoadProgress(
                self.load.rows, self.load.bytes_read, self.size_bytes, phase="reading"
            )

        def report(p: LoadProgress) -> None:
            status.rows, status.bytes_read = p.rows, p.bytes_read
            if progress:
                progress(status)

        con = self.con.cursor()
        try:
            present = con.execute("SELECT count(*) FROM raw").fetchone()
            if present and int(present[0]) != self.load.rows:
                # An earlier pass was cut short between a chunk and its record: start over.
                con.execute("DELETE FROM raw")
                self._reset_load()
            load_more(
                con,
                self.path,
                self.sniff,
                self.load,
                null_strings=_nulls(self.format),
                progress=report,
                chunk_bytes=self.chunk_bytes,
                workdir=self.store.tmp if self.store else None,
            )
            status.phase = "building"
            report(status)
            self._build(con)
            self._reset_caches()
            status.rows, status.bytes_read = self.load.rows, self.load.bytes_read
            status.phase = "ready"
            self.persist()
        except Exception as exc:  # the UI shows the error and offers to try again
            status.phase = "failed"
            status.error = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        finally:
            con.close()
        if progress:
            progress(status)

    def _build(self, con: duckdb.DuckDBPyConnection) -> None:
        """(Re)build the format's canonical table from ``raw``, atomically for other readers."""
        if not self.format.table:
            return
        try:
            con.begin()
            cols = self.plugin.build_table(con, self.format, "raw")
            con.commit()
        except duckdb.Error as exc:
            con.rollback()
            self.build_error = str(exc).splitlines()[0]
            self.load.warnings.append(
                f"Could not build the {self.format.table} table: {self.build_error}"
            )
            return
        self.canonical_columns = cols
        self.table = self.format.table
        self.build_error = ""

    def _reset_load(self) -> None:
        res = self.load
        res.rows = res.offset = res.lines = res.bytes_read = res.rejected_lines = 0
        res.reject_examples = []
        res.complete = False
        for c in res.columns:
            c.bad_values = 0

    def _reset_caches(self) -> None:
        for name in CACHED:
            self.__dict__.pop(name, None)

    # ------------------------------------------------------------- persistence

    def persist(self) -> None:
        if self.store is not None:
            self.store.save(self.id, self.to_meta())

    def to_meta(self) -> dict[str, Any]:
        sn = asdict(self.sniff)
        sn["rows"] = []
        sn["field_counts"] = {str(k): v for k, v in self.sniff.field_counts.items()}
        fmt = asdict(self.format)
        fmt["kind"] = str(self.format.kind)
        return {
            "version": META_VERSION,
            "id": self.id,
            "name": self.name,
            "path": str(self.path),
            "size_bytes": self.size_bytes,
            "created": self.created,
            "chunk_bytes": self.chunk_bytes,
            "sniff": sn,
            "format": fmt,
            "load": asdict(self.load),
            "table": self.table,
            "canonical_columns": self.canonical_columns,
            "build_error": self.build_error,
        }

    @classmethod
    def restore(cls, store: Store, meta: dict[str, Any]) -> Dataset:
        """Reopen a dataset from its sidecar and database. Raises when either is unusable."""
        if meta.get("version") != META_VERSION:
            raise ValueError(f"unknown dataset version {meta.get('version')!r}")
        sn_meta = dict(meta["sniff"])
        sn_meta["field_counts"] = Counter({int(k): v for k, v in sn_meta["field_counts"].items()})
        sn_meta["rows"] = []
        sn = Sniff(**sn_meta)
        fmt_meta = dict(meta["format"])
        fmt_meta["kind"] = Format(fmt_meta["kind"])
        fmt = FormatInfo(**fmt_meta)
        ld_meta = dict(meta["load"])
        ld_meta["columns"] = [ColumnType(**c) for c in ld_meta["columns"]]
        ld_meta["reject_examples"] = [tuple(x) for x in ld_meta["reject_examples"]]
        ld = LoadResult(**ld_meta)
        con = store.connect(meta["id"])
        ds = cls(
            id=meta["id"],
            name=meta["name"],
            path=Path(meta["path"]),
            size_bytes=int(meta["size_bytes"]),
            con=con,
            sniff=sn,
            format=fmt,
            load=ld,
            table=meta["table"],
            canonical_columns=list(meta["canonical_columns"]),
            build_error=meta.get("build_error", ""),
            store=store,
            created=float(meta.get("created", 0)),
            chunk_bytes=int(meta.get("chunk_bytes", CHUNK_BYTES)),
        )
        con.execute(f"SELECT count(*) FROM {q(ds.table)}")  # the tables must really be there
        ds.status = LoadProgress(ld.rows, ld.bytes_read, ds.size_bytes, phase="ready")
        return ds

    @classmethod
    def restore_all(cls, store: Store) -> list[Dataset]:
        """Every dataset the store holds; anything unreadable is dropped from the store."""
        out: list[Dataset] = []
        for meta in store.metas():
            try:
                out.append(cls.restore(store, meta))
            except (duckdb.Error, KeyError, TypeError, ValueError):
                store.remove(str(meta.get("id", "")))
        return out


def _nulls(fmt: FormatInfo) -> tuple[str, ...]:
    return ("", "-") if fmt.dash_means_missing else ("",)
