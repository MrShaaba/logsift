"""Saved investigations: findings and rows pinned from one or more files, with notes.

An investigation is a small JSON document under ``data/investigations/``. A pin keeps a
snapshot of what it points at (the finding's text, tables and query, or the row's values),
so the investigation still reads well after the file it came from is closed or reloaded,
and the pinned finding can be rendered by the same template as a live one.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from logsift.explore import table_columns
from logsift.insights.base import Finding, Severity, Table
from logsift.sql import q

if TYPE_CHECKING:
    from logsift.dataset import Dataset

INVESTIGATION_VERSION = 1
# Rows kept per finding table in the snapshot; the live finding may hold more.
TABLE_ROWS = 10


def plain(value: Any) -> Any:
    """A JSON-friendly copy of a cell value."""
    if isinstance(value, datetime | date):
        return value.isoformat(sep=" ") if isinstance(value, datetime) else value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


@dataclass
class Pin:
    id: str
    kind: str  # "finding" or "row"
    dataset_id: str
    dataset_name: str
    created: float = field(default_factory=time.time)
    note: str = ""
    # A finding pin: the finding as a dictionary (see Pin.of_finding).
    finding: dict[str, Any] | None = None
    # A row pin: the row's position in the canonical table and its values.
    row_no: int | None = None
    columns: list[str] = field(default_factory=list)
    values: list[Any] = field(default_factory=list)

    @classmethod
    def of_finding(cls, ds: Dataset, f: Finding) -> Pin:
        snapshot = {
            "id": f.id,
            "rule": f.rule,
            "title": f.title,
            "severity": str(f.severity),
            "summary": f.summary,
            "explanation": f.explanation,
            "likely_cause": f.likely_cause,
            "row_count": f.row_count,
            "row_filter": f.row_filter,
            "query": f.query,
            "tables": [
                {
                    "title": t.title,
                    "columns": list(t.columns),
                    "rows": [[plain(v) for v in r] for r in t.rows[:TABLE_ROWS]],
                    "total": len(t.rows),
                }
                for t in f.tables
            ],
        }
        return cls(uuid.uuid4().hex[:8], "finding", ds.id, ds.name, finding=snapshot)

    @classmethod
    def of_row(cls, ds: Dataset, row_no: int) -> Pin | None:
        """Pin the row at ``row_no`` in the dataset's table; None when there is no such row."""
        columns = [c for c, _ in ds.columns]
        if "row_no" not in {c for c, _ in table_columns(ds.cursor(), ds.table)}:
            return None
        cols = ", ".join(q(c) for c in columns)
        row = (
            ds.cursor()
            .execute(f"SELECT {cols} FROM {q(ds.table)} WHERE row_no = ?", [int(row_no)])
            .fetchone()
        )
        if row is None:
            return None
        return cls(
            uuid.uuid4().hex[:8],
            "row",
            ds.id,
            ds.name,
            row_no=int(row_no),
            columns=columns,
            values=[plain(v) for v in row],
        )

    @property
    def title(self) -> str:
        if self.kind == "finding" and self.finding:
            return str(self.finding["title"])
        return f"Row {self.row_no:,}" if self.row_no is not None else "Row"

    @property
    def finding_id(self) -> str:
        return str(self.finding["id"]) if self.finding else ""

    def as_finding(self) -> Finding:
        """The pinned finding as a Finding, so the usual template can render it."""
        if not self.finding:
            raise ValueError("not a finding pin")
        f = self.finding
        return Finding(
            str(f["id"]),
            str(f["rule"]),
            str(f["title"]),
            Severity(f["severity"]),
            str(f["summary"]),
            str(f["explanation"]),
            str(f["likely_cause"]),
            int(f["row_count"]),
            str(f["row_filter"]),
            [
                Table(t["title"], list(t["columns"]), [tuple(r) for r in t["rows"]])
                for t in f["tables"]
            ],
            query=str(f.get("query", "")),
        )

    def same_as(self, other: Pin) -> bool:
        if self.kind != other.kind or self.dataset_id != other.dataset_id:
            return False
        if self.kind == "finding":
            return self.finding_id == other.finding_id
        return self.row_no == other.row_no


@dataclass
class Investigation:
    id: str
    name: str
    created: float = field(default_factory=time.time)
    updated: float = field(default_factory=time.time)
    notes: str = ""
    pins: list[Pin] = field(default_factory=list)

    # ------------------------------------------------------------------ pins

    def add(self, pin: Pin) -> Pin:
        """Add a pin, or return the one already there for the same finding or row."""
        for existing in self.pins:
            if existing.same_as(pin):
                return existing
        self.pins.append(pin)
        self.touch()
        return pin

    def pin(self, pin_id: str) -> Pin | None:
        return next((p for p in self.pins if p.id == pin_id), None)

    def remove(self, pin_id: str) -> bool:
        before = len(self.pins)
        self.pins = [p for p in self.pins if p.id != pin_id]
        if len(self.pins) != before:
            self.touch()
        return len(self.pins) != before

    def has(self, ds_id: str, *, finding_id: str = "", row_no: int | None = None) -> bool:
        for p in self.pins:
            if p.dataset_id != ds_id:
                continue
            if finding_id and p.kind == "finding" and p.finding_id == finding_id:
                return True
            if row_no is not None and p.kind == "row" and p.row_no == row_no:
                return True
        return False

    def pinned_findings(self, ds_id: str) -> set[str]:
        return {p.finding_id for p in self.pins if p.kind == "finding" and p.dataset_id == ds_id}

    def pinned_rows(self, ds_id: str) -> set[int]:
        return {
            p.row_no
            for p in self.pins
            if p.kind == "row" and p.dataset_id == ds_id and p.row_no is not None
        }

    @property
    def findings(self) -> list[Pin]:
        return [p for p in self.pins if p.kind == "finding"]

    @property
    def rows(self) -> list[Pin]:
        return [p for p in self.pins if p.kind == "row"]

    def by_dataset(self) -> list[dict[str, Any]]:
        """Pins grouped by the file they came from, in the order the files were first pinned."""
        groups: dict[str, dict[str, Any]] = {}
        for p in self.pins:
            g = groups.setdefault(
                p.dataset_id,
                {
                    "dataset_id": p.dataset_id,
                    "dataset_name": p.dataset_name,
                    "findings": [],
                    "rows": [],
                },
            )
            g["findings" if p.kind == "finding" else "rows"].append(p)
        return list(groups.values())

    def touch(self) -> None:
        self.updated = time.time()

    # ----------------------------------------------------------- persistence

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["version"] = INVESTIGATION_VERSION
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Investigation:
        if data.get("version") != INVESTIGATION_VERSION:
            raise ValueError(f"unknown investigation version {data.get('version')!r}")
        pins = [Pin(**p) for p in data.get("pins", [])]
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            created=float(data.get("created", 0)),
            updated=float(data.get("updated", 0)),
            notes=str(data.get("notes", "")),
            pins=pins,
        )


class InvestigationStore:
    """One JSON file per investigation under ``root``."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, inv_id: str) -> Path:
        return self.root / f"{inv_id}.json"

    def create(self, name: str = "") -> Investigation:
        inv = Investigation(uuid.uuid4().hex[:8], name.strip() or "Untitled investigation")
        self.save(inv)
        return inv

    def save(self, inv: Investigation) -> None:
        target = self.path(inv.id)
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(inv.to_dict(), indent=1, default=str), encoding="utf-8")
        os.replace(tmp, target)

    def get(self, inv_id: str) -> Investigation | None:
        path = self.path(Path(inv_id).name)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return Investigation.from_dict(data)
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def find(self, key: str) -> Investigation | None:
        """By id, or by exact name (case-insensitive) when no id matches."""
        inv = self.get(key)
        if inv is not None:
            return inv
        wanted = key.strip().lower()
        return next((i for i in self.list() if i.name.lower() == wanted), None)

    def list(self) -> list[Investigation]:
        """Every readable investigation, most recently changed first."""
        out: list[Investigation] = []
        for path in self.root.glob("*.json"):
            inv = self.get(path.stem)
            if inv is not None and inv.id == path.stem:
                out.append(inv)
        return sorted(out, key=lambda i: (-i.updated, i.name))

    def delete(self, inv_id: str) -> None:
        self.path(Path(inv_id).name).unlink(missing_ok=True)
