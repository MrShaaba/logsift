"""On-disk home for loaded files: one DuckDB database and one JSON sidecar per dataset.

Everything lives under ``data/db/`` (or whatever directory the server was given). The
database holds the raw and canonical tables, the sidecar holds what the loader and the
format detection found out, so a restart reopens the file instead of reloading it.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import duckdb


class Store:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        # Chunks are staged here while a file loads, next to the database they feed.
        self.tmp = self.root / "tmp"
        self.tmp.mkdir(exist_ok=True)

    def db_path(self, ds_id: str) -> Path:
        return self.root / f"{ds_id}.duckdb"

    def meta_path(self, ds_id: str) -> Path:
        return self.root / f"{ds_id}.json"

    def connect(self, ds_id: str) -> duckdb.DuckDBPyConnection:
        return duckdb.connect(str(self.db_path(ds_id)))

    def save(self, ds_id: str, meta: dict[str, Any]) -> None:
        """Write the sidecar atomically, so a crash mid-write leaves the old one intact."""
        target = self.meta_path(ds_id)
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(meta, indent=1, default=str), encoding="utf-8")
        os.replace(tmp, target)

    def metas(self) -> list[dict[str, Any]]:
        """Every readable sidecar whose database file is present, oldest first."""
        out: list[dict[str, Any]] = []
        for path in self.root.glob("*.json"):
            try:
                meta = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(meta, dict) or meta.get("id") != path.stem:
                continue
            if not self.db_path(path.stem).is_file():
                path.unlink(missing_ok=True)
                continue
            out.append(meta)
        return sorted(out, key=lambda m: (float(m.get("created", 0)), str(m.get("id"))))

    def remove(self, ds_id: str) -> None:
        for p in (self.meta_path(ds_id), self.db_path(ds_id)):
            p.unlink(missing_ok=True)
        db = self.db_path(ds_id)
        db.with_name(db.name + ".wal").unlink(missing_ok=True)
        shutil.rmtree(db.with_name(db.name + ".tmp"), ignore_errors=True)
