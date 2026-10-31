"""Paginated, searchable, filterable row access with safe parameter binding."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import duckdb

from logsift.flow import q

PER_PAGE = 50
MAX_EXPORT_ROWS = 200_000


@dataclass
class RowQuery:
    """What the user asked to see. ``where`` is server-generated SQL from a finding."""

    search: str = ""
    filters: dict[str, str] = field(default_factory=dict)
    where: str = ""
    order_by: str = ""
    descending: bool = False


@dataclass
class Page:
    columns: list[str]
    rows: list[tuple[Any, ...]]
    total: int
    page: int
    per_page: int

    @property
    def pages(self) -> int:
        return max(1, -(-self.total // self.per_page))

    @property
    def first_row(self) -> int:
        return 0 if self.total == 0 else (self.page - 1) * self.per_page + 1

    @property
    def last_row(self) -> int:
        return min(self.total, self.page * self.per_page)


def table_columns(con: duckdb.DuckDBPyConnection, table: str) -> list[tuple[str, str]]:
    return [(r[0], r[1]) for r in con.execute(f"DESCRIBE {q(table)}").fetchall()]


def build_where(columns: list[str], rq: RowQuery) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if rq.where:
        clauses.append(f"({rq.where})")
    for col, val in rq.filters.items():
        if col not in columns:
            continue
        if val == "":
            clauses.append(f"{q(col)} IS NULL")
        else:
            clauses.append(f"CAST({q(col)} AS VARCHAR) = ?")
            params.append(val)
    if rq.search:
        like = " OR ".join(f"lower(CAST({q(c)} AS VARCHAR)) LIKE ?" for c in columns)
        clauses.append(f"({like})")
        params.extend([f"%{rq.search.lower()}%"] * len(columns))
    return (" AND ".join(clauses) if clauses else "TRUE"), params


def fetch_page(
    con: duckdb.DuckDBPyConnection,
    table: str,
    rq: RowQuery,
    page: int = 1,
    per_page: int = PER_PAGE,
) -> Page:
    cols = [c for c, _ in table_columns(con, table)]
    where, params = build_where(cols, rq)
    total = con.execute(f"SELECT count(*) FROM {q(table)} WHERE {where}", params).fetchone()
    total_n = int(total[0]) if total else 0
    page = max(1, min(page, max(1, -(-total_n // per_page))))
    order = "row_no" if "row_no" in cols else "1"
    if rq.order_by in cols:
        order = f"{q(rq.order_by)} {'DESC' if rq.descending else 'ASC'} NULLS LAST"
    rows = con.execute(
        f"SELECT * FROM {q(table)} WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?",
        [*params, per_page, (page - 1) * per_page],
    ).fetchall()
    return Page(cols, rows, total_n, page, per_page)


def fetch_all(
    con: duckdb.DuckDBPyConnection, table: str, rq: RowQuery, limit: int = MAX_EXPORT_ROWS
) -> tuple[list[str], list[tuple[Any, ...]]]:
    cols = [c for c, _ in table_columns(con, table)]
    where, params = build_where(cols, rq)
    order = "row_no" if "row_no" in cols else "1"
    rows = con.execute(
        f"SELECT * FROM {q(table)} WHERE {where} ORDER BY {order} LIMIT ?", [*params, limit]
    ).fetchall()
    return cols, rows


def distinct_values(
    con: duckdb.DuckDBPyConnection, table: str, column: str, limit: int = 30
) -> list[str]:
    cols = [c for c, _ in table_columns(con, table)]
    if column not in cols:
        return []
    rows = con.execute(
        f"SELECT CAST({q(column)} AS VARCHAR) AS v, count(*) AS n FROM {q(table)} "
        f"WHERE {q(column)} IS NOT NULL GROUP BY 1 ORDER BY n DESC, 1 LIMIT {int(limit)}"
    ).fetchall()
    return [r[0] for r in rows]
