"""Write rows and findings as CSV, JSON and .xlsx."""

from __future__ import annotations

import csv
import io
import json
from datetime import date, datetime
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from logsift.insights.base import Finding

Rows = list[tuple[Any, ...]]

FINDING_COLUMNS = [
    "id",
    "severity",
    "title",
    "summary",
    "explanation",
    "likely_cause",
    "row_count",
    "rule",
    "query",
]


def _plain(v: Any) -> Any:
    if isinstance(v, datetime | date):
        return v.isoformat()
    return v


def rows_to_csv(columns: list[str], rows: Rows) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(columns)
    for r in rows:
        w.writerow(["" if v is None else v for v in r])
    return buf.getvalue().encode("utf-8")


def rows_to_json(columns: list[str], rows: Rows) -> bytes:
    data = [dict(zip(columns, (_plain(v) for v in r), strict=False)) for r in rows]
    return json.dumps(data, indent=2).encode("utf-8")


def _write_sheet(ws: Worksheet, columns: list[str], rows: Rows, start_row: int = 1) -> int:
    """Write a bold header and rows. Returns the next free row."""
    bold = Font(bold=True)
    for j, name in enumerate(columns, 1):
        cell = ws.cell(row=start_row, column=j, value=name)
        cell.font = bold
    for i, r in enumerate(rows, start_row + 1):
        for j, v in enumerate(r, 1):
            if isinstance(v, int | float | datetime | date | bool) or v is None:
                cell = ws.cell(row=i, column=j, value=v)
                if isinstance(v, datetime):
                    cell.number_format = "yyyy-mm-dd hh:mm:ss"
                elif isinstance(v, date):
                    cell.number_format = "yyyy-mm-dd"
            else:
                ws.cell(row=i, column=j, value=str(v))
    return start_row + len(rows) + 1


def _autosize(ws: Worksheet, max_width: int = 60) -> None:
    widths: dict[int, int] = {}
    for row in ws.iter_rows():
        for cell in row:
            if cell.value is None:
                continue
            text = (
                cell.value.strftime("%Y-%m-%d %H:%M:%S")
                if isinstance(cell.value, datetime)
                else str(cell.value)
            )
            widths[cell.column] = max(widths.get(cell.column, 0), len(text))
    for col, width in widths.items():
        ws.column_dimensions[get_column_letter(col)].width = min(max_width, width + 2)


def rows_to_xlsx(columns: list[str], rows: Rows, sheet: str = "rows") -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = sheet[:31]
    _write_sheet(ws, columns, rows)
    ws.freeze_panes = "A2"
    _autosize(ws)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def findings_rows(findings: list[Finding]) -> Rows:
    return [
        (
            f.id,
            str(f.severity),
            f.title,
            f.summary,
            f.explanation,
            f.likely_cause,
            f.row_count,
            f.rule,
            f.query,
        )
        for f in findings
    ]


def findings_to_csv(findings: list[Finding]) -> bytes:
    return rows_to_csv(FINDING_COLUMNS, findings_rows(findings))


def findings_to_json(findings: list[Finding]) -> bytes:
    return json.dumps([f.to_dict() for f in findings], indent=2, default=_plain).encode("utf-8")


def findings_to_xlsx(findings: list[Finding]) -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = "findings"
    _write_sheet(ws, FINDING_COLUMNS, findings_rows(findings))
    ws.freeze_panes = "A2"
    _autosize(ws)
    for f in findings:
        if not f.tables:
            continue
        sheet = wb.create_sheet(title=f.id[:31])
        row = 1
        for t in f.tables:
            sheet.cell(row=row, column=1, value=t.title).font = Font(bold=True, italic=True)
            row = _write_sheet(sheet, t.columns, t.rows, start_row=row + 1) + 1
        _autosize(sheet)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


CONTENT_TYPES = {
    "csv": "text/csv; charset=utf-8",
    "json": "application/json",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
