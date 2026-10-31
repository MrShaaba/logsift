from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from openpyxl import load_workbook
from openpyxl.utils import get_column_letter

from logsift.dataset import Dataset
from logsift.explore import RowQuery, fetch_all
from logsift.export import (
    findings_to_csv,
    findings_to_json,
    findings_to_xlsx,
    rows_to_csv,
    rows_to_json,
    rows_to_xlsx,
)


def test_rows_csv_and_json(flow_ds: Dataset) -> None:
    cols, rows = fetch_all(flow_ds.cursor(), "flow", RowQuery(filters={"dstport": "5432"}))
    assert len(rows) == 320
    parsed = list(csv.DictReader(io.StringIO(rows_to_csv(cols, rows).decode())))
    assert len(parsed) == 320
    assert parsed[0]["dstport"] == "5432"
    data = json.loads(rows_to_json(cols, rows))
    assert data[0]["dstaddr"] == "10.0.3.20"
    assert data[0]["start_ts"].startswith("2026-03-10T")


def test_rows_xlsx_has_real_cells(flow_ds: Dataset) -> None:
    cols, rows = fetch_all(flow_ds.cursor(), "flow", RowQuery(filters={"log_status": "SKIPDATA"}))
    wb = load_workbook(io.BytesIO(rows_to_xlsx(cols, rows)))
    ws = wb.active
    assert ws.freeze_panes == "A2"
    header = [c.value for c in ws[1]]
    assert header == cols
    assert all(c.font.bold for c in ws[1])
    bytes_col = cols.index("start") + 1
    assert isinstance(ws.cell(row=2, column=bytes_col).value, int)
    ts_col = cols.index("start_ts") + 1
    cell = ws.cell(row=2, column=ts_col)
    assert isinstance(cell.value, datetime)
    assert cell.number_format == "yyyy-mm-dd hh:mm:ss"
    eni_letter = get_column_letter(cols.index("interface_id") + 1)
    assert ws.column_dimensions[eni_letter].width > 20  # interface ids are long


def test_findings_exports(flow_ds: Dataset) -> None:
    findings = flow_ds.findings
    rows = list(csv.DictReader(io.StringIO(findings_to_csv(findings).decode())))
    assert len(rows) == len(findings)
    assert rows[0]["severity"] == "high"
    data = json.loads(findings_to_json(findings))
    assert data[0]["id"] == "asymmetric"
    assert data[0]["tables"][0]["rows"][0]["server"] == "10.0.2.10"
    wb = load_workbook(io.BytesIO(findings_to_xlsx(findings)))
    assert wb.sheetnames[0] == "findings"
    assert "asymmetric" in wb.sheetnames
    detail = wb["asymmetric"]
    assert detail.cell(row=1, column=1).value == "Request accepted, reply rejected"
    assert detail.cell(row=2, column=1).value == "client"
    assert isinstance(detail.cell(row=3, column=5).value, int)
