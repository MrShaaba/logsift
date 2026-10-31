from __future__ import annotations

from datetime import date

from logsift.dataset import Dataset


def test_sales_profile(sales_ds: Dataset) -> None:
    prof = sales_ds.profile
    cols = {c.name: c for c in prof.columns}
    assert prof.rows == 3285
    assert cols["date"].kind == "date"
    assert cols["date"].min == date(2025, 1, 1)
    assert cols["date"].max == date(2025, 12, 31)
    assert cols["date"].distinct == 365
    assert cols["units"].kind == "integer"
    assert cols["units"].min == 0
    assert cols["units"].mean is not None and cols["units"].median is not None
    assert cols["unit_price"].kind == "number"
    assert cols["customer_rating"].missing > 0
    assert cols["customer_rating"].missing_label.endswith("%")
    assert cols["store"].distinct == 3
    assert [v for v, _ in cols["store"].top] == ["Harbour Street", "Mill Lane", "Online"]
    assert len(cols["revenue"].histogram) == 16
    assert sum(cols["revenue"].histogram) == 3285


def test_summary_mentions_shape_dates_and_missing(sales_ds: Dataset) -> None:
    text = " ".join(sales_ds.profile.summary)
    assert "3,285 rows and 11 columns" in text
    assert "date runs from 2025-01-01 to 2025-12-31" in text
    assert "customer_rating" in text
    assert "store (3 values)" in text


def test_flow_profile_uses_canonical_columns(flow_ds: Dataset) -> None:
    names = [c.name for c in flow_ds.profile.columns]
    assert "row_no" not in names
    assert {"srcaddr", "dstaddr", "tcp_flags", "start_ts"} <= set(names)
    ts = next(c for c in flow_ds.profile.columns if c.name == "start_ts")
    assert ts.kind == "timestamp"
    assert str(ts.min).startswith("2026-03-10 08:00")
