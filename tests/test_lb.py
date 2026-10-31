from __future__ import annotations

from datetime import datetime

from logsift.dataset import Dataset
from logsift.lb import alert_name


def count(ds: Dataset, where: str) -> int:
    return int(ds.cursor().execute(f"SELECT count(*) FROM lb WHERE {where}").fetchone()[0])


def test_alb_table_has_typed_and_derived_columns(alb_ds: Dataset) -> None:
    assert alb_ds.table == "lb" and alb_ds.is_lb_log and alb_ds.has_rules
    assert alb_ds.rows == 4156
    assert alb_ds.load.warnings == []
    names = [c for c, _ in alb_ds.columns]
    assert names[:5] == ["time", "type", "client_ip", "client_port", "method"]
    types = dict(alb_ds.columns)
    assert types["time"] == "TIMESTAMP"
    assert types["elb_status_code"] == "INTEGER"
    assert types["target_processing_time"] == "DOUBLE"
    assert types["sent_bytes"] == "BIGINT"
    assert types["client_port"] == "INTEGER"


def test_alb_request_line_is_split(alb_ds: Dataset) -> None:
    row = (
        alb_ds.cursor()
        .execute(
            "SELECT time, client_ip, method, host, path, http_version, url, target_ip, "
            "target_port, target_group, total_time FROM lb WHERE path LIKE '/search%' LIMIT 1"
        )
        .fetchone()
    )
    assert row is not None
    time, client, method, host, path, version, url, tip, tport, group, total = row
    assert isinstance(time, datetime) and time.year == 2026
    assert client.startswith(("198.51.100.", "203.0.113."))
    assert (method, host, path, version) == ("GET", "shop.example.com", "/search", "HTTP/2.0")
    assert url.startswith("https://shop.example.com:443/search?q=")
    assert tip.startswith("10.0.1.") and tport == 80
    assert group == "shop-web"
    assert total is not None and total > 0


def test_alb_dash_fields_are_null(alb_ds: Dataset) -> None:
    # The ALB answered these itself: no target, no target status, no processing times.
    assert count(alb_ds, "elb_status_code = 400") == 6
    assert count(alb_ds, "elb_status_code = 400 AND target_ip IS NULL") == 6
    assert count(alb_ds, "elb_status_code = 400 AND method IS NULL") == 6
    assert count(alb_ds, "target_processing_time < 0 AND total_time IS NOT NULL") == 0
    assert count(alb_ds, "actions_executed = 'redirect' AND redirect_url IS NULL") == 0
    assert count(alb_ds, "elb_status_code = 301 AND target_status_code IS NULL") == 96


def test_nlb_table_has_typed_and_derived_columns(nlb_ds: Dataset) -> None:
    assert nlb_ds.table == "lb" and nlb_ds.format.kind == "nlb_access"
    assert nlb_ds.rows == 3015
    types = dict(nlb_ds.columns)
    assert types["connection_time"] == "BIGINT"
    assert types["incoming_tls_alert"] == "INTEGER"
    assert types["handshake_ok"] == "BOOLEAN"
    assert types["version"] == "VARCHAR"
    row = (
        nlb_ds.cursor()
        .execute(
            "SELECT client_ip, client_port, destination_ip, destination_port, version "
            "FROM lb LIMIT 1"
        )
        .fetchone()
    )
    assert row is not None
    assert (row[2], row[3], row[4]) == ("192.0.2.80", 443, "2.0")
    assert isinstance(row[1], int)


def test_nlb_alerts_are_named(nlb_ds: Dataset) -> None:
    rows = (
        nlb_ds.cursor()
        .execute("SELECT handshake_ok, alert_name, count(*) FROM lb GROUP BY ALL ORDER BY 3 DESC")
        .fetchall()
    )
    assert rows == [
        (True, None, 2825),
        (False, "unknown_ca", 120),
        (False, "bad_certificate", 40),
        (False, None, 30),
    ]
    assert alert_name(48) == "unknown_ca"
    assert alert_name(99) == "alert 99"
    assert alert_name(None) == "none"
