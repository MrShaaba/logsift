from __future__ import annotations

from datetime import datetime
from pathlib import Path

from logsift.dataset import Dataset
from tests.conftest import write


def count(ds: Dataset, where: str) -> int:
    return int(ds.cursor().execute(f"SELECT count(*) FROM s3 WHERE {where}").fetchone()[0])


def test_s3_table_has_typed_and_derived_columns(s3_ds: Dataset) -> None:
    assert s3_ds.table == "s3" and s3_ds.format.plugin == "s3_access" and s3_ds.has_rules
    assert s3_ds.rows == 4830
    assert s3_ds.load.warnings == []
    names = [c for c, _ in s3_ds.columns]
    assert names[:6] == ["time", "remote_ip", "principal", "operation", "key", "http_status"]
    assert "time_offset" not in names
    types = dict(s3_ds.columns)
    assert types["time"] == "TIMESTAMP"
    assert types["http_status"] == "INTEGER"
    assert types["bytes_sent"] == "BIGINT"
    assert types["total_time"] == "BIGINT"
    assert types["anonymous"] == "BOOLEAN" and types["is_error"] == "BOOLEAN"
    assert count(s3_ds, "time IS NULL") == 0
    first, last = s3_ds.cursor().execute("SELECT min(time), max(time) FROM s3").fetchone()
    assert first == datetime(2026, 3, 10, 8, 0) and last.hour == 9 and last.minute == 59


def test_s3_request_line_is_split(s3_ds: Dataset) -> None:
    row = (
        s3_ds.cursor()
        .execute(
            "SELECT method, path, query, http_version, prefix, verb, target, principal, "
            "authentication_type FROM s3 WHERE key = 'images/thumbs/494.jpg' ORDER BY time LIMIT 1"
        )
        .fetchone()
    )
    assert row is not None
    method, path, query, version, prefix, verb, target, principal, auth = row
    assert (method, path, version) == ("GET", "/images/thumbs/494.jpg", "HTTP/1.1")
    assert query.startswith("X-Amz-Algorithm=AWS4-HMAC-SHA256")
    assert (prefix, verb, target) == ("images/thumbs/", "GET", "OBJECT")
    assert principal == "shop-web-role" and auth == "QueryString"


def test_s3_principal_and_anonymous_flags(s3_ds: Dataset) -> None:
    con = s3_ds.cursor()
    by = dict(con.execute("SELECT principal, count(*) FROM s3 GROUP BY 1").fetchall())
    assert by["shop-web-role"] == 4286 and by["bob"] == 303 and by["anonymous"] == 75
    assert by["s3.amazonaws.com"] == 12  # lifecycle expiries, no client address
    assert count(s3_ds, "anonymous AND requester IS NOT NULL") == 0
    assert count(s3_ds, "anonymous AND NOT is_error") == 15
    assert count(s3_ds, "anonymous AND http_status = 403") == 60
    assert count(s3_ds, "remote_ip IS NULL AND operation = 'S3.EXPIRE.OBJECT'") == 12
    assert count(s3_ds, "is_error") == count(s3_ds, "http_status >= 400") == 625
    assert count(s3_ds, "key IS NULL AND target = 'BUCKET'") == 48
    assert count(s3_ds, "prefix = '(no prefix)'") == 40  # the probe's bare file names


def test_s3_dash_fields_are_null(s3_ds: Dataset) -> None:
    assert count(s3_ds, "http_status = 404 AND object_size IS NULL") == 478
    assert count(s3_ds, "http_status = 404 AND turn_around_time IS NULL") == 478
    assert count(s3_ds, "operation = 'REST.DELETE.OBJECT' AND bytes_sent IS NULL") == 300
    assert count(s3_ds, "error_code IS NOT NULL AND NOT is_error") == 0
    assert count(s3_ds, "version_id IS NOT NULL") == 0


def test_s3_older_shape_builds_without_tls_columns(samples: Path, tmp_path: Path) -> None:
    import csv

    lines = (samples / "s3_access_logs.log").read_text().splitlines()[:50]
    older = []
    for ln in lines:
        fields = next(csv.reader([ln], delimiter=" "))[:19]
        older.append(" ".join(f'"{f}"' if " " in f else f for f in fields))
    ds = Dataset.open(write(tmp_path, "old.log", "\n".join(older) + "\n"))
    try:
        assert ds.table == "s3" and ds.rows == 50
        names = [c for c, _ in ds.columns]
        assert "tls_version" not in names and "principal" in names and "prefix" in names
        assert count(ds, "time IS NULL") == 0
    finally:
        ds.close()
