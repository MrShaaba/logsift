from __future__ import annotations

import csv
from pathlib import Path

from logsift.dataset import Dataset
from logsift.explore import RowQuery, fetch_page
from logsift.insights.base import Finding, Severity
from tests.conftest import write


def by_rule(ds: Dataset, rule: str) -> list[Finding]:
    return [f for f in ds.findings if f.rule == rule]


def rows_for(ds: Dataset, f: Finding) -> int:
    return fetch_page(ds.cursor(), ds.table, RowQuery(where=f.row_filter), 1, 1).total


def test_anonymous_reads_are_high(s3_ds: Dataset) -> None:
    reads, denied = by_rule(s3_ds, "anonymous")
    assert reads.id == "anonymous-reads" and reads.severity == Severity.HIGH
    assert reads.title == "15 anonymous requests succeeded, reading 13 objects (4.1 GB)"
    assert "1 address (203.0.113.61)" in reads.summary
    assert "2 bucket listings and 13 objects under backups/db/, backups/config/" in reads.summary
    assert "The largest was backups/db/2026-03-04-0800.sql.gz" in reads.summary
    assert "Block Public Access" in reads.likely_cause
    assert reads.row_count == 15 == rows_for(s3_ds, reads)
    assert [t.title for t in reads.tables] == [
        "By key prefix",
        "By client address",
        "Largest objects read",
        "By operation",
    ]
    assert reads.tables[0].rows[0][0] == "backups/db/"
    assert {r[0] for r in reads.tables[3].rows} == {"REST.GET.OBJECT", "REST.GET.BUCKET"}

    assert denied.id == "anonymous-denied" and denied.severity == Severity.MEDIUM
    assert denied.title == (
        "60 anonymous requests were refused, all from 198.51.100.77 trying 60 different keys "
        "in 8 minutes"
    )
    assert ".env" in denied.summary and "and 54 more" in denied.summary
    assert "shop-assets-example is known outside" in denied.likely_cause
    assert "python-requests/2.31.0" in denied.likely_cause
    assert denied.row_count == 60 == rows_for(s3_ds, denied)
    assert len(denied.tables[1].rows) == 25  # keys tried, capped for display


def test_failed_requests_overview(s3_ds: Dataset) -> None:
    (f,) = by_rule(s3_ds, "errors")
    assert f.severity == Severity.HIGH
    assert f.title == "625 requests failed (12.9% of requests)"
    assert "The most common was 404 NoSuchKey (478), mostly under images/thumbs/" in f.summary
    assert "15 were 5xx" in f.summary
    assert "missing-keys finding" in f.likely_cause
    assert f.row_count == 625 == rows_for(s3_ds, f)
    codes = {(r[0], r[1]): r[2] for r in f.tables[0].rows}
    assert codes == {(404, "NoSuchKey"): 478, (403, "AccessDenied"): 132, (503, "SlowDown"): 15}
    prefixes = {r[0]: (r[1], r[4]) for r in f.tables[1].rows}
    assert prefixes["images/thumbs/"] == (478, "NoSuchKey")
    assert prefixes["exports/finance/"] == (72, "AccessDenied")


def test_missing_keys_name_who_deleted_them(s3_ds: Dataset) -> None:
    (f,) = by_rule(s3_ds, "missing_keys")
    assert f.id == "missing-keys-1" and f.severity == Severity.MEDIUM
    assert f.title == "478 requests for objects that do not exist under images/thumbs/"
    assert "478 requests for 237 different keys" in f.summary
    assert "referer from shop.example.com" in f.summary
    assert f.likely_cause.startswith(
        "All 237 missing keys were deleted earlier in this file by bob between "
        "2026-03-10 09:05 and 2026-03-10 09:07, and 478 of these requests came after that."
    )
    assert f.row_count == 478 == rows_for(s3_ds, f)
    assert [t.title for t in f.tables] == [
        "Most requested missing keys",
        "By referer",
        "By client address",
        "Deleted earlier in this file",
    ]
    assert all(k.startswith("images/thumbs/") for k, *_ in f.tables[0].rows)
    assert f.tables[3].rows[0][2] == "bob"


def test_refused_principal_is_a_retry_loop(s3_ds: Dataset) -> None:
    (f,) = by_rule(s3_ds, "access_denied")
    assert f.id == "access-denied-1" and f.severity == Severity.MEDIUM
    assert f.title == "shop-reports-role was refused 72 requests under exports/finance/"
    assert "on 1 key under exports/finance/ (REST.GET.OBJECT, about every 5 minutes)" in f.summary
    assert "was allowed 12 other requests." in f.summary
    assert f.likely_cause.startswith("Add s3:GetObject on exports/finance/* to shop-reports-role")
    assert f.row_count == 72 == rows_for(s3_ds, f)
    assert [t.title for t in f.tables] == ["By key prefix", "By operation", "By minute"]
    assert len(f.tables[2].rows) == 24


def test_delete_burst_links_to_the_404s(s3_ds: Dataset) -> None:
    (f,) = by_rule(s3_ds, "delete_burst")
    assert f.id == "delete-burst-1" and f.severity == Severity.HIGH
    assert f.title == "bob deleted 300 objects in 3 minutes under images/thumbs/"
    assert "from 198.51.100.21 with aws-cli/2.15.30" in f.summary
    assert "478 requests for 237 of those keys came back 404 afterwards." in f.summary
    assert "still in use when they were removed" in f.likely_cause
    assert f.row_count == 300 == rows_for(s3_ds, f)
    assert [t.title for t in f.tables] == ["By key prefix", "By minute", "First keys deleted"]
    assert [r[1] for r in f.tables[1].rows] == [100, 100, 100]


def test_top_clients_overview(s3_ds: Dataset) -> None:
    (f,) = by_rule(s3_ds, "top_clients")
    assert f.severity == Severity.INFO
    assert f.title == "Top principal: shop-web-role made 4,286 requests (88.7%)"
    assert "4,830 requests by 9 principals from 108 addresses, 4.5 GB sent" in f.summary
    assert "Most bytes went to 203.0.113.61 (4.1 GB, as anonymous)" in f.summary
    assert f.row_count == 4286 == rows_for(s3_ds, f)
    assert [t.title for t in f.tables] == [
        "By principal",
        "By client address",
        "By operation",
        "By user agent",
        "By key prefix",
    ]


def test_findings_are_ordered_and_timeline_counts_errors(s3_ds: Dataset) -> None:
    severities = [f.severity for f in s3_ds.findings]
    order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}
    assert severities == sorted(severities, key=order.__getitem__)
    assert len({f.id for f in s3_ds.findings}) == len(s3_ds.findings)
    tl = s3_ds.timeline
    assert tl is not None and tl["bucket"] == "minute"
    assert tl["title"] == "Requests against errors (4xx and 5xx)" and tl["unit"] == "requests"
    assert sum(tl["series"]["rejected"]) == 625
    assert sum(tl["series"]["accepted"]) + 625 == 4830
    assert tl["labels"][0] == "08:00" and len(tl["labels"]) == 120


def quiet_lines(samples: Path, keep: int) -> str:
    out: list[str] = []
    for line in (samples / "s3_access_logs.log").read_text().splitlines():
        fields = next(csv.reader([line], delimiter=" "))
        requester, operation, status = fields[5], fields[7], fields[10]
        if requester != "-" and status < "400" and operation != "REST.DELETE.OBJECT":
            out.append(line)
        if len(out) == keep:
            break
    return "\n".join(out) + "\n"


def test_quiet_bucket_reports_info_only(samples: Path, tmp_path: Path) -> None:
    ds = Dataset.open(write(tmp_path, "quiet.log", quiet_lines(samples, 400)))
    try:
        assert ds.table == "s3" and ds.rows == 400
        rules = {f.rule: f for f in ds.findings}
        assert rules["anonymous"].title == "No anonymous requests"
        assert rules["errors"].title == "Every request succeeded"
        assert set(rules) == {"anonymous", "errors", "top_clients"}
        assert all(f.severity == Severity.INFO for f in ds.findings)
        assert ds.timeline is not None and sum(ds.timeline["series"]["rejected"]) == 0
    finally:
        ds.close()


def test_background_anonymous_noise_is_low(samples: Path, tmp_path: Path) -> None:
    lines = quiet_lines(samples, 200).splitlines()
    probe = next(
        ln
        for ln in (samples / "s3_access_logs.log").read_text().splitlines()
        if " 198.51.100.77 - " in ln and " 403 AccessDenied " in ln
    )
    ds = Dataset.open(write(tmp_path, "noise.log", "\n".join([*lines, probe, probe]) + "\n"))
    try:
        (denied,) = by_rule(ds, "anonymous")
        assert denied.id == "anonymous-denied" and denied.severity == Severity.LOW
        assert denied.title == "2 anonymous requests were refused"
        assert denied.likely_cause == "Background noise from the internet; nothing to do."
        assert denied.row_count == 2 == rows_for(ds, denied)
    finally:
        ds.close()
