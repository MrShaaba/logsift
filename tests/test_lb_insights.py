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


def test_alb_server_errors_overview(alb_ds: Dataset) -> None:
    (f,) = by_rule(alb_ds, "server_errors")
    assert f.severity == Severity.HIGH
    assert f.title == "402 server errors (9.7% of requests)"
    assert "mostly 502 answered by the load balancer" in f.summary
    assert "closed the connection" in f.likely_cause
    assert f.row_count == 402 == rows_for(alb_ds, f)
    assert [t.title for t in f.tables] == ["By status code", "By path", "By target"]
    status, origin, count, _ = f.tables[0].rows[0]
    assert (status, origin, count) == (502, "load balancer", 391)
    assert f.tables[2].rows[0][0] == "10.0.2.11:8080"


def test_alb_error_burst_is_the_planted_window(alb_ds: Dataset) -> None:
    (f,) = by_rule(alb_ds, "error_bursts")
    assert f.severity == Severity.HIGH
    assert f.title.startswith("1 burst of server errors")
    (start, stop, requests, errors, share, code, target) = f.tables[0].rows[0]
    assert (start.hour, start.minute, stop.hour, stop.minute) == (9, 5, 9, 25)
    assert errors == f.row_count == rows_for(alb_ds, f)
    assert share > 40 and requests > errors
    assert (code, target) == (502, "10.0.2.11:8080")
    assert "10.0.2.11:8080 stopped answering" in f.likely_cause


def test_alb_failing_target_with_passing_health_check(alb_ds: Dataset) -> None:
    (f,) = by_rule(alb_ds, "failing_target")
    assert f.severity == Severity.HIGH
    assert f.title.startswith("Target 10.0.2.11:8080 failed 48%")
    assert f.row_count == 396 == rows_for(alb_ds, f)
    assert "mostly 502 between 2026-03-10 09:05 and 2026-03-10 09:24" in f.summary
    assert "no response from the target at all" in f.summary
    assert "health check" in f.likely_cause and "crash loop" in f.likely_cause
    siblings = {r[0]: r for r in f.tables[0].rows}
    assert set(siblings) == {"10.0.2.10:8080", "10.0.2.11:8080"}
    assert siblings["10.0.2.10:8080"][3] < 2  # the healthy sibling's 5xx share


def test_alb_slow_path_and_timeouts(alb_ds: Dataset) -> None:
    (f,) = by_rule(alb_ds, "slow_requests")
    assert f.severity == Severity.MEDIUM
    assert f.title == "60 slow requests took 2 s or more, 8 timed out"
    assert "/api/reports/export" in f.summary and "/api/reports/export" in f.likely_cause
    assert f.row_count == 60 == rows_for(alb_ds, f)
    slowest = f.tables[0].rows[0]
    assert slowest[0] == "/api/reports/export" and slowest[5] == 8  # 504 column
    assert f.tables[1].title == "By target"


def test_alb_client_errors_point_at_the_prober(alb_ds: Dataset) -> None:
    (f,) = by_rule(alb_ds, "client_errors")
    assert f.severity == Severity.LOW
    assert f.row_count == 197 == rows_for(alb_ds, f)
    assert "198.51.100.77 alone produced 79.2%" in f.likely_cause
    assert f.tables[0].rows[0][:2] == (404, "target")
    assert (400, "load balancer", 6) in f.tables[0].rows


def test_alb_probing_is_stated_as_a_fact(alb_ds: Dataset) -> None:
    (f,) = by_rule(alb_ds, "path_probing")
    assert f.severity == Severity.LOW
    assert f.title == "198.51.100.77 tried 60 different paths and got 156 client errors"
    assert "python-requests/2.31.0" in f.summary
    assert "not as a verdict" in f.explanation
    assert f.row_count == 156 == rows_for(alb_ds, f)
    paths = {r[0] for r in f.tables[0].rows}
    assert "/wp-login.php" in paths or "/.env" in paths
    assert "(malformed request)" in paths


def test_alb_old_tls_clients(alb_ds: Dataset) -> None:
    (f,) = by_rule(alb_ds, "tls_versions")
    assert f.severity == Severity.LOW
    assert f.title == "40 requests still used TLSv1.1"
    assert "96 requests arrived over plain HTTP" in f.summary
    client, proto, n, agent = f.tables[0].rows[0]
    assert (client, proto, n, agent) == ("203.0.113.61", "TLSv1.1", 40, "Java/1.7.0_80")
    assert f.row_count == 40 == rows_for(alb_ds, f)


def test_alb_top_clients(alb_ds: Dataset) -> None:
    (f,) = by_rule(alb_ds, "top_clients")
    assert f.severity == Severity.INFO
    assert f.title.startswith("Top client: 198.51.100.77 made 156 requests")
    assert [t.title for t in f.tables] == [
        "Top clients by requests",
        "Top clients by bytes sent",
        "Top user agents",
    ]


def test_alb_timeline(alb_ds: Dataset) -> None:
    tl = alb_ds.timeline
    assert tl is not None
    assert tl["bucket"] == "minute" and len(tl["labels"]) == 120
    assert tl["title"] == "Requests against server errors (5xx)"
    assert (tl["good"], tl["bad"], tl["unit"]) == ("ok", "5xx", "requests")
    assert sum(tl["series"]["rejected"]) == 402
    assert sum(tl["series"]["accepted"]) == 4156 - 402
    assert max(tl["series"]["rejected"]) >= 15  # the burst minutes stand out


def test_nlb_handshake_failures(nlb_ds: Dataset) -> None:
    (f,) = by_rule(nlb_ds, "tls_handshake_failures")
    assert f.severity == Severity.HIGH
    assert f.title == "190 TLS handshakes failed (6.3% of connections)"
    assert "120 ended with unknown_ca from 1 client" in f.summary
    assert "30 sent no valid client hello" in f.summary
    assert f.row_count == 190 == rows_for(nlb_ds, f)
    alerts = [(r[0], r[1], r[2]) for r in f.tables[0].rows]
    assert alerts == [
        ("unknown_ca", 120, 1),
        ("bad_certificate", 40, 1),
        ("no client hello", 30, 1),
    ]
    for phrase in ("trust store", "SNI shows as none", "port scan"):
        assert phrase in f.likely_cause
    clients = {r[0]: r for r in f.tables[1].rows}
    assert clients["198.51.100.88"][2] == "(none)"  # connected without a server name
    assert clients["198.51.100.33"][3] == "-"  # no protocol negotiated at all


def test_nlb_connection_churn_narrows_to_the_burst(nlb_ds: Dataset) -> None:
    (f,) = by_rule(nlb_ds, "connection_churn")
    assert f.severity == Severity.MEDIUM
    assert f.title.startswith("198.51.100.23 opened 601 connections in 4 minutes")
    assert "about 150 a minute" in f.summary or "about 151 a minute" in f.summary
    assert "Between 2026-03-10 08:30 and 2026-03-10 08:33" in f.summary
    assert "http/1.1" in f.likely_cause
    assert f.row_count == 601 == rows_for(nlb_ds, f)
    assert f.tables[0].rows[0][0] == "198.51.100.23"


def test_nlb_old_tls_and_top_clients(nlb_ds: Dataset) -> None:
    (tls,) = by_rule(nlb_ds, "tls_versions")
    assert tls.title == "25 connections still used tlsv11"
    assert tls.tables[0].columns == ["client", "protocol", "connections"]
    assert tls.tables[0].rows[0][:2] == ("203.0.113.62", "tlsv11")
    (top,) = by_rule(nlb_ds, "top_clients")
    assert top.title.startswith("Top client: 198.51.100.23 made 628 connections")
    assert len(top.tables) == 2  # no user agents in an NLB log


def test_nlb_timeline(nlb_ds: Dataset) -> None:
    tl = nlb_ds.timeline
    assert tl is not None
    assert tl["title"] == "Completed connections against failed TLS handshakes"
    assert sum(tl["series"]["rejected"]) == 190
    assert tl["unit"] == "connections"


def test_rules_only_fire_for_their_format(alb_ds: Dataset, nlb_ds: Dataset) -> None:
    alb_rules = {f.rule for f in alb_ds.findings}
    nlb_rules = {f.rule for f in nlb_ds.findings}
    assert "tls_handshake_failures" not in alb_rules and "server_errors" not in nlb_rules
    assert {"tls_versions", "top_clients"} <= alb_rules & nlb_rules


def test_every_row_filter_matches_its_count(alb_ds: Dataset, nlb_ds: Dataset) -> None:
    for ds in (alb_ds, nlb_ds):
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        ranks = [order[str(f.severity)] for f in ds.findings]
        assert ranks == sorted(ranks)
        for f in ds.findings:
            assert rows_for(ds, f) == f.row_count, f.id
            assert ds.finding(f.id) is f


def healthy_lines(samples: Path, name: str, keep: int) -> list[str]:
    """Sample lines with no planted problem in them."""
    out: list[str] = []
    for line in (samples / name).read_text().splitlines():
        fields = next(csv.reader([line], delimiter=" "))
        if name.startswith("alb"):
            ok = (
                fields[8] == "200"
                and fields[15] in ("TLSv1.2", "TLSv1.3")
                and float(fields[6]) < 1.0
            )
        else:
            ok = (
                fields[8] != "-"
                and fields[15] != "tlsv11"
                and fields[5].split(":")[0] != "198.51.100.23"
            )
        if ok:
            out.append(line)
        if len(out) == keep:
            break
    return out


def test_healthy_alb_log_reports_quiet(samples: Path, tmp_path: Path) -> None:
    text = "\n".join(healthy_lines(samples, "alb_access_logs.log", 300)) + "\n"
    ds = Dataset.open(write(tmp_path, "quiet.log", text))
    assert ds.is_lb_log and ds.rows == 300
    rules = {f.rule: f for f in ds.findings}
    assert rules["server_errors"].title == "No server errors"
    assert rules["server_errors"].severity == Severity.INFO
    assert rules["slow_requests"].title == "Target response times look healthy"
    assert rules["tls_versions"].title == "All TLS connections used TLS 1.2 or 1.3"
    for absent in ("error_bursts", "failing_target", "client_errors", "path_probing"):
        assert absent not in rules
    assert all(f.severity == Severity.INFO for f in ds.findings)


def test_healthy_nlb_log_reports_quiet(samples: Path, tmp_path: Path) -> None:
    text = "\n".join(healthy_lines(samples, "nlb_access_logs.log", 300)) + "\n"
    ds = Dataset.open(write(tmp_path, "quiet.log", text))
    rules = {f.rule: f for f in ds.findings}
    assert rules["tls_handshake_failures"].title == "Every TLS handshake completed"
    assert "connection_churn" not in rules
    assert rules["tls_versions"].severity == Severity.INFO
    assert ds.timeline is not None and sum(ds.timeline["series"]["rejected"]) == 0
