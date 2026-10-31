from __future__ import annotations

from datetime import datetime

from logsift.dataset import Dataset
from logsift.explore import RowQuery, fetch_page
from logsift.insights.base import Finding, Severity


def by_rule(ds: Dataset, rule: str) -> list[Finding]:
    return [f for f in ds.findings if f.rule == rule]


def rows_for(ds: Dataset, f: Finding) -> int:
    return fetch_page(ds.cursor(), ds.table, RowQuery(where=f.row_filter), 1, 1).total


def test_asymmetric_flows_point_at_the_nacl(flow_ds: Dataset) -> None:
    (f,) = by_rule(flow_ds, "asymmetric_flows")
    assert f.severity == Severity.HIGH
    assert "320 requests" in f.title
    assert "10.0.2.10" in f.summary and "8080" in f.summary
    assert "stateless" in f.explanation and "stateful" in f.explanation
    assert "subnet-0a1b2c3d4e5f60001" in f.likely_cause
    clients = {r[0] for r in f.tables[0].rows}
    assert clients == {"10.0.1.10", "10.0.1.11", "10.0.1.12"}
    assert all(r[1] == "10.0.2.10" for r in f.tables[0].rows)
    assert f.row_count == rows_for(flow_ds, f) == 1280


def test_healthy_app_host_is_not_flagged(flow_ds: Dataset) -> None:
    (f,) = by_rule(flow_ds, "asymmetric_flows")
    assert "10.0.2.11" not in {r[1] for r in f.tables[0].rows}


def test_security_group_rejecting_5432(flow_ds: Dataset) -> None:
    clusters = by_rule(flow_ds, "rejected_cluster")
    f = clusters[0]
    assert f.severity == Severity.HIGH
    assert "5432" in f.title and "10.0.3.20" in f.title
    assert f.row_count == 160 == rows_for(flow_ds, f)
    assert {r[0] for r in f.tables[0].rows} == {"10.0.2.10", "10.0.2.11"}
    assert "no rule allowing TCP port 5432" in f.likely_cause
    # Internet background noise is ranked low, not as a missing rule.
    noise = [c for c in clusters if c.severity == Severity.LOW]
    assert noise and all("Unsolicited" in c.likely_cause for c in noise)


def test_rejected_traffic_overview(flow_ds: Dataset) -> None:
    (f,) = by_rule(flow_ds, "rejected_traffic")
    assert f.row_count == 861 == rows_for(flow_ds, f)
    titles = [t.title for t in f.tables]
    assert titles == [
        "By source, destination, port and protocol",
        "By network interface",
        "By subnet",
    ]
    top = f.tables[0].rows[0]
    assert (top[1], top[2]) == ("10.0.3.20", 5432)


def test_rejected_by_subnet_only_when_present(v2_ds: Dataset) -> None:
    (f,) = by_rule(v2_ds, "rejected_traffic")
    assert [t.title for t in f.tables] == [
        "By source, destination, port and protocol",
        "By network interface",
    ]


def test_syn_without_synack(flow_ds: Dataset, v2_ds: Dataset) -> None:
    (f,) = by_rule(flow_ds, "syn_without_synack")
    assert f.severity == Severity.MEDIUM
    assert f.row_count == 130 == rows_for(flow_ds, f)
    assert f.tables[0].rows[0][:4] == ("10.0.2.99", 9200, 130, 2)
    assert "Nothing is listening on port 9200 of 10.0.2.99" in f.likely_cause
    # The default v2 format has no tcp-flags, so the rule stays quiet.
    assert by_rule(v2_ds, "syn_without_synack") == []


def test_top_talker(flow_ds: Dataset) -> None:
    (f,) = by_rule(flow_ds, "top_talkers")
    assert f.title.startswith("Top talker: 10.0.1.12")
    assert f.severity == Severity.LOW
    assert f.tables[0].rows[0][0] == "10.0.1.12"
    convo = f.tables[1].rows[0]
    assert (convo[0], convo[1], convo[2]) == ("10.0.1.12", "203.0.113.9", 443)
    assert f.tables[2].title == "Top sources by packets"


def test_public_ip_traffic(flow_ds: Dataset) -> None:
    (f,) = by_rule(flow_ds, "public_traffic")
    assert f.severity == Severity.INFO
    assert f.row_count == rows_for(flow_ds, f) > 0
    public = {r[0] for r in f.tables[0].rows}
    assert "198.51.100.77" in public
    assert not any(ip.startswith("10.") for ip in public)


def test_port_sweep_is_stated_as_a_fact(flow_ds: Dataset) -> None:
    (f,) = by_rule(flow_ds, "port_sweep")
    assert "198.51.100.77" in f.title and "10.0.1.10" in f.title
    assert "201 different ports" in f.title
    assert "not as a verdict" in f.explanation
    assert f.row_count == 201 == rows_for(flow_ds, f)
    assert by_rule(flow_ds, "host_sweep") == []


def test_server_replies_do_not_look_like_a_sweep(flow_ds: Dataset) -> None:
    # Web servers answer hundreds of client ephemeral ports; none of them may be flagged.
    sweeps = by_rule(flow_ds, "port_sweep") + by_rule(flow_ds, "host_sweep")
    sources = {f.tables[0].rows[0][0] for f in sweeps}
    assert sources == {"198.51.100.77"}


def test_nodata_and_skipdata(flow_ds: Dataset) -> None:
    (skip,) = by_rule(flow_ds, "skipdata")
    (nodata,) = by_rule(flow_ds, "nodata")
    assert skip.row_count == 6 == rows_for(flow_ds, skip)
    assert nodata.row_count == 20 == rows_for(flow_ds, nodata)
    assert nodata.tables[0].rows[0][0] == "eni-0e5f6a7b8c9d00009"
    assert nodata.severity == Severity.INFO


def test_time_gap(flow_ds: Dataset) -> None:
    (f,) = by_rule(flow_ds, "time_gaps")
    assert "1 gap" in f.title
    before, after, minutes = f.tables[0].rows[0]
    assert before == datetime(2026, 3, 10, 9, 14)
    assert after == datetime(2026, 3, 10, 9, 35)
    assert minutes == 21


def test_no_gap_reported_for_continuous_export(cw_ds: Dataset) -> None:
    (f,) = by_rule(cw_ds, "time_gaps")
    assert f.title == "Continuous time range, no gaps"
    assert f.severity == Severity.INFO


def test_timeline(flow_ds: Dataset) -> None:
    tl = flow_ds.timeline
    assert tl is not None
    assert tl["bucket"] == "minute"
    assert len(tl["labels"]) == 120
    assert sum(tl["series"]["accepted"]) == 7770
    assert sum(tl["series"]["rejected"]) == 861
    assert tl["labels"][0] == "08:00"


def test_findings_are_sorted_by_severity(flow_ds: Dataset) -> None:
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    ranks = [order[str(f.severity)] for f in flow_ds.findings]
    assert ranks == sorted(ranks)
    assert flow_ds.findings[0].rule == "asymmetric_flows"


def test_every_row_filter_matches_its_count(flow_ds: Dataset, cw_ds: Dataset) -> None:
    for ds in (flow_ds, cw_ds):
        for f in ds.findings:
            assert rows_for(ds, f) == f.row_count, f.id
            assert ds.finding(f.id) is f


def test_same_problems_found_in_every_flow_format(v2_ds: Dataset, cw_ds: Dataset) -> None:
    for ds in (v2_ds, cw_ds):
        rules = {f.rule for f in ds.findings}
        assert {"asymmetric_flows", "rejected_cluster", "top_talkers", "public_traffic"} <= rules
        (a,) = by_rule(ds, "asymmetric_flows")
        assert a.tables[0].rows[0][1] == "10.0.2.10"


def test_generic_file_has_no_findings(sales_ds: Dataset) -> None:
    assert sales_ds.findings == []
    assert sales_ds.timeline is None
