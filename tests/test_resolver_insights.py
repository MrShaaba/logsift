from __future__ import annotations

from pathlib import Path

from logsift.dataset import Dataset
from logsift.insights.base import Severity
from tests.conftest import write


def by_id(ds: Dataset) -> dict[str, object]:
    return {f.id: f for f in ds.findings}


def test_findings_on_the_sample(dns_ds: Dataset) -> None:
    f = by_id(dns_ds)
    assert [x.id for x in dns_ds.findings] == [
        "nxdomain-burst-2",
        "tunnel-1",
        "nxdomain-burst-1",
        "firewall-blocks",
        "errors",
        "servfail-1",
        "top-clients",
    ]
    # Every finding's filter selects exactly the rows it counts.
    for x in dns_ds.findings:
        n = dns_ds.cursor().execute(f"SELECT count(*) FROM dns WHERE {x.row_filter}").fetchone()[0]
        assert n == x.row_count, x.id
        assert x.query.startswith(f"# {x.title}")

    blocks = f["firewall-blocks"]
    assert blocks.severity == Severity.HIGH and blocks.row_count == 342
    assert blocks.title == "DNS Firewall blocked 342 queries for 3 names under bad.example"
    assert "all from 10.0.1.11 (i-0a1b2c3d4e5f60102)" in blocks.summary
    assert "a process on a timer rather than a person" in blocks.summary
    assert [t.title for t in blocks.tables] == ["Blocked names", "By host", "By domain", "Per hour"]

    dga = f["nxdomain-burst-2"]
    assert dga.severity == Severity.HIGH and dga.row_count == 1490
    assert dga.title == "10.0.2.11 got NXDOMAIN for 1,490 different names in 14 minutes"
    assert "spread across .example, .test, .invalid" in dga.summary
    assert "domain generation algorithm" in dga.summary
    assert "Malware on 10.0.2.11" in dga.likely_cause

    sweep = f["nxdomain-burst-1"]
    assert sweep.title == "10.0.0.5 got NXDOMAIN for 590 different names in 10 minutes"
    assert "Nearly all of the names were under example.internal, and 190 were reverse lookups" in (
        sweep.summary
    )
    assert "enumerating example.internal" in sweep.likely_cause
    # The hosts already explained as bursts or tunnels are not reported as sweeps again.
    assert not any(x.rule == "name_sweep" for x in dns_ds.findings)

    tunnel = f["tunnel-1"]
    assert tunnel.severity == Severity.HIGH and tunnel.row_count == 700
    assert tunnel.title == (
        "Possible DNS tunnel: 10.0.2.10 sent 700 TXT queries with 48-character labels under "
        "dns.example.net"
    )
    assert "700 were answered, with answers averaging 62 characters" in tunnel.summary
    assert "Block dns.example.net in DNS Firewall" in tunnel.likely_cause

    sf = f["servfail-1"]
    assert sf.severity == Severity.MEDIUM and sf.row_count == 68
    assert sf.title == "SERVFAIL for 68 queries under example.internal over 6 minutes"
    assert "68 of the 70 queries for names under example.internal (97%)" in sf.summary
    assert "forwarding to on-premises or VPC DNS servers" in sf.likely_cause

    errors = f["errors"]
    assert errors.severity == Severity.MEDIUM and errors.row_count == 2565
    assert "NXDOMAIN 2,497, SERVFAIL 68" in errors.summary

    top = f["top-clients"]
    assert top.severity == Severity.INFO
    assert top.title == "Top client: 10.0.2.11 made 2,421 queries (29.9%)"
    assert "s3.eu-west-1.amazonaws.com. (569 queries from 7 hosts)" in top.summary
    assert [t.title for t in top.tables][-1] == "By transport"


def test_timeline(dns_ds: Dataset) -> None:
    tl = dns_ds.timeline
    assert tl is not None and tl["bucket"] == "minute" and len(tl["labels"]) == 120
    assert tl["good"] == "answered" and tl["bad"] == "failed or blocked"
    assert sum(tl["series"]["rejected"]) == 2565 and sum(tl["series"]["accepted"]) == 5537
    assert tl["labels"][0] == "08:00"


def test_logs_insights_queries(dns_ds: Dataset) -> None:
    f = by_id(dns_ds)
    q = f["firewall-blocks"].query
    assert (
        'filter firewall_rule_action = "BLOCK"\n| stats count(*) as queries by query_name, srcaddr'
        in q
    )
    q = f["nxdomain-burst-1"].query
    assert "# Time range: 2026-03-10 09:10 to 2026-03-10 09:20 UTC." in q
    assert (
        'filter rcode = "NXDOMAIN" and (not ispresent(firewall_rule_action) or '
        'firewall_rule_action != "BLOCK") and srcaddr = "10.0.0.5"'
    ) in q
    q = f["tunnel-1"].query
    assert 'srcaddr = "10.0.2.10" and query_name like /(^|\\.)example\\.net\\.?$/' in q
    assert "fields @timestamp, query_timestamp, srcaddr, query_name" in q
    q = f["servfail-1"].query
    assert 'filter rcode = "SERVFAIL" and query_name like /(^|\\.)example\\.internal\\.?$/' in q
    assert "# Time range: 2026-03-10 09:00 to 2026-03-10 09:06 UTC." in q


def test_name_sweep_rule_on_a_quiet_fleet(tmp_path: Path) -> None:
    """A host resolving hundreds of existing names stands out against quiet neighbours."""
    lines = []
    t = 0
    for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"):
        for i in range(40):
            t += 1
            lines.append(record(t, host, f"svc{i % 10}.example.com.", "NOERROR", "192.0.2.5"))
    for i in range(400):
        t += 1
        lines.append(
            record(t, "10.0.0.9", f"node-{i}.corp.example.internal.", "NOERROR", "10.0.5.1")
        )
    path = write(tmp_path, "sweep.json", "\n".join(lines) + "\n")
    ds = Dataset.open(path)
    try:
        ids = [f.id for f in ds.findings]
        assert ids == ["name-sweep-1", "top-clients", "errors"]
        sweep = ds.findings[0]
        assert (
            sweep.title == "10.0.0.9 looked up 400 different names; the typical host asked for 10"
        )
        assert sweep.severity == Severity.MEDIUM and sweep.row_count == 400
        assert "mostly under example.internal" in sweep.summary
        assert ds.findings[2].title == "Every query was answered"
    finally:
        ds.close()


def record(second: int, src: str, name: str, rcode: str, rdata: str) -> str:
    minute, sec = divmod(second, 60)
    stamp = f"2026-03-10T08:{minute:02d}:{sec:02d}Z"
    answers = f'[{{"Rdata":"{rdata}","Type":"A","Class":"IN"}}]' if rcode == "NOERROR" else "[]"
    return (
        f'{{"version":"1.100000","account_id":"123456789012","region":"eu-west-1",'
        f'"vpc_id":"vpc-1","query_timestamp":"{stamp}","query_name":"{name}","query_type":"A",'
        f'"query_class":"IN","rcode":"{rcode}","answers":{answers},"srcaddr":"{src}",'
        f'"srcport":"4242","transport":"UDP","srcids":{{"instance":"i-{src.split(".")[-1]}"}}}}'
    )
