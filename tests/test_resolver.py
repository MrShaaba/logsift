from __future__ import annotations

from datetime import datetime
from pathlib import Path

from logsift.dataset import Dataset
from logsift.formats import detect_format
from logsift.loader import sniff
from tests.conftest import write


def count(ds: Dataset, where: str) -> int:
    return int(ds.cursor().execute(f"SELECT count(*) FROM dns WHERE {where}").fetchone()[0])


def test_dns_table_from_json_lines(dns_ds: Dataset) -> None:
    assert dns_ds.format.plugin == "route53_resolver" and dns_ds.table == "dns"
    assert dns_ds.format.options == {"source": "json", "line_column": "line"}
    assert dns_ds.sniff.json_lines and dns_ds.rows == 8102 and dns_ds.load.warnings == []
    names = [c for c, _ in dns_ds.columns]
    assert names[:8] == [
        "query_time",
        "srcaddr",
        "query_name",
        "query_type",
        "rcode",
        "answers",
        "answer_count",
        "domain",
    ]
    types = dict(dns_ds.columns)
    assert types["query_time"] == "TIMESTAMP" and types["srcport"] == "INTEGER"
    assert types["is_error"] == "BOOLEAN" and types["blocked"] == "BOOLEAN"
    assert count(dns_ds, "query_time IS NULL") == 0
    first, last = (
        dns_ds.cursor().execute("SELECT min(query_time), max(query_time) FROM dns").fetchone()
    )
    assert first == datetime(2026, 3, 10, 8, 0, 1) and last == datetime(2026, 3, 10, 9, 59, 57)
    row = (
        dns_ds.cursor()
        .execute(
            "SELECT answers, answer_count, domain, name_length, labels, instance_id, transport "
            "FROM dns WHERE query_name = 'shop.example.com.' AND answer_count = 2 LIMIT 1"
        )
        .fetchone()
    )
    assert row == ("203.0.113.10 203.0.113.11", 2, "example.com", 16, 3, row[5], row[6])
    assert row[5].startswith("i-0") and row[6] in ("UDP", "TCP")
    assert count(dns_ds, "blocked") == count(dns_ds, "firewall_action = 'BLOCK'") == 342
    assert count(dns_ds, "is_error") == count(dns_ds, "rcode <> 'NOERROR'") == 2565
    assert count(dns_ds, "domain = 'in-addr.arpa'") == count(dns_ds, "query_type = 'PTR'") == 284
    assert count(dns_ds, "domain = 'example.internal'") > 2000
    assert count(dns_ds, "answers = '' AND rcode = 'NOERROR'") > 0  # AAAA with no data


def test_dns_table_from_csv(samples: Path) -> None:
    ds = Dataset.open(samples / "route53_resolver_query_logs.csv")
    try:
        assert ds.format.plugin == "route53_resolver" and ds.table == "dns"
        assert ds.format.options == {"source": "csv"} and ds.format.kind == "route53_resolver"
        assert "CSV export" in ds.format.label
        assert ds.rows == 4052 and ds.load.warnings == []
        types = dict(ds.columns)
        assert types["query_time"] == "TIMESTAMP" and types["answer_count"] == "INTEGER"
        assert count(ds, "blocked") == 172 and count(ds, "answer_count = 2") > 0
        assert count(ds, "answers IS NULL AND answer_count = 0") > 0
        assert count(ds, "domain = 'bad.example'") == 172
        # The same hour of the JSON file: the same planted burst shows up.
        assert [f.id for f in ds.findings][:1] == ["nxdomain-burst-1"]
    finally:
        ds.close()


def test_detection_shapes(tmp_path: Path) -> None:
    rec = (
        '{"version":"1.100000","query_timestamp":"2026-03-10T08:00:00Z","query_name":"a.example.com.",'
        '"query_type":"A","rcode":"NOERROR","answers":[{"Rdata":"192.0.2.1","Type":"A","Class":"IN"}],'
        '"srcaddr":"10.0.0.1","srcport":"4242","transport":"UDP","srcids":{"instance":"i-1"}}\n'
    )
    gz = write(tmp_path, "q.json.gz", rec * 30, gz=True)
    info = detect_format(sniff(gz))
    assert info.plugin == "route53_resolver" and info.table == "dns"
    ds = Dataset.open(gz)
    try:
        assert ds.rows == 30 and count(ds, "answers = '192.0.2.1' AND domain = 'example.com'") == 30
        assert [f.id for f in ds.findings] == ["top-clients", "errors"]
        assert ds.findings[1].title == "Every query was answered"
    finally:
        ds.close()
    # Other JSON lines are not claimed.
    other = write(tmp_path, "o.json", '{"a": 1, "b": "x"}\n' * 20)
    assert detect_format(sniff(other)).plugin == "generic"
    # A CSV needs the three key columns and a fourth known one.
    csv = write(
        tmp_path,
        "d.csv",
        "query_name,rcode,srcaddr,query_type\na.example.com.,NOERROR,10.0.0.1,A\n",
    )
    assert detect_format(sniff(csv)).plugin == "route53_resolver"
    thin = write(tmp_path, "t.csv", "query_name,rcode,srcaddr\na.example.com.,NOERROR,10.0.0.1\n")
    assert detect_format(sniff(thin)).plugin == "generic"
    # Answers given as the JSON array text in a CSV are flattened too.
    arr = write(
        tmp_path,
        "arr.csv",
        "query_timestamp,query_name,query_type,rcode,answers,srcaddr\n"
        '2026-03-10T08:00:00Z,shop.example.co.uk.,A,NOERROR,"[{""Rdata"":""192.0.2.1""},{""Rdata"":""192.0.2.2""}]",10.0.0.1\n',
    )
    ds = Dataset.open(arr)
    try:
        row = ds.cursor().execute("SELECT answers, answer_count, domain FROM dns").fetchone()
        assert row == ("192.0.2.1 192.0.2.2", 2, "example.co.uk")
    finally:
        ds.close()
