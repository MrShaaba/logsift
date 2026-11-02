from __future__ import annotations

from datetime import datetime

import pytest

from logsift.dataset import Dataset
from logsift.insights.base import Finding, Severity
from logsift.insights.cwlogs import (
    Emitter,
    QuerySpec,
    boolean,
    build_query,
    like,
    mapped,
    parse_clause,
    private_ip,
)

SPEC = QuerySpec(
    fields={"a": "a", "b": "bField", "n": "n", "t": "t", "stamp": "stamp"},
    time_columns=("stamp", "t"),
    derived={
        "ok": boolean('x = "yes"', 'x = "no"'),
        "ip": like("client", "^{v}:"),
        "mfa": mapped("mfaUsed", {True: '"Yes"', False: '"No"'}),
        "nope": lambda op, v: None,
    },
    funcs={"is_private": private_ip},
    missing="-",
)


def tr(sql: str, spec: QuerySpec = SPEC) -> str:
    return Emitter(spec).run(sql).filter


def finding(row_filter: str, rule: str = "r") -> Finding:
    return Finding("f", rule, "Title", Severity.LOW, "", "", "", 1, row_filter)


def test_comparisons_and_boolean_logic() -> None:
    assert tr("a = 'x'") == 'a = "x"'
    assert tr("b <> 'x' AND n >= 3") == 'bField != "x" and n >= 3'
    assert tr("n != 3 OR (a = 'y' AND n < 2)") == '(n != 3 or (a = "y" and n < 2))'
    assert tr("NOT (a = 'x' OR a = 'y')") == 'not (a = "x" or a = "y")'
    assert tr("3 < n") == "n > 3"
    assert tr("a IN ('x', 'y''z')") == 'a in ["x", "y\'z"]'
    assert tr("n NOT IN (1, 2)") == "n not in [1, 2]"
    assert tr("n BETWEEN 500 AND 599") == "(n >= 500 and n <= 599)"
    assert tr("a LIKE '/api/%'") == "a like /^\\/api\\/.*$/"
    assert tr("a NOT ILIKE 'x_y'") == "a not like /(?i)^x.y$/"
    assert tr("a IS NULL AND b IS NOT NULL") == 'a = "-" and bField != "-"'
    assert tr("a IS NULL", QuerySpec(fields={"a": "a"})) == "not ispresent(a)"
    assert tr("a = NULL") == 'a = "-"'
    assert tr("\"a\" = 'quoted ident'") == 'a = "quoted ident"'


def test_true_false_and_coalesce() -> None:
    assert tr("TRUE") == ""
    assert tr("a = 'x' AND TRUE") == 'a = "x"'
    assert Emitter(SPEC).run("FALSE").never
    assert tr("coalesce(a, 'Success') = 'Success'") == '(a = "Success" or a = "-")'
    assert tr("coalesce(a, 'x') = 'y'") == 'a = "y"'
    assert tr("coalesce(a, 'x') <> 'x'") == '(a != "x" and a != "-")'


def test_derived_columns_and_functions() -> None:
    assert tr("ok") == 'x = "yes"'
    assert tr("NOT ok") == 'x = "no"'
    assert tr("ok = false") == 'x = "no"'
    assert tr("ip = '10.0.0.1'") == "client like /^10\\.0\\.0\\.1:/"
    assert tr("ip <> '10.0.0.1'") == "not (client like /^10\\.0\\.0\\.1:/)"
    assert tr("mfa = false") == 'mfaUsed = "No"'
    assert tr("NOT is_private(a)") == (
        'not (isIpv4InSubnet(a, "10.0.0.0/8") or isIpv4InSubnet(a, "172.16.0.0/12") '
        'or isIpv4InSubnet(a, "192.168.0.0/16"))'
    )


def test_untranslatable_parts_are_dropped_from_an_and_with_a_note() -> None:
    out = Emitter(SPEC).run("a = 'x' AND nope = 1 AND unknown_col = 2 AND weird(a) = 1")
    assert out.filter == 'a = "x"'
    assert len(out.dropped) == 3
    assert "nope cannot be expressed" in out.dropped[0]
    assert "no CloudWatch field for unknown_col" in out.dropped[1]
    assert "weird()" in out.dropped[2]
    # Inside an OR nothing can be dropped, so the whole OR goes.
    out = Emitter(SPEC).run("(a = 'x' OR nope = 1) AND n = 1")
    assert out.filter == "n = 1" and len(out.dropped) == 1
    out = Emitter(SPEC).run("a = 'x' AND (b = 1")
    assert out.filter == "" and "expected )" in out.dropped[0]


def test_time_conditions_become_the_range() -> None:
    out = Emitter(SPEC).run(
        "a = 'x' AND stamp >= TIMESTAMP '2026-03-10 09:05:00.000000' "
        "AND stamp < TIMESTAMP '2026-03-10 09:25:00.000000'"
    )
    assert out.filter == 'a = "x"'
    assert out.start == datetime(2026, 3, 10, 9, 5) and out.end == datetime(2026, 3, 10, 9, 25)
    out = Emitter(SPEC).run("((stamp >= '2026-03-10 09:14:00' AND stamp <= '2026-03-10 09:35:00'))")
    assert out.filter == "" and out.start == datetime(2026, 3, 10, 9, 14)
    out = Emitter(SPEC).run("t >= 1773132000 AND t < 1773132300")
    assert (out.start, out.end) == (datetime(2026, 3, 10, 8, 40), datetime(2026, 3, 10, 8, 45))
    out = Emitter(SPEC).run("stamp BETWEEN '2026-03-10' AND '2026-03-11'")
    assert out.start == datetime(2026, 3, 10) and out.end == datetime(2026, 3, 11)
    # A time condition inside an OR is just a comparison.
    out = Emitter(SPEC).run("a = 'x' OR t >= 1773132000")
    assert out.filter == '(a = "x" or t >= 1773132000)' and out.start is None


def test_query_text_rows_and_stats() -> None:
    spec = QuerySpec(
        fields={"a": "a", "stamp": "stamp"},
        time_columns=("stamp",),
        display=["a"],
        stats={"agg": "stats count(*) as n by {a} | sort n desc | limit 10"},
        notes=["Shipped from S3."],
        parse="parse @message '* *' as a, b",
    )
    q = build_query(finding("a = 'x' AND stamp >= '2026-03-10 08:00'"), spec)
    assert q.splitlines() == [
        "# Title",
        "# Time range: from 2026-03-10 08:00 UTC. Set it in the console's time picker.",
        "# Shipped from S3.",
        "fields @timestamp, a",
        "| parse @message '* *' as a, b",
        '| filter a = "x"',
        "| sort @timestamp desc",
        "| limit 200",
    ]
    q = build_query(finding("a = 'x'", rule="agg"), spec, (datetime(2026, 3, 10, 8), None))
    assert q.splitlines() == [
        "# Title",
        "# Time range: this file covers from 2026-03-10 08:00 UTC.",
        "# Shipped from S3.",
        "parse @message '* *' as a, b",
        '| filter a = "x"',
        "| stats count(*) as n by a",
        "| sort n desc",
        "| limit 10",
    ]
    q = build_query(finding("FALSE"), QuerySpec(fields={}))
    assert "no rows of its own" in q and "fields @timestamp, @message" in q and "filter" not in q
    q = build_query(finding("a = 'x' AND zzz = 1"), spec)
    assert "# Not expressed here, so this returns more rows than the finding: " in q


def test_parse_clause() -> None:
    assert (
        parse_clause(["a", "b", "c", "d"], quoted={"b"}, brackets={"c"})
        == "parse @message '* \"*\" [*] *' as a, b, c, d"
    )


# ------------------------------------------------------------ the real formats


def queries(ds: Dataset) -> dict[str, str]:
    return {f.id: f.query for f in ds.findings}


def test_every_finding_has_a_query(
    flow_ds: Dataset,
    v2_ds: Dataset,
    cw_ds: Dataset,
    alb_ds: Dataset,
    nlb_ds: Dataset,
    trail_ds: Dataset,
    s3_ds: Dataset,
) -> None:
    for ds in (flow_ds, v2_ds, cw_ds, alb_ds, nlb_ds, trail_ds, s3_ds):
        assert ds.findings
        for f in ds.findings:
            assert f.query.startswith(f"# {f.title}\n"), f.id
            lines = f.query.splitlines()
            assert lines[-1].startswith("| limit "), f.id
            body = [ln for ln in lines if not ln.startswith("#")]
            assert body[0].startswith(("fields ", "parse ", "filter ")), f.id
            assert not body[0].startswith("|"), f.id
            assert f.to_dict()["query"] == f.query


def test_flow_log_queries(v2_ds: Dataset, flow_ds: Dataset) -> None:
    q = queries(v2_ds)
    assert (
        'filter (logStatus = "-" or logStatus = "OK") and action = "REJECT" and '
        'dstAddr = "10.0.3.20" and dstPort = 5432 and protocol = 6 and '
        'interfaceId = "eni-0c3d4e5f6a7b80301"\n'
        "| stats count(*) as flows, sum(bytes) as bytes by srcAddr"
    ) in q["reject-cluster-1"]
    assert "# Time range: 2026-03-10 08:40 to 2026-03-10 08:45 UTC." in q["port-sweep-1"]
    assert 'srcAddr = "198.51.100.77" and dstAddr = "10.0.1.10"' in q["port-sweep-1"]
    assert "start" not in q["port-sweep-1"].split("filter")[1]
    assert 'isIpv4InSubnet(srcAddr, "10.0.0.0/8")' in q["public-ips"]
    assert "# Time range: 2026-03-10 09:14 to 2026-03-10 09:35 UTC." in q["time-gaps"]
    assert "| filter" not in q["time-gaps"]
    # The custom format is parsed out of @message under the file's own names.
    q = queries(flow_ds)
    stars = " ".join(["*"] * 25)
    assert f"parse @message '{stars}' as version, account_id, interface_id" in q["rejected"]
    assert "tcp_flags in [2, 3, 6, 7]" in q["syn-no-synack"]
    assert "# tcp_flags 2, 3, 6 and 7 are the values with SYN set" in q["syn-no-synack"]
    assert 'dstaddr = "10.0.2.99" and dstport = 9200' in q["syn-no-synack"]


def test_load_balancer_queries(alb_ds: Dataset, nlb_ds: Dataset) -> None:
    q = queries(alb_ds)
    assert "# ALB access logs are delivered to S3" in q["server-errors"]
    assert (
        'parse @message \'* * * * * * * * * * * * "*" "*" * * * "*" "*" "*" * * '
        '"*" "*" "*" "*" "*" "*" "*" *\' as type, time, elb, client, target'
    ) in q["server-errors"]
    assert (
        "| filter (elb_status_code >= 500 and elb_status_code <= 599) and "
        "target like /^10\\.0\\.2\\.11:/ and target like /:8080$/"
    ) in q["failing-target-1"]
    assert "# Time range: 2026-03-10 09:05 to 2026-03-10 09:25 UTC." in q["error-burst"]
    assert (
        'ssl_protocol in ["SSLv3", "TLSv1", "TLSv1.1", "sslv3", "tlsv1", "tlsv11"]'
        in (q["tls-versions"])
    )
    assert "client like /^198\\.51\\.100\\.77:/ and (elb_status_code >= 400" in q["probing-1"]
    q = queries(nlb_ds)
    assert '| filter tls_handshake_time = "-"' in q["tls-failures"]
    assert (
        'client like /^198\\.51\\.100\\.23:/ and tls_handshake_time != "-"'
        in (q["connection-churn-1"])
    )
    assert "# Time range: 2026-03-10 08:30 to 2026-03-10 08:34 UTC." in q["connection-churn-1"]


def test_cloudtrail_queries(trail_ds: Dataset) -> None:
    q = queries(trail_ds)
    denied = "errorCode like /AccessDenied|Unauthorized|Forbidden|AuthorizationError/"
    assert f"filter {denied}\n| stats count(*) as calls by userIdentity.arn" in q["access-denied"]
    assert f"userIdentity.arn like /[:/]bob(/|$)/ and {denied}" in q["denied-burst-1"]
    assert "# Time range: 2026-03-10 08:52 to 2026-03-10 08:58 UTC." in q["denied-burst-1"]
    assert '| filter userIdentity.type = "Root"' in q["root-activity"]
    assert (
        '| filter eventName = "ConsoleLogin" and (responseElements.ConsoleLogin = "Success" or '
        'not ispresent(responseElements.ConsoleLogin)) and additionalEventData.MFAUsed = "No"'
    ) in q["console-mfa"]
    assert 'awsRegion in ["ap-southeast-1", "us-east-2"]' in q["unusual-regions"]
    assert 'not (eventSource in ["iam.amazonaws.com"' in q["unusual-regions"]
    assert 'eventSource = "sts.amazonaws.com" and awsRegion = "us-east-1"' in q["unusual-regions"]
    assert (
        "fields @timestamp, eventTime, eventSource, eventName, userIdentity.arn"
        in (q["root-activity"])
    )


def test_s3_queries(s3_ds: Dataset) -> None:
    q = queries(s3_ds)
    assert "# S3 server access logs are delivered to a bucket" in q["errors"]
    assert (
        'parse @message \'* * [*] * * * * * "*" * * * * * * "*" "*" * * * * * * * * *\' '
        "as bucket_owner, bucket, time, remote_ip"
    ) in q["errors"]
    assert "| filter http_status >= 400\n| stats count(*) as requests by http_status" in q["errors"]
    assert '| filter requester = "-" and http_status < 400' in q["anonymous-reads"]
    assert "| filter http_status = 404 and key like /^images\\/thumbs\\//" in q["missing-keys-1"]
    assert (
        "| filter operation like /^[A-Z0-9]+\\.DELETE\\./ and requester like /bob/"
        in (q["delete-burst-1"])
    )
    assert (
        "| filter http_status = 403 and requester like /shop-reports-role/"
        in (q["access-denied-1"])
    )


@pytest.mark.parametrize("sql", ["a = 'x' AND", "a = = 1", "a BETWEEN 1", "'x'", "~a"])
def test_bad_sql_is_dropped_not_raised(sql: str) -> None:
    out = Emitter(SPEC).run(sql)
    assert out.filter == "" and out.dropped
