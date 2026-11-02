from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from logsift.web.app import create_app


@pytest.fixture(scope="module")
def client(tmp_path_factory: pytest.TempPathFactory, samples: Path) -> TestClient:
    app = create_app(data_dir=tmp_path_factory.mktemp("data"), samples_dir=samples)
    return TestClient(app)


@pytest.fixture(scope="module")
def flow_url(client: TestClient) -> str:
    r = client.post(
        "/load-sample", data={"name": "vpc_flow_logs_custom_v5.log"}, follow_redirects=False
    )
    assert r.status_code == 303
    return r.headers["location"]


def test_index_lists_samples(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "Drag a file here" in r.text
    assert "daily_sales.csv" in r.text


def test_overview_shows_format_counts_and_findings(client: TestClient, flow_url: str) -> None:
    r = client.get(flow_url)
    assert r.status_code == 200
    assert "VPC Flow Logs, custom format with header" in r.text
    assert "8,657" in r.text
    assert "Return traffic blocked" in r.text
    assert "Likely cause:" in r.text
    assert 'class="timeline"' in r.text
    assert "What this file looks like" in r.text


def test_explore_filters_and_pages(client: TestClient, flow_url: str) -> None:
    r = client.get(f"{flow_url}/explore?finding=asymmetric")
    assert r.status_code == 200
    assert "Showing the rows behind" in r.text
    assert "of 1,280" in r.text
    r = client.get(f"{flow_url}/rows?finding=asymmetric&page=3")
    assert "Page 3 of 26" in r.text
    r = client.get(f"{flow_url}/rows?col=dstport&val=5432&q=reject")
    assert "of 160" in r.text
    r = client.get(f"{flow_url}/rows?sort=bytes&desc=1")
    assert "bytes ▼" in r.text
    r = client.get(f"{flow_url}/rows?q=nothing-matches-this")
    assert "No rows match" in r.text


def test_finding_cards_carry_a_logs_insights_query(client: TestClient, flow_url: str) -> None:
    r = client.get(flow_url)
    assert "CloudWatch Logs Insights query" in r.text
    assert 'data-copy="query-reject-cluster-1"' in r.text
    assert "button.copy" in r.text  # the copy handler ships with the page
    assert "| filter (log_status = &#34;-&#34; or log_status = &#34;OK&#34;) and action" in r.text
    data = client.get(f"{flow_url}/export/findings.json").json()
    assert all(f["query"].startswith("# ") for f in data)
    header = client.get(f"{flow_url}/export/findings.csv").text.splitlines()[0]
    assert header.endswith(",rule,query")


def test_exports(client: TestClient, flow_url: str) -> None:
    for fmt, ctype in (("csv", "text/csv"), ("json", "application/json"), ("xlsx", "sheet")):
        r = client.get(f"{flow_url}/export/findings.{fmt}")
        assert r.status_code == 200 and ctype in r.headers["content-type"]
        assert "attachment" in r.headers["content-disposition"]
        r = client.get(f"{flow_url}/export/rows.{fmt}?finding=reject-cluster-1")
        assert r.status_code == 200 and ctype in r.headers["content-type"]
    rows = client.get(f"{flow_url}/export/rows.csv?finding=reject-cluster-1").text.splitlines()
    assert len(rows) == 161
    assert not rows[0].startswith("row_no")


def test_upload_and_close(client: TestClient, samples: Path) -> None:
    with (samples / "daily_sales.csv").open("rb") as fh:
        r = client.post(
            "/upload", files={"file": ("sales.csv", fh, "text/csv")}, follow_redirects=False
        )
    assert r.status_code == 303
    url = r.headers["location"]
    page = client.get(url)
    assert "Generic delimited file" in page.text
    assert "Findings" not in page.text
    r = client.post(f"{url}/close", follow_redirects=False)
    assert r.status_code == 303
    assert client.get(url).status_code == 404


def test_errors_render_as_html(client: TestClient, flow_url: str) -> None:
    r = client.get("/d/missing")
    assert r.status_code == 404
    assert "no longer loaded" in r.text and "<html" in r.text
    assert client.get(f"{flow_url}/explore?finding=nope").status_code == 404
    assert client.get(f"{flow_url}/export/findings.pdf").status_code == 404


def test_load_balancer_overview_explore_and_export(client: TestClient) -> None:
    r = client.post("/load-sample", data={"name": "alb_access_logs.log"}, follow_redirects=False)
    url = r.headers["location"]
    page = client.get(url)
    assert page.status_code == 200
    assert "Application Load Balancer access log" in page.text
    assert "Requests against server errors (5xx), per minute" in page.text
    assert "Target 10.0.2.11:8080 failed 48% of its requests" in page.text
    assert "Likely cause:" in page.text
    r = client.get(f"{url}/explore?finding=failing-target-1")
    assert r.status_code == 200 and "of 396" in r.text
    r = client.get(
        f"{url}/rows?col=path&val=/api/reports/export&sort=target_processing_time&desc=1"
    )
    assert "of 60" in r.text
    rows = client.get(f"{url}/export/rows.csv?finding=probing-1").text.splitlines()
    assert len(rows) == 157 and rows[0].startswith("time,type,client_ip")
    assert client.get(f"{url}/export/findings.xlsx").status_code == 200


def test_nlb_overview(client: TestClient) -> None:
    r = client.post("/load-sample", data={"name": "nlb_access_logs.log"}, follow_redirects=False)
    page = client.get(r.headers["location"])
    assert "Network Load Balancer access log" in page.text
    assert "Completed connections against failed TLS handshakes" in page.text
    assert "190 TLS handshakes failed" in page.text


def test_cloudtrail_overview_explore_and_export(client: TestClient) -> None:
    r = client.post("/load-sample", data={"name": "cloudtrail_events.csv"}, follow_redirects=False)
    url = r.headers["location"]
    page = client.get(url)
    assert page.status_code == 200
    assert "CloudTrail event export" in page.text
    assert "API calls against errors, per minute" in page.text
    assert "bob was refused 220 calls in 6 minutes across 22 different actions" in page.text
    assert "3 console sign-ins without MFA, 1 by the root account" in page.text
    r = client.get(f"{url}/explore?finding=denied-burst-1")
    assert r.status_code == 200 and "of 220" in r.text
    r = client.get(f"{url}/rows?col=principal&val=root&sort=event_time")
    assert "of 11" in r.text
    rows = client.get(f"{url}/export/rows.csv?finding=console-mfa").text.splitlines()
    assert len(rows) == 4 and rows[0].startswith("event_time,event_name,service,principal")
    assert client.get(f"{url}/export/findings.xlsx").status_code == 200


def test_s3_overview_explore_and_export(client: TestClient) -> None:
    r = client.post("/load-sample", data={"name": "s3_access_logs.log"}, follow_redirects=False)
    url = r.headers["location"]
    page = client.get(url)
    assert page.status_code == 200
    assert "S3 server access log" in page.text
    assert "Requests against errors (4xx and 5xx), per minute" in page.text
    assert "15 anonymous requests succeeded, reading 13 objects (4.1 GB)" in page.text
    assert "bob deleted 300 objects in 3 minutes under images/thumbs/" in page.text
    r = client.get(f"{url}/explore?finding=missing-keys-1")
    assert r.status_code == 200 and "of 478" in r.text
    r = client.get(f"{url}/rows?col=principal&val=anonymous&sort=bytes_sent&desc=1")
    assert "of 75" in r.text
    rows = client.get(f"{url}/export/rows.csv?finding=anonymous-reads").text.splitlines()
    assert len(rows) == 16 and rows[0].startswith("time,remote_ip,principal,operation,key")
    assert client.get(f"{url}/export/findings.xlsx").status_code == 200


def test_resolver_overview_explore_and_export(client: TestClient) -> None:
    r = client.post(
        "/load-sample", data={"name": "route53_resolver_query_logs.json"}, follow_redirects=False
    )
    url = r.headers["location"]
    page = client.get(url)
    assert page.status_code == 200
    assert "Route 53 Resolver query log" in page.text and "JSON lines" in page.text
    assert "no header row" not in page.text
    assert "Answered queries against failed or blocked ones" in page.text
    assert "DNS Firewall blocked 342 queries for 3 names under bad.example" in page.text
    assert "Possible DNS tunnel: 10.0.2.10 sent 700 TXT queries" in page.text
    assert "filter firewall_rule_action = &#34;BLOCK&#34;" in page.text
    r = client.get(f"{url}/explore?finding=firewall-blocks")
    assert r.status_code == 200 and "of 342" in r.text
    r = client.get(f"{url}/rows?col=rcode&val=SERVFAIL&sort=query_time")
    assert "of 68" in r.text
    rows = client.get(f"{url}/export/rows.csv?finding=servfail-1").text.splitlines()
    assert len(rows) == 69 and rows[0].startswith("query_time,srcaddr,query_name,query_type")
    assert client.get(f"{url}/export/findings.xlsx").status_code == 200


def test_sample_full_pass_progress_and_restart(tmp_path: Path, samples: Path) -> None:
    data = tmp_path / "data"
    app = create_app(data_dir=data, samples_dir=samples, sample_rows=2000)
    client = TestClient(app)
    r = client.post(
        "/load-sample", data={"name": "vpc_flow_logs_custom_v5.log"}, follow_redirects=False
    )
    url = r.headers["location"]
    ds_id = url.rsplit("/", 1)[1]
    page = client.get(url)
    assert "Showing the first 2,000 rows" in page.text
    assert "Run the full pass" in page.text and "Rows (sample)" in page.text
    assert "first 2,000 rows" in client.get("/").text
    assert client.get(f"{url}/rows").status_code == 200

    r = client.post(f"{url}/full", follow_redirects=False)
    assert r.status_code == 303
    registry = app.state.registry
    ds = registry.get(ds_id)
    # While the pass runs the panel polls, and closing the file is refused.
    if ds.loading:
        assert client.post(f"{url}/close", follow_redirects=False).status_code == 409
        panel = client.get(f"{url}/progress")
        assert 'hx-trigger="every 1s"' in panel.text and "HX-Refresh" not in panel.headers
    ds.wait(60)
    panel = client.get(f"{url}/progress")
    assert panel.headers.get("HX-Refresh") == "true" and "Loaded 8,657 rows" in panel.text
    page = client.get(url)
    assert "8,657" in page.text and "Showing the first" not in page.text
    assert "Return traffic blocked" in page.text
    assert client.get(f"{url}/rows?finding=asymmetric").status_code == 200
    assert "of 1,280" in client.get(f"{url}/explore?finding=asymmetric").text
    # Nothing to do now: the button is gone and a second request is a plain redirect.
    assert client.post(f"{url}/full", follow_redirects=False).status_code == 303

    # A new process picks the file up from the store without reloading it.
    again = create_app(
        data_dir=data,
        samples_dir=samples,
        sample_rows=2000,
        preload=[samples / "vpc_flow_logs_custom_v5.log"],
    )
    client2 = TestClient(again)
    home = client2.get("/")
    assert home.text.count("vpc_flow_logs_custom_v5.log</strong>") == 1  # preload was a no-op
    assert again.state.registry.get(ds_id).rows == 8657
    assert "Return traffic blocked" in client2.get(url).text
    assert client2.post(f"{url}/close", follow_redirects=False).status_code == 303
    assert client2.get(url).status_code == 404
    assert not (data / "db" / f"{ds_id}.duckdb").exists()


def test_uploads_survive_a_restart_and_close_removes_them(tmp_path: Path, samples: Path) -> None:
    data = tmp_path / "data"
    client = TestClient(create_app(data_dir=data, samples_dir=None))
    with (samples / "daily_sales.csv").open("rb") as fh:
        r = client.post(
            "/upload", files={"file": ("sales.csv", fh, "text/csv")}, follow_redirects=False
        )
    url = r.headers["location"]
    uploads = list((data / "uploads").iterdir())
    assert len(uploads) == 1
    client2 = TestClient(create_app(data_dir=data, samples_dir=None))
    assert "sales.csv" in client2.get("/").text
    assert client2.get(url).status_code == 200
    client2.post(f"{url}/close")
    assert not uploads[0].exists() and list((data / "db").glob("*.duckdb")) == []


def test_investigations_pin_note_export_and_delete(tmp_path: Path, samples: Path) -> None:
    app = create_app(data_dir=tmp_path / "data", samples_dir=samples)
    client = TestClient(app)
    assert "Nothing yet" in client.get("/investigations").text
    r = client.post(
        "/load-sample", data={"name": "vpc_flow_logs_custom_v5.log"}, follow_redirects=False
    )
    url = r.headers["location"]
    page = client.get(url)
    assert "a new investigation, made on the first pin" in page.text
    assert "Pin to investigation" in page.text

    # The first pin creates an investigation named after the file.
    r = client.post(
        f"{url}/pin",
        data={"kind": "finding", "finding": "asymmetric"},
        headers={"HX-Request": "true"},
    )
    assert r.status_code == 200
    assert "Pinned to <a href=" in r.text and "Investigation: vpc_flow_logs_custom_v5.log" in r.text
    inv = app.state.registry.active()
    assert inv is not None and len(inv.pins) == 1
    page = client.get(url)
    assert f'Pinned to <a href="/investigations/{inv.id}">' in page.text
    assert "receives pins" not in page.text and f'<option value="{inv.id}" selected>' in page.text

    # Pinning a second finding without HTMX redirects back to the referring page.
    r = client.post(
        f"{url}/pin",
        data={"kind": "finding", "finding": "reject-cluster-1"},
        headers={"Referer": f"http://testserver{url}#finding-reject-cluster-1"},
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"].endswith("#finding-reject-cluster-1")
    # Rows get a pin column; pinning one marks it.
    rows = client.get(f"{url}/rows?finding=reject-cluster-1")
    assert 'hx-vals=\'{"kind": "row", "row_no": ' in rows.text
    row_no = int(rows.text.split('"row_no": ')[1].split("}")[0])
    r = client.post(
        f"{url}/pin", data={"kind": "row", "row_no": row_no}, headers={"HX-Request": "true"}
    )
    assert r.status_code == 200 and "Pinned to" in r.text
    rows = client.get(f"{url}/rows?finding=reject-cluster-1")
    assert 'title="Pinned to Investigation: vpc_flow_logs_custom_v5.log">Pinned' in rows.text
    assert client.post(f"{url}/pin", data={"kind": "row", "row_no": 10**9}).status_code == 404
    assert client.post(f"{url}/pin", data={"kind": "finding", "finding": "zzz"}).status_code == 404
    assert client.post(f"{url}/pin", data={"kind": "what"}).status_code == 400

    # The investigation page: pinned finding card with its query, the row, notes.
    inv_url = f"/investigations/{inv.id}"
    page = client.get(inv_url)
    assert page.status_code == 200
    assert "Return traffic blocked" in page.text and "TCP port 5432 to 10.0.3.20" in page.text
    assert "CloudWatch Logs Insights query" in page.text
    assert "1 pinned rows" in page.text and f'<a href="{url}">open</a>' in page.text
    assert "Show the 1,280 rows behind this finding" in page.text  # the file is still loaded
    pin = inv.pins[0]
    r = client.post(f"{inv_url}/pins/{pin.id}/note", data={"note": "NACL change at 08:55"})
    assert r.status_code == 200 and "NACL change at 08:55" in r.text
    r = client.post(f"{inv_url}/notes", data={"notes": "Opened after the deploy."})
    assert "Opened after the deploy." in r.text
    r = client.post(f"{inv_url}/rename", data={"name": "Blocked replies"})
    assert 'value="Blocked replies"' in r.text
    assert client.post(f"{inv_url}/pins/nope/note", data={"note": "x"}).status_code == 404
    listing = client.get("/investigations").text
    assert "Blocked replies" in listing and "2 findings, 1 rows" in listing
    assert "receives pins" in listing

    # The export is one self-contained page with the notes and pins, and no forms.
    r = client.get(f"{inv_url}/report.html")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert "Blocked replies.investigation.html" in r.headers["content-disposition"]
    assert "<style>" in r.text and "/static/" not in r.text and "<form" not in r.text
    assert "Opened after the deploy." in r.text and "NACL change at 08:55" in r.text
    assert "Return traffic blocked" in r.text and "1 pinned rows" in r.text
    assert "1,280 rows behind this finding" in r.text and "Show the" not in r.text

    # Closing the file keeps the snapshot; unpinning and deleting work.
    client.post(f"{url}/close")
    page = client.get(inv_url)
    assert "no longer loaded" in page.text and "Return traffic blocked" in page.text
    r = client.post(f"{inv_url}/pins/{pin.id}/remove")
    assert r.status_code == 200 and "Return traffic blocked" not in r.text
    assert client.post(f"{inv_url}/pins/{pin.id}/remove").status_code == 404
    # A second investigation can be made the target for new pins.
    r = client.post("/investigations", data={"name": "Second", "next": "/"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    second = app.state.registry.active()
    assert second is not None and second.name == "Second"
    r = client.post(
        "/investigations/active", data={"inv": inv.id, "next": inv_url}, follow_redirects=False
    )
    assert r.headers["location"] == inv_url and app.state.registry.active_id == inv.id
    assert client.post("/investigations/active", data={"inv": "nope"}).status_code == 404
    r = client.post(f"{inv_url}/delete", follow_redirects=False)
    assert r.status_code == 303 and client.get(inv_url).status_code == 404
    assert [i.name for i in app.state.registry.investigations.list()] == ["Second"]
    # The store survives a restart.
    again = TestClient(create_app(data_dir=tmp_path / "data", samples_dir=samples))
    assert "Second" in again.get("/investigations").text
