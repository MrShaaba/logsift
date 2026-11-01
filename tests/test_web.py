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
