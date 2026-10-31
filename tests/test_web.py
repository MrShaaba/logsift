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
