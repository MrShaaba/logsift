from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from logsift.cli import ProgressPrinter, main
from logsift.loader import LoadProgress


def test_inspect_prints_summary_and_findings(samples: Path, capsys: pytest.CaptureFixture) -> None:
    assert main(["inspect", str(samples / "vpc_flow_logs_v2.log.gz"), "-v"]) == 0
    out = capsys.readouterr().out
    assert "VPC Flow Logs, default version 2 format" in out
    assert "[HIGH  ] Return traffic blocked" in out
    assert "Likely cause:" in out


def test_inspect_can_print_the_queries(samples: Path, capsys: pytest.CaptureFixture) -> None:
    assert main(["inspect", str(samples / "s3_access_logs.log"), "--queries"]) == 0
    out = capsys.readouterr().out
    assert "[HIGH  ] 15 anonymous requests succeeded" in out
    assert "           # S3 server access logs are delivered to a bucket" in out
    assert '           | filter requester = "-" and http_status < 400' in out
    assert main(["inspect", str(samples / "s3_access_logs.log")]) == 0
    assert "| filter" not in capsys.readouterr().out


def test_inspect_load_balancer_log(samples: Path, capsys: pytest.CaptureFixture) -> None:
    assert main(["inspect", str(samples / "nlb_access_logs.log")]) == 0
    out = capsys.readouterr().out
    assert "Network Load Balancer access log" in out
    assert "[HIGH  ] 190 TLS handshakes failed (6.3% of connections)" in out
    assert "[MEDIUM] 198.51.100.23 opened 601 connections" in out


def test_report_is_self_contained(
    samples: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "flow.html"
    assert main(["report", str(samples / "vpc_flow_logs_custom_v5.log"), "-o", str(out)]) == 0
    html = out.read_text()
    assert "Return traffic blocked" in html
    assert "<style>" in html and "/static/" not in html
    assert "First 25 of 1,280 rows" in html
    assert "CloudWatch Logs Insights query" in html and "button.copy" in html
    assert "What this file looks like" in html
    assert str(out) in capsys.readouterr().out


def test_report_default_name(samples: Path, tmp_path: Path) -> None:
    src = tmp_path / "sales.csv"
    src.write_bytes((samples / "daily_sales.csv").read_bytes())
    assert main(["report", str(src)]) == 0
    assert (tmp_path / "sales.report.html").exists()


def test_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    assert main(["report", str(tmp_path / "nope.csv")]) == 2
    assert "not a file" in capsys.readouterr().err


def test_inspect_cloudtrail_export(samples: Path, capsys: pytest.CaptureFixture) -> None:
    assert main(["inspect", str(samples / "cloudtrail_events.csv"), "-v"]) == 0
    out = capsys.readouterr().out
    assert "CloudTrail event export" in out
    assert "[HIGH  ] The root account made 11 calls, 4 of them changes" in out
    assert "[MEDIUM] shop-web-role was refused 181 calls in 30 minutes" in out
    assert "Likely cause: Resources appearing in a region nobody works in" in out


def test_inspect_s3_access_log(samples: Path, capsys: pytest.CaptureFixture) -> None:
    assert main(["inspect", str(samples / "s3_access_logs.log"), "-v"]) == 0
    out = capsys.readouterr().out
    assert "S3 server access log" in out
    assert "[HIGH  ] 15 anonymous requests succeeded, reading 13 objects (4.1 GB)" in out
    assert "[MEDIUM] shop-reports-role was refused 72 requests under exports/finance/" in out
    assert "Likely cause: Add s3:GetObject on exports/finance/*" in out


def test_inspect_and_report_can_sample(
    samples: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    assert main(["inspect", str(samples / "vpc_flow_logs_custom_v5.log"), "--sample", "300"]) == 0
    out = capsys.readouterr().out
    assert "300 rows, " in out
    assert "Sampled the first 300 rows, about" in out
    assert "the summary and findings cover only these rows" in out
    out_file = tmp_path / "sample.html"
    args = ["report", str(samples / "s3_access_logs.log"), "-o", str(out_file), "--sample", "500"]
    assert main(args) == 0
    html = out_file.read_text()
    assert "This report covers the first 500 rows" in html


class FakeTty(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_progress_printer_on_a_terminal_and_a_pipe() -> None:
    tty = FakeTty()
    printer = ProgressPrinter(tty)
    printer(LoadProgress(rows=1000, bytes_read=512, total_bytes=1024))
    printer(LoadProgress(rows=2000, bytes_read=1024, total_bytes=1024))
    assert tty.getvalue().count("\r") == 2
    assert "1,000 rows, 512 B of 1.0 KB (50%)" in tty.getvalue()
    assert "2,000 rows, 1.0 KB of 1.0 KB (100%)" in tty.getvalue()
    printer.done()
    assert tty.getvalue().endswith("\r\x1b[2K")

    pipe = io.StringIO()
    quiet = ProgressPrinter(pipe, every=60)
    quiet(LoadProgress(rows=10, bytes_read=1, total_bytes=2))
    assert pipe.getvalue() == ""  # a quick load says nothing on a pipe
    quiet.last -= 120
    quiet(LoadProgress(rows=20, bytes_read=2, total_bytes=2, phase="building"))
    assert pipe.getvalue() == "building the table, 20 rows loaded\n"
    quiet.done()
    assert pipe.getvalue() == "building the table, 20 rows loaded\n"


def test_investigations_list_and_export(
    samples: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    from logsift.dataset import Dataset
    from logsift.investigations import InvestigationStore, Pin

    data = tmp_path / "data"
    assert main(["investigations", "--data-dir", str(data)]) == 0
    assert "no investigations yet" in capsys.readouterr().out
    store = InvestigationStore(data / "investigations")
    inv = store.create("Slow reports")
    ds = Dataset.open(samples / "alb_access_logs.log")
    try:
        f = ds.finding("slow-requests")
        assert f is not None
        inv.add(Pin.of_finding(ds, f))
        row = Pin.of_row(ds, 2)
        assert row is not None
        inv.add(row)
    finally:
        ds.close()
    inv.notes = "The export endpoint again.\nSecond line."
    store.save(inv)

    assert main(["investigations", "--data-dir", str(data), "-v"]) == 0
    out = capsys.readouterr().out
    assert f"{inv.id}  Slow reports  (1 findings, 1 rows" in out
    assert "    The export endpoint again." in out
    assert "    - 60 slow requests took 2 s or more, 8 timed out [alb_access_logs.log]" in out
    assert "    - Row 2 [alb_access_logs.log]" in out

    out_path = tmp_path / "slow.html"
    assert (
        main(
            [
                "report",
                "--investigation",
                "slow reports",
                "--data-dir",
                str(data),
                "-o",
                str(out_path),
            ]
        )
        == 0
    )
    html = out_path.read_text()
    assert "60 slow requests took 2 s or more" in html and "<style>" in html
    assert "The export endpoint again." in html and "1 pinned rows" in html
    assert "<form" not in html
    assert str(out_path) in capsys.readouterr().out
    # Default name comes from the investigation; by id works too.
    monkey_cwd = tmp_path / "cwd"
    monkey_cwd.mkdir()
    import os

    old = os.getcwd()
    os.chdir(monkey_cwd)
    try:
        assert main(["report", "--investigation", inv.id, "--data-dir", str(data)]) == 0
    finally:
        os.chdir(old)
    assert (monkey_cwd / "Slow_reports.investigation.html").exists()
    assert main(["report", "--investigation", "nope", "--data-dir", str(data)]) == 2
    assert "no investigation called" in capsys.readouterr().err
    assert main(["report", "--investigation", inv.id, str(samples / "daily_sales.csv")]) == 2
    assert main(["report"]) == 2


def test_diff_prints_the_verdict_and_writes_the_report(
    samples: Path, tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    before = str(samples / "cutover_before_flow_logs.log")
    after = str(samples / "cutover_after_flow_logs.log")
    assert main(["diff", before, after, "-v"]) == 0
    out = capsys.readouterr().out
    assert "cutover_before_flow_logs.log -> cutover_after_flow_logs.log: VPC Flow Logs" in out
    assert "60 minutes compared from each file's first record" in out
    assert "VERDICT: REGRESSION  (3 regressions, 2 to review, 1 clean)" in out
    assert "[REGRESSION] New rejected traffic: 180 flows to 1 destination" in out
    assert "[REVIEW    ] Traffic that disappeared" in out
    assert "10.0.3.20:5432 TCP was accepted 360 times before" in out
    # A pipeline gate.
    assert main(["diff", before, after, "--fail-on", "regression"]) == 1
    assert main(["diff", before, before, "--fail-on", "review"]) == 0
    capsys.readouterr()
    # HTML and JSON.
    html_path = tmp_path / "cutover.html"
    assert main(["diff", before, after, "-o", str(html_path), "--json"]) == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["verdict"] == "regression" and data["window_minutes"] == 60
    assert [c["id"] for c in data["changes"]][:2] == ["bad-share", "new-rejects"]
    assert f"wrote {html_path}" in captured.err
    html = html_path.read_text()
    assert "<style>" in html and "/static/" not in html and "<form" not in html
    assert "Cutover report" in html and 'class="banner regression"' in html
    assert "Lost return path: replies to 86 requests" in html
    assert "Evidence: first 25 of 180 rows from the after file" in html
    assert "Evidence: first 25 of 440 rows from the before file" in html
    assert "per minute since each file's start" in html
    # Mismatched formats and missing files.
    assert main(["diff", before, str(samples / "daily_sales.csv")]) == 2
    assert "cannot compare" in capsys.readouterr().err
    assert main(["diff", before, str(tmp_path / "nope.log")]) == 2
