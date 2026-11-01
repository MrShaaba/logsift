from __future__ import annotations

import io
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
