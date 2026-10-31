from __future__ import annotations

from pathlib import Path

import pytest

from logsift.cli import main


def test_inspect_prints_summary_and_findings(samples: Path, capsys: pytest.CaptureFixture) -> None:
    assert main(["inspect", str(samples / "vpc_flow_logs_v2.log.gz"), "-v"]) == 0
    out = capsys.readouterr().out
    assert "VPC Flow Logs, default version 2 format" in out
    assert "[HIGH  ] Return traffic blocked" in out
    assert "Likely cause:" in out


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
