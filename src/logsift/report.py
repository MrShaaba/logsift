"""Render a self-contained HTML report for one file."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from logsift import __version__
from logsift.dataset import Dataset
from logsift.explore import RowQuery, fetch_page
from logsift.investigations import Investigation
from logsift.web.render import make_env, static_text

ROWS_PER_FINDING = 25
SAMPLE_ROWS = 50


@dataclass
class SampleRows:
    columns: list[str]
    rows: list[tuple[Any, ...]]


def render_report(ds: Dataset) -> str:
    env = make_env()
    findings = ds.findings
    for f in findings:
        if f.row_count:
            page = fetch_page(
                ds.cursor(), ds.table, RowQuery(where=f.row_filter), 1, ROWS_PER_FINDING
            )
            f.sample_rows = SampleRows(page.columns, page.rows)  # type: ignore[attr-defined]
    sample = fetch_page(ds.cursor(), ds.table, RowQuery(), 1, SAMPLE_ROWS)
    return env.get_template("report.html").render(
        standalone=True,
        css=static_text("app.css"),
        ds=ds,
        profile=ds.profile,
        findings=findings,
        timeline=ds.timeline,
        sample=SampleRows(sample.columns, sample.rows),
        generated=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        version=__version__,
    )


def write_report(
    path: Path, out: Path | None = None, *, limit: int | None = None, progress: Any = None
) -> Path:
    ds = Dataset.open(path, limit=limit, progress=progress)
    try:
        html = render_report(ds)
    finally:
        ds.close()
    out = out or path.with_suffix("").with_name(path.stem + ".report.html")
    out.write_text(html, encoding="utf-8")
    return out


def render_investigation(inv: Investigation) -> str:
    """A self-contained HTML page for an investigation: its notes, pinned findings and rows."""
    env = make_env()
    return env.get_template("investigation.html").render(
        standalone=True,
        css=static_text("app.css"),
        inv=inv,
        groups=inv.by_dataset(),
        loaded=set(),
        generated=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        version=__version__,
    )


def write_investigation_report(inv: Investigation, out: Path) -> Path:
    out.write_text(render_investigation(inv), encoding="utf-8")
    return out
