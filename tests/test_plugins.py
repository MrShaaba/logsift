from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from logsift import formats
from logsift.dataset import Dataset
from logsift.formats import PLUGINS, FormatInfo, FormatPlugin, detect_format, plugin_for
from logsift.formats.base import Format
from logsift.insights.base import Finding, Severity
from logsift.loader import Sniff, sniff
from tests.conftest import write


def test_registry_is_well_formed() -> None:
    names = [p.name for p in PLUGINS]
    assert names and len(set(names)) == len(names)
    assert names[-1] == "generic"
    for plugin in PLUGINS:
        assert isinstance(plugin, FormatPlugin)
        assert plugin_for(plugin.name) is plugin
    with pytest.raises(KeyError):
        plugin_for("nope")


def test_every_sample_is_claimed_by_its_plugin(samples: Path) -> None:
    expect = {
        "vpc_flow_logs_v2.log": ("vpc_flow", "flow"),
        "vpc_flow_logs_custom_v5.log": ("vpc_flow", "flow"),
        "cloudwatch_insights_export.csv": ("cloudwatch_insights", "flow"),
        "alb_access_logs.log": ("load_balancer", "lb"),
        "nlb_access_logs.log": ("load_balancer", "lb"),
        "cloudtrail_events.csv": ("cloudtrail", "trail"),
        "daily_sales.csv": ("generic", ""),
    }
    for name, (plugin, table) in expect.items():
        info = detect_format(sniff(samples / name))
        assert (info.plugin, info.table) == (plugin, table), name
        assert info.has_rules == bool(table)
        assert plugin_for(info.plugin).table == table


class ToyPlugin(FormatPlugin):
    """Recognises a file whose first header is 'toy' and counts its rows."""

    name = "toy"
    table = "toy"
    dash_means_missing = True

    def detect(self, sn: Sniff) -> FormatInfo | None:
        if sn.has_header and sn.columns[:1] == ["toy"]:
            return self.found(Format.GENERIC, "Toy format", "first column is toy")
        return None

    def build_table(self, con: Any, fmt: FormatInfo, source: str = "raw") -> list[str]:
        con.execute(f'CREATE TABLE toy AS SELECT row_number() OVER () AS row_no, * FROM "{source}"')
        return [r[0] for r in con.execute("DESCRIBE toy").fetchall()]

    def findings(self, ds: Dataset) -> list[Finding]:
        n = ds.cursor().execute("SELECT count(*) FROM toy WHERE toy IS NULL").fetchone()[0]
        return [
            Finding("toy-1", "toy", f"{n} toys missing", Severity.LOW, "", "", "", n, "toy IS NULL")
        ]

    def timeline(self, ds: Dataset) -> dict[str, Any] | None:
        return {
            "bucket": "minute",
            "labels": ["08:00"],
            "series": {"accepted": [1], "rejected": [0]},
        }


def test_a_new_plugin_only_needs_registering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(formats, "PLUGINS", [ToyPlugin(), *PLUGINS])
    path = write(tmp_path, "toy.csv", "toy,n\n-,1\nred,2\n-,3\n")
    ds = Dataset.open(path)
    try:
        assert ds.format.plugin == "toy" and ds.format.label == "Toy format"
        assert ds.format.dash_means_missing
        assert ds.table == "toy" and ds.has_rules
        assert [c for c, _ in ds.columns] == ["toy", "n"]
        assert [f.title for f in ds.findings] == ["2 toys missing"]
        assert ds.timeline is not None and ds.timeline["labels"] == ["08:00"]
        assert ds.finding("toy-1") is not None
    finally:
        ds.close()


def test_generic_file_has_no_table_and_no_findings(sales_ds: Dataset) -> None:
    assert sales_ds.format.plugin == "generic"
    assert sales_ds.table == "raw" and not sales_ds.has_rules
    assert sales_ds.findings == [] and sales_ds.timeline is None
    with pytest.raises(NotImplementedError):
        sales_ds.plugin.build_table(sales_ds.con, sales_ds.format)
