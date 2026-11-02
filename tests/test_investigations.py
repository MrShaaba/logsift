from __future__ import annotations

import json
from pathlib import Path

from logsift.dataset import Dataset
from logsift.investigations import INVESTIGATION_VERSION, Investigation, InvestigationStore, Pin


def test_store_round_trip_list_find_and_delete(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path / "inv")
    assert store.list() == []
    a = store.create("  Blocked database traffic ")
    b = store.create("")
    assert a.name == "Blocked database traffic" and b.name == "Untitled investigation"
    assert (tmp_path / "inv" / f"{a.id}.json").is_file()
    assert [i.id for i in store.list()] == [b.id, a.id]  # most recently changed first
    a.notes = "Started after the 09:00 deploy."
    a.touch()
    store.save(a)
    assert [i.id for i in store.list()] == [a.id, b.id]
    again = store.get(a.id)
    assert again is not None and again.notes == a.notes and again.name == a.name
    assert store.find("blocked DATABASE traffic") is not None
    assert store.find(a.id) is not None and store.find("nope") is None
    store.delete(a.id)
    assert store.get(a.id) is None and [i.id for i in store.list()] == [b.id]


def test_unreadable_files_are_skipped(tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path)
    (tmp_path / "junk.json").write_text("{not json")
    (tmp_path / "old.json").write_text(json.dumps({"version": 99, "id": "old", "name": "x"}))
    (tmp_path / "renamed.json").write_text(
        json.dumps({"version": INVESTIGATION_VERSION, "id": "other", "name": "x"})
    )
    assert store.list() == [] and store.get("junk") is None and store.get("old") is None
    assert store.get("../etc/passwd") is None


def test_pin_findings_and_rows(flow_ds: Dataset, s3_ds: Dataset, tmp_path: Path) -> None:
    store = InvestigationStore(tmp_path)
    inv = store.create("Return traffic")
    f = flow_ds.finding("asymmetric")
    assert f is not None
    pin = inv.add(Pin.of_finding(flow_ds, f))
    assert pin.kind == "finding" and pin.title == f.title and pin.dataset_name == flow_ds.name
    assert pin.finding is not None
    assert pin.finding["query"] == f.query and pin.finding["row_filter"] == f.row_filter
    assert all(len(t["rows"]) <= 10 for t in pin.finding["tables"])
    assert pin.finding["tables"][0]["total"] == len(f.tables[0].rows)
    # Pinning the same finding twice keeps one pin.
    assert inv.add(Pin.of_finding(flow_ds, f)) is pin and len(inv.pins) == 1
    assert inv.has(flow_ds.id, finding_id="asymmetric") and inv.pinned_findings(flow_ds.id) == {
        "asymmetric"
    }

    row = Pin.of_row(flow_ds, 7)
    assert row is not None and row.row_no == 7 and row.title == "Row 7"
    assert row.columns[:4] == ["version", "account_id", "interface_id", "srcaddr"]
    assert "row_no" not in row.columns and len(row.values) == len(row.columns)
    assert isinstance(row.values[row.columns.index("start_ts")], str)  # JSON-friendly
    inv.add(row)
    assert inv.add(Pin.of_row(flow_ds, 7)) is row and inv.pinned_rows(flow_ds.id) == {7}
    assert Pin.of_row(flow_ds, 10**9) is None
    other = s3_ds.finding("anonymous-reads")
    assert other is not None
    inv.add(Pin.of_finding(s3_ds, other))
    inv.add(Pin.of_row(s3_ds, 1))
    assert len(inv.findings) == 2 and len(inv.rows) == 2
    groups = inv.by_dataset()
    assert [g["dataset_name"] for g in groups] == [flow_ds.name, s3_ds.name]
    assert len(groups[0]["findings"]) == 1 and len(groups[1]["rows"]) == 1

    pin.note = "Matches the NACL change at 08:55."
    store.save(inv)
    loaded = store.get(inv.id)
    assert loaded is not None and len(loaded.pins) == 4
    back = loaded.pin(pin.id)
    assert back is not None and back.note == pin.note
    rebuilt = back.as_finding()
    assert rebuilt.title == f.title and rebuilt.severity == f.severity
    assert rebuilt.query == f.query and rebuilt.row_count == f.row_count
    assert rebuilt.tables[0].title == f.tables[0].title
    assert rebuilt.tables[0].rows[0] == tuple(
        v.isoformat(sep=" ") if hasattr(v, "isoformat") else v for v in f.tables[0].rows[0]
    )
    assert loaded.remove(pin.id) and not loaded.remove(pin.id)
    assert not loaded.has(flow_ds.id, finding_id="asymmetric")
    assert loaded.updated >= inv.updated


def test_investigation_dict_round_trip() -> None:
    inv = Investigation("abc", "Name", notes="n")
    inv.pins.append(Pin("p1", "row", "d", "file.log", row_no=3, columns=["a"], values=[1]))
    data = json.loads(json.dumps(inv.to_dict()))
    again = Investigation.from_dict(data)
    assert again.id == "abc" and again.pins[0].values == [1] and again.pins[0].row_no == 3
