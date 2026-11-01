from __future__ import annotations

from pathlib import Path

from logsift.dataset import Dataset
from logsift.loader import LoadProgress
from logsift.store import Store
from tests.conftest import write

CHUNK = 64 * 1024  # small chunks so the samples span several of them


def test_sample_then_full_pass_matches_a_direct_load(samples: Path, flow_ds: Dataset) -> None:
    path = samples / "vpc_flow_logs_custom_v5.log"
    seen: list[LoadProgress] = []
    ds = Dataset.open(path, limit=2000, chunk_bytes=CHUNK, progress=seen.append)
    assert ds.is_sample and ds.rows == 2000 and ds.table == "flow"
    assert 0 < ds.fraction_loaded < 1
    assert ds.status.phase == "ready" and not ds.loading
    assert seen and seen[-1].rows == 2000
    sample_findings = [f.title for f in ds.findings]
    assert sample_findings  # the rules already run over the sample
    assert ds.profile.rows == 2000

    phases: list[str] = []
    rows: list[int] = []

    def watch(p: LoadProgress) -> None:
        phases.append(p.phase)
        rows.append(p.rows)

    ds.run_full_pass(progress=watch)
    assert not ds.is_sample and ds.rows == flow_ds.rows == 8657
    assert ds.fraction_loaded == 1.0 and ds.status.phase == "ready"
    assert rows == sorted(rows) and rows[-1] == 8657
    assert phases[0] == "reading" and "building" in phases and phases[-1] == "ready"
    assert ds.profile.rows == 8657
    assert [f.title for f in ds.findings] == [f.title for f in flow_ds.findings]
    assert ds.timeline == flow_ds.timeline
    assert ds.load.warnings == flow_ds.load.warnings
    # Nothing left to do.
    assert not ds.start_full_pass()
    ds.close()


def test_background_full_pass_can_be_waited_for(samples: Path) -> None:
    ds = Dataset.open(samples / "s3_access_logs.log", limit=1000, chunk_bytes=CHUNK)
    assert ds.is_sample and ds.rows == 1000
    assert ds.start_full_pass()
    assert not ds.start_full_pass()  # already running
    ds.wait(60)
    assert ds.status.phase == "ready" and ds.rows == 4830 and not ds.is_sample
    assert any("625 requests failed" in f.title for f in ds.findings)
    ds.close()


def test_small_file_under_the_limit_is_complete(tmp_path: Path) -> None:
    path = write(tmp_path, "small.csv", "a,b\n1,2\n3,4\n")
    ds = Dataset.open(path, limit=1000)
    assert not ds.is_sample and ds.rows == 2 and ds.fraction_loaded == 1.0
    assert not ds.start_full_pass()


def test_store_round_trip_and_resume_after_restart(samples: Path, tmp_path: Path) -> None:
    store = Store(tmp_path / "db")
    path = samples / "cloudtrail_events.csv"
    ds = Dataset.open(path, name="trail.csv", store=store, limit=500, chunk_bytes=CHUNK)
    ds_id = ds.id
    assert store.db_path(ds_id).is_file() and store.meta_path(ds_id).is_file()
    assert ds.is_sample and ds.rows == 500 and ds.table == "trail"
    titles = [f.title for f in ds.findings]
    ds.close()

    (again,) = Dataset.restore_all(store)
    assert again.id == ds_id and again.name == "trail.csv" and again.path == path
    assert again.rows == 500 and again.is_sample and again.table == "trail"
    assert again.format.label == ds.format.label and again.sniff.columns == ds.sniff.columns
    assert again.load.columns == ds.load.columns and again.canonical_columns == ds.canonical_columns
    assert [f.title for f in again.findings] == titles  # no reload needed
    assert again.status.phase == "ready"

    again.run_full_pass()
    assert again.rows == 2267 and not again.is_sample
    again.close()

    (third,) = Dataset.restore_all(store)
    assert third.rows == 2267 and not third.is_sample
    assert any(f.title.startswith("407 calls were refused") for f in third.findings)
    third.close()

    store.remove(ds_id)
    assert not store.db_path(ds_id).exists() and not store.meta_path(ds_id).exists()
    assert Dataset.restore_all(store) == []


def test_restore_drops_broken_entries(tmp_path: Path) -> None:
    store = Store(tmp_path / "db")
    ds = Dataset.open(write(tmp_path, "ok.csv", "a,b\n1,2\n"), store=store)
    ds.close()
    # A sidecar without its database, a database with a bad sidecar, and junk.
    store.meta_path("orphan").write_text('{"id": "orphan", "version": 1}')
    store.db_path("broken").write_bytes(b"not a database")
    store.meta_path("broken").write_text('{"id": "broken", "version": 1}')
    (store.root / "junk.json").write_text("[]")
    restored = Dataset.restore_all(store)
    assert [d.id for d in restored] == [ds.id]
    assert not store.meta_path("orphan").exists()
    assert not store.meta_path("broken").exists() and not store.db_path("broken").exists()
    for d in restored:
        d.close()


def test_full_pass_restarts_when_the_table_does_not_match(samples: Path) -> None:
    ds = Dataset.open(samples / "daily_sales.csv", limit=50, chunk_bytes=CHUNK)
    assert ds.is_sample and ds.rows == 50
    ds.con.execute("DELETE FROM raw WHERE rowid >= 40")  # as if a pass died halfway
    ds.run_full_pass()
    assert ds.status.phase == "ready" and not ds.is_sample
    assert ds.rows == ds.con.execute("SELECT count(*) FROM raw").fetchone()[0]
    assert ds.rows == Dataset.open(samples / "daily_sales.csv").rows
