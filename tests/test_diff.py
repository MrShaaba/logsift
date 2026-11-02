from __future__ import annotations

from datetime import datetime

import pytest

from logsift.cutover import Verdict, describe_change, worst
from logsift.dataset import Dataset
from logsift.diff import DiffError, align, compare
from tests.conftest import SAMPLES


@pytest.fixture(scope="module")
def pair() -> tuple[Dataset, Dataset]:
    before = Dataset.open(SAMPLES / "cutover_before_flow_logs.log")
    after = Dataset.open(SAMPLES / "cutover_after_flow_logs.log")
    yield before, after
    before.close()
    after.close()


def count(ds: Dataset, where: str) -> int:
    return int(ds.cursor().execute(f"SELECT count(*) FROM {ds.table} WHERE {where}").fetchone()[0])


def test_describe_change_and_worst() -> None:
    assert describe_change(0, 0) == "unchanged" and describe_change(0, 5) == "new"
    assert describe_change(5, 0) == "gone" and describe_change(100, 320) == "up 3.2x"
    assert describe_change(100, 130) == "up 30%" and describe_change(100, 60) == "down 40%"
    assert worst([]) == Verdict.CLEAN
    assert worst([Verdict.CLEAN, Verdict.REVIEW]) == Verdict.REVIEW
    assert worst([Verdict.REVIEW, Verdict.REGRESSION, Verdict.CLEAN]) == Verdict.REGRESSION


def test_cutover_pair_finds_the_planted_regressions(pair: tuple[Dataset, Dataset]) -> None:
    before, after = pair
    report = compare(before, after)
    assert report.verdict == Verdict.REGRESSION
    assert [c.id for c in report.changes] == [
        "bad-share",
        "new-rejects",
        "return-paths",
        "new-talkers",
        "disappeared",
        "volume",
    ]
    assert [c.verdict for c in report.regressions] == [Verdict.REGRESSION] * 3
    assert len(report.reviews) == 2 and len(report.clean) == 1
    al = report.alignment
    assert al.minutes == 60 and al.trimmed == "" and al.column == "start_ts"
    assert al.before_start == datetime(2026, 3, 9, 8, 0) and al.after_start == datetime(
        2026, 3, 11, 8, 0
    )
    assert report.totals == {"before_rows": 4960, "after_rows": 4420}

    rejects = report.change("new-rejects")
    assert rejects is not None
    assert rejects.title == (
        "New rejected traffic: 180 flows to 1 destination that were not rejected before"
    )
    assert "10.0.3.20:5432 TCP was accepted 360 times before and rejected 180 times after" in (
        rejects.summary
    )
    assert "security group or network ACL that no longer allows it" in rejects.explanation
    assert rejects.tables[0].rows == [("10.0.3.20", 5432, "TCP", 180, 3, 0, 360)]
    assert rejects.before == 0 and rejects.after == 180 and rejects.change_text == "new"

    paths = report.change("return-paths")
    assert paths is not None
    assert paths.title.startswith("Lost return path: replies to 86 requests are now rejected")
    assert "10.0.2.11:8080" in paths.title
    assert "these pairs completed 240 exchanges normally" in paths.summary
    assert [r[:3] for r in paths.tables[0].rows] == [
        ("10.0.1.10", "10.0.2.11", 8080),
        ("10.0.1.11", "10.0.2.11", 8080),
        ("10.0.1.12", "10.0.2.11", 8080),
    ]

    gone = report.change("disappeared")
    assert gone is not None and gone.verdict == Verdict.REVIEW and gone.evidence == "before"
    assert gone.title == (
        "Traffic that disappeared: 1 destination carried 440 flows before and none after"
    )
    assert "10.0.2.30:6379 TCP received 440 accepted flows" in gone.summary
    assert gone.after_filter == "" and gone.before == 440 and gone.after == 0

    talkers = report.change("new-talkers")
    assert talkers is not None and talkers.verdict == Verdict.REVIEW
    assert talkers.title == "New talkers: 2 sources not seen before sent 756 flows (6.7 MB)"
    assert [r[0] for r in talkers.tables[0].rows] == ["10.0.2.12", "10.0.2.40"]
    assert "10.0.2.12 is the biggest, with 316 accepted flows" in talkers.summary

    share = report.change("bad-share")
    assert share is not None and share.verdict == Verdict.REGRESSION
    assert share.title == "Rejected flows: 7.8% after, 1.6% before (up 4.3x)"
    volume = report.change("volume")
    assert volume is not None and volume.verdict == Verdict.CLEAN
    assert volume.title == "Volume: 73.7 flows a minute after, 82.7 before (down 11%)"

    # Every filter selects exactly the rows it claims, in the file it points at.
    for c in report.changes:
        if c.after_filter:
            assert count(after, c.after_filter) == (
                c.rows if c.evidence == "after" else count(after, c.after_filter)
            ), c.id
        if c.evidence == "before":
            assert count(before, c.before_filter) == c.rows, c.id
        ev = report.evidence(c)
        assert ev.total == c.rows and len(ev.rows) == min(25, c.rows), c.id
        assert ev.columns[0] == "row_no"
    assert report.evidence(gone, side="after").total == 0
    assert report.evidence(paths, side="before").total == count(before, paths.before_filter)

    data = report.to_dict()
    assert data["verdict"] == "regression" and data["window_minutes"] == 60
    assert data["before"]["name"] == "cutover_before_flow_logs.log"
    assert data["compared"]["after"]["start"] == "2026-03-11 08:00:00"
    assert [c["id"] for c in data["changes"]][:2] == ["bad-share", "new-rejects"]
    assert data["changes"][1]["tables"][0]["rows"][0]["destination"] == "10.0.3.20"

    tl = report.timeline
    assert tl is not None and tl["bucket"] == "minute" and len(tl["labels"]) == 60
    assert tl["labels"][:2] == ["+0m", "+1m"] and tl["good"] == "accepted"
    assert sum(tl["after"]["rejected"]) == 346 and sum(tl["before"]["rejected"]) == 80
    assert sum(tl["after"]["accepted"]) + 346 == 4420


def test_same_file_twice_is_clean(pair: tuple[Dataset, Dataset]) -> None:
    before, _ = pair
    report = compare(before, before)
    assert report.verdict == Verdict.CLEAN
    assert all(c.verdict == Verdict.CLEAN for c in report.changes)
    titles = [c.title for c in report.changes]
    assert "No destination started rejecting traffic" in titles
    assert "No return path was lost" in titles and "No new talkers" in titles


def test_longer_file_is_trimmed_to_the_shorter(
    pair: tuple[Dataset, Dataset], flow_ds: Dataset
) -> None:
    _, after = pair
    al = align(flow_ds, after, "start_ts")
    assert al.minutes == 60 and al.trimmed == "before"
    assert al.before_full == (datetime(2026, 3, 10, 8, 0), datetime(2026, 3, 10, 9, 59))
    assert al.before_end == datetime(2026, 3, 10, 9, 0)
    report = compare(flow_ds, after)
    assert report.totals["before_rows"] == count(flow_ds, al.where("before"))
    assert report.totals["before_rows"] < flow_ds.rows
    assert "cut to the shorter" in report.change("volume").explanation  # type: ignore[union-attr]


def test_files_must_share_a_format(
    flow_ds: Dataset, alb_ds: Dataset, sales_ds: Dataset, pair: tuple[Dataset, Dataset]
) -> None:
    with pytest.raises(DiffError, match="not the same recognised format"):
        compare(flow_ds, alb_ds)
    with pytest.raises(DiffError, match="not the same recognised format"):
        compare(sales_ds, sales_ds)
    # The v2 and custom shapes are both flow logs, so they compare.
    before, _ = pair
    v2 = Dataset.open(SAMPLES / "vpc_flow_logs_v2.log")
    try:
        assert compare(v2, before).alignment.minutes == 60
    finally:
        v2.close()
