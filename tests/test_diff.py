from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path

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
    assert share.title == "Rejected flows: 7.8% after, 1.6% before (share up 4.9x)"
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


# ----------------------------------------------------------- the other formats
# Each sample's planted problems sit in its second hour, so the first hour against the
# second is a cutover that went wrong.


def split_sample(name: str, tmp_path: Path) -> tuple[Path, Path]:
    """The sample's rows before 09:00 and from 09:00 on, as two files of the same shape."""
    text = (SAMPLES / name).read_text()
    if name.endswith(".csv"):
        rows = list(csv.reader(io.StringIO(text)))
        head, body = rows[0], rows[1:]
        idx = next(i for i, c in enumerate(head) if c.lower().replace(" ", "") == "eventtime")
        parts = {
            "before": [r for r in body if r[idx][11:13] < "09"],
            "after": [r for r in body if r[idx][11:13] >= "09"],
        }
        for part, rs in parts.items():
            with (tmp_path / f"{part}_{name}").open("w", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(head)
                w.writerows(rs)
    else:
        lines = text.splitlines()
        stamp = {
            "alb_access_logs.log": lambda ln: ln.split(" ")[1][11:13],
            "nlb_access_logs.log": lambda ln: ln.split(" ")[2][11:13],
            "route53_resolver_query_logs.json": lambda ln: json.loads(ln)["query_timestamp"][11:13],
        }[name]
        for part, keep in (("before", lambda h: h < "09"), ("after", lambda h: h >= "09")):
            chosen = [ln for ln in lines if keep(stamp(ln))]
            (tmp_path / f"{part}_{name}").write_text("\n".join(chosen) + "\n")
    return tmp_path / f"before_{name}", tmp_path / f"after_{name}"


def diff_sample(name: str, tmp_path: Path):  # noqa: ANN201
    before_path, after_path = split_sample(name, tmp_path)
    before, after = Dataset.open(before_path), Dataset.open(after_path)
    try:
        report = compare(before, after)
        for c in report.changes:  # every filter selects what it claims
            where = c.after_filter if c.evidence == "after" else c.before_filter
            ds = after if c.evidence == "after" else before
            if where:
                assert count(ds, where) == c.rows, c.id
        return report
    finally:
        before.close()
        after.close()


def test_alb_cutover_checks(tmp_path: Path) -> None:
    report = diff_sample("alb_access_logs.log", tmp_path)
    assert report.verdict == Verdict.REGRESSION
    ids = {c.id: c for c in report.changes}
    assert [c.id for c in report.changes] == [
        "target-errors",
        "bad-share",
        "path-errors",
        "volume",
        "latency",
        "targets",
    ]
    t = ids["target-errors"]
    assert t.verdict == Verdict.REGRESSION and t.after == 393 and t.before == 3
    assert (
        t.title == "5xx per target: 10.0.2.11:8080 fails 67.3% of its requests after, 1.2% before"
    )
    assert "1 target fails more of its requests" in t.summary
    assert t.tables[0].rows[0][:3] == ("10.0.2.11:8080", 244, 3) and t.tables[0].rows[0][-1] == (
        "/api/products"
    )
    assert ids["path-errors"].verdict == Verdict.REGRESSION
    assert ids["path-errors"].tables[0].rows[0] == ("/api/products", 148, 0, 192, 81)
    assert ids["bad-share"].title == "5xx requests: 18.1% after, 0.4% before (share up 51.0x)"
    assert ids["latency"].verdict == Verdict.CLEAN and ids["latency"].unit == "seconds"
    assert ids["latency"].tables[0].rows[0] == ("/api/reports/export", 32, 60.0)
    assert ids["targets"].verdict == Verdict.CLEAN
    assert report.timeline is not None and report.timeline["good"] == "ok"


def test_nlb_cutover_checks(tmp_path: Path) -> None:
    report = diff_sample("nlb_access_logs.log", tmp_path)
    assert report.verdict == Verdict.REVIEW
    ids = {c.id: c for c in report.changes}
    h = ids["handshakes"]
    assert h.verdict == Verdict.REVIEW and h.unit == "connections"
    assert h.title == "Failed handshakes: 192.0.2.80:443 fails 7.9% after, 5.2% before"
    assert h.tables[0].rows == [("192.0.2.80:443", 1793, 94, 1222, 96)]
    assert ids["bad-share"].title == "Failed connections: 7.9% after, 5.2% before (share up 50%)"
    assert "not by enough to distrust" in ids["volume"].summary
    assert ids["targets"].title == "The same targets serve traffic before and after"
    assert "latency" not in ids and "target-errors" not in ids


def test_resolver_cutover_checks(tmp_path: Path) -> None:
    report = diff_sample("route53_resolver_query_logs.json", tmp_path)
    assert report.verdict == Verdict.REGRESSION
    ids = {c.id: c for c in report.changes}
    f = ids["new-failures"]
    assert f.verdict == Verdict.REGRESSION and f.after == 671 and f.before == 15
    assert f.title == (
        "New failures: 671 NXDOMAIN and other answers for 2 domains that resolved before"
    )
    assert "example.internal got 413 NXDOMAIN answers after (15 before) from 6 hosts" in (f.summary)
    assert f.tables[0].rows[1][:5] == ("in-addr.arpa", "NXDOMAIN", 0, 190, 1)
    assert ids["blocked"].verdict == Verdict.CLEAN
    assert ids["blocked"].title == "DNS Firewall blocked 170 queries after, 172 before"
    assert "The same names were blocked before" in ids["blocked"].summary
    assert "an improvement" in ids["bad-share"].summary
    assert (
        ids["names-gone"].verdict == Verdict.CLEAN and ids["new-talkers"].verdict == Verdict.CLEAN
    )


def test_cloudtrail_cutover_checks(tmp_path: Path) -> None:
    report = diff_sample("cloudtrail_events.csv", tmp_path)
    assert report.verdict == Verdict.REGRESSION
    ids = {c.id: c for c in report.changes}
    s = ids["service-errors"]
    assert s.verdict == Verdict.REGRESSION
    assert s.title == "Errors per service: ssm fails 33.5% of calls after, 5.3% before"
    assert s.tables[0].rows[0] == ("ssm", 380, 20, 540, 181, "AccessDeniedException")
    d = ids["new-denials"]
    assert d.verdict == Verdict.REVIEW and d.after == 181
    assert "shop-web-role is refused ssm:GetParameter 181 times after" in d.summary
    assert "an action it did not call before" in d.summary
    p = ids["principals"]
    assert (
        p.verdict == Verdict.REVIEW
        and p.title == "Principals changed: 2 principals new (backup-admin, root)"
    )
    assert [r[0] for r in p.tables[0].rows] == ["backup-admin", "root"]
    r = ids["regions"]
    assert r.title == "New regions: ap-southeast-1, us-east-2 with 22 calls after and none before"
    assert "most often RunInstances" in r.summary
    assert ids["bad-share"].verdict == Verdict.CLEAN and report.timeline["unit"] == "calls"  # type: ignore[index]
