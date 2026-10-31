from __future__ import annotations

import csv
from pathlib import Path

from logsift.dataset import Dataset
from logsift.explore import RowQuery, fetch_page
from logsift.insights.base import Finding, Severity
from tests.conftest import write


def by_rule(ds: Dataset, rule: str) -> list[Finding]:
    return [f for f in ds.findings if f.rule == rule]


def rows_for(ds: Dataset, f: Finding) -> int:
    return fetch_page(ds.cursor(), ds.table, RowQuery(where=f.row_filter), 1, 1).total


def test_access_denied_overview(trail_ds: Dataset) -> None:
    (f,) = by_rule(trail_ds, "access_denied")
    assert f.severity == Severity.HIGH
    assert f.title == "407 calls were refused by a policy (18.0% of calls)"
    assert "bob accounts for 222 of them, spread over 22 different actions" in f.summary
    assert "2 addresses" in f.summary
    assert "the burst finding has the details" in f.likely_cause
    assert f.row_count == 407 == rows_for(trail_ds, f)
    assert [t.title for t in f.tables] == [
        "By principal and action",
        "By principal",
        "By error code",
        "By source address",
    ]
    pairs = {(r[0], r[1]): r[2] for r in f.tables[0].rows}
    assert pairs[("shop-web-role", "ssm:GetParameter")] == 181
    codes = {r[0]: r[1] for r in f.tables[2].rows}
    assert codes == {
        "AccessDeniedException": 271,
        "AccessDenied": 105,
        "Client.UnauthorizedOperation": 31,
    }


def test_denied_bursts_tell_enumeration_from_a_retry_loop(trail_ds: Dataset) -> None:
    bursts = by_rule(trail_ds, "denied_burst")
    assert [f.id for f in bursts] == ["denied-burst-1", "denied-burst-2"]
    key, loop = bursts

    assert key.severity == Severity.HIGH
    assert key.title == "bob was refused 220 calls in 6 minutes across 22 different actions"
    assert "from 203.0.113.77" in key.summary
    assert "never appears in this principal's other 156 calls" in key.summary
    assert "came from 198.51.100.21" in key.summary
    assert "stolen or found credential" in key.likely_cause
    assert "AKIAI44QH8DHBEXAMPLE" in key.likely_cause
    assert key.row_count == 220 == rows_for(trail_ds, key)
    assert [t.title for t in key.tables] == ["By action", "By source address", "By minute"]
    assert len(key.tables[0].rows) == 22 and all(r[1] == 10 for r in key.tables[0].rows)
    assert key.tables[1].rows[0][0] == "203.0.113.77"

    assert loop.severity == Severity.MEDIUM
    assert loop.title == "shop-web-role was refused 181 calls in 30 minutes, all ssm:GetParameter"
    assert "Between 2026-03-10 09:30 and 2026-03-10 09:59" in loop.summary
    assert "0 refused" in loop.summary  # nothing refused outside the window
    assert "retry loop" in loop.likely_cause
    assert "parameter/shop/web/feature-flags" in loop.likely_cause
    assert loop.row_count == 181 == rows_for(trail_ds, loop)
    assert {r[0] for r in loop.tables[1].rows} == {"10.0.1.10", "10.0.1.11", "10.0.1.12"}


def test_console_sign_ins_without_mfa(trail_ds: Dataset) -> None:
    (f,) = by_rule(trail_ds, "console_logins")
    assert f.severity == Severity.HIGH
    assert f.title == "3 console sign-ins without MFA, 1 by the root account"
    assert f.summary == (
        "3 of 5 successful console sign-ins used a password alone, by carol, root. "
        "1 sign-in failed."
    )
    assert "aws:MultiFactorAuthPresent" in f.likely_cause
    assert "203.0.113.61 is an address you recognise" in f.likely_cause
    assert f.row_count == 3 == rows_for(trail_ds, f)
    assert [t.title for t in f.tables] == [
        "Sign-ins without MFA",
        "All sign-ins",
        "Failed sign-ins",
    ]
    assert [r[0] for r in f.tables[0].rows] == ["carol", "root", "carol"]
    assert f.tables[2].rows == [("carol", "198.51.100.22", 1)]


def test_root_activity(trail_ds: Dataset) -> None:
    (f,) = by_rule(trail_ds, "root_activity")
    assert f.severity == Severity.HIGH
    assert f.title == "The root account made 11 calls, 4 of them changes"
    assert "from 203.0.113.61" in f.summary
    assert "iam:AttachUserPolicy, iam:CreateAccessKey, iam:CreateUser" in f.summary
    assert "The root sign-in did not use MFA." in f.summary
    assert "arn:aws:iam::123456789012:user/backup-admin" in f.likely_cause
    assert "rotate the root password" in f.likely_cause
    assert f.row_count == 11 == rows_for(trail_ds, f)
    events = f.tables[1].rows
    assert len(events) == 11 and events[0][1] == "signin:ConsoleLogin" and events[0][5] == "no"


def test_unusual_regions(trail_ds: Dataset) -> None:
    (f,) = by_rule(trail_ds, "unusual_regions")
    assert f.severity == Severity.HIGH
    assert f.title == "22 calls in 2 regions this account rarely uses (ap-southeast-1, us-east-2)"
    assert f.summary.startswith(
        "eu-west-1 (90%), eu-central-1 (9%) hold the account's regional activity."
    )
    assert "by backup-admin; 12 of them created or changed something" in f.summary
    assert "ec2:RunInstances" in f.summary and "compromised credential" in f.likely_cause
    assert f.row_count == 22 == rows_for(trail_ds, f)
    rare = {r[0]: (r[1], r[2]) for r in f.tables[0].rows}
    assert rare == {"ap-southeast-1": (12, 7), "us-east-2": (10, 5)}
    assert f.tables[2].rows[0][:2] == ("backup-admin", "IAMUser")
    assert [r[0] for r in f.tables[3].rows] == ["eu-west-1", "eu-central-1"]


def test_top_principals(trail_ds: Dataset) -> None:
    (f,) = by_rule(trail_ds, "top_principals")
    assert f.severity == Severity.INFO
    assert f.title == "Top principal: shop-web-role made 922 calls (40.7%)"
    assert "10 principals called 20 services" in f.summary
    assert "407 of them errors" in f.summary
    assert [t.title for t in f.tables] == ["By principal", "By service", "By source address"]
    assert f.tables[1].rows[0][0] == "ssm"


def test_timeline(trail_ds: Dataset) -> None:
    tl = trail_ds.timeline
    assert tl is not None
    assert tl["bucket"] == "minute" and len(tl["labels"]) == 120
    assert (tl["title"], tl["good"], tl["bad"], tl["unit"]) == (
        "API calls against errors",
        "ok",
        "error",
        "events",
    )
    assert sum(tl["series"]["rejected"]) == 407
    assert sum(tl["series"]["accepted"]) == 2267 - 407
    assert max(tl["series"]["rejected"]) >= 30  # the enumeration minutes stand out


def test_every_row_filter_matches_its_count(trail_ds: Dataset) -> None:
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    ranks = [order[str(f.severity)] for f in trail_ds.findings]
    assert ranks == sorted(ranks)
    for f in trail_ds.findings:
        assert rows_for(trail_ds, f) == f.row_count, f.id
        assert trail_ds.finding(f.id) is f


def healthy_lines(samples: Path, keep: int) -> str:
    """Rows with no planted problem: no errors, no root, no carol, no new admin user."""
    lines = (samples / "cloudtrail_events.csv").read_text().splitlines()
    header = next(csv.reader([lines[0]]))
    out = [lines[0]]
    for line in lines[1:]:
        row = dict(zip(header, next(csv.reader([line])), strict=True))
        if (
            row["Error code"] == ""
            and row["User name"] not in ("root", "carol", "backup-admin")
            and row["Source IP address"] not in ("203.0.113.61", "203.0.113.77")
            and row["AWS region"] in ("eu-west-1", "eu-central-1", "us-east-1")
        ):
            out.append(line)
        if len(out) == keep + 1:
            break
    return "\n".join(out) + "\n"


def test_healthy_export_reports_quiet(samples: Path, tmp_path: Path) -> None:
    ds = Dataset.open(write(tmp_path, "quiet.csv", healthy_lines(samples, 400)))
    assert ds.is_trail_log and ds.rows == 400
    rules = {f.rule: f for f in ds.findings}
    assert rules["access_denied"].title == "No access denied errors"
    assert rules["console_logins"].title == "Every console sign-in used MFA"
    assert rules["root_activity"].title == "No root account activity"
    assert (
        rules["unusual_regions"].title == "All activity was in 2 regions: eu-west-1, eu-central-1"
    )
    assert "denied_burst" not in rules
    assert all(f.severity == Severity.INFO for f in ds.findings)
    assert ds.timeline is not None and sum(ds.timeline["series"]["rejected"]) == 0


def test_sign_ins_without_mfa_information(tmp_path: Path) -> None:
    header = (
        "Event time,User name,Event name,Event source,AWS region,Source IP address,Error code\n"
    )
    lines = "".join(
        f"2026-03-10T08:0{i}:00Z,alice,DescribeInstances,ec2.amazonaws.com,eu-west-1,198.51.100.20,\n"
        for i in range(8)
    )
    lines += (
        "2026-03-10T08:09:00Z,alice,ConsoleLogin,signin.amazonaws.com,us-east-1,198.51.100.20,\n"
    )
    ds = Dataset.open(write(tmp_path, "console.csv", header + lines))
    (f,) = by_rule(ds, "console_logins")
    assert f.severity == Severity.LOW
    assert f.title == "Could not tell whether 1 console sign-in used MFA"
    assert "additionalEventData" in f.explanation
    assert f.row_count == 1 == rows_for(ds, f)
    assert by_rule(ds, "root_activity")[0].title == "No root account activity"
