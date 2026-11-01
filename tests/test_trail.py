from __future__ import annotations

from datetime import datetime
from pathlib import Path

from logsift.dataset import Dataset
from tests.conftest import write
from tests.test_formats import ATHENA_HEADER, athena_line


def count(ds: Dataset, where: str) -> int:
    return int(ds.cursor().execute(f"SELECT count(*) FROM trail WHERE {where}").fetchone()[0])


def test_trail_table_has_typed_and_derived_columns(trail_ds: Dataset) -> None:
    assert trail_ds.table == "trail" and trail_ds.format.plugin == "cloudtrail"
    assert trail_ds.rows == 2267
    assert trail_ds.load.warnings == []
    names = [c for c, _ in trail_ds.columns]
    assert names[:4] == ["event_time", "event_name", "service", "principal"]
    assert names[-1] == "event_json"
    types = dict(trail_ds.columns)
    assert types["event_time"] == "TIMESTAMP"
    assert types["read_only"] == "BOOLEAN"
    assert types["mfa_used"] == "BOOLEAN"
    assert types["access_denied"] == "BOOLEAN"
    assert types["recipient_account_id"] == "VARCHAR"


def test_identity_is_read_from_the_event_record(trail_ds: Dataset) -> None:
    rows = (
        trail_ds.cursor()
        .execute("SELECT identity_type, count(*) FROM trail GROUP BY 1 ORDER BY 2 DESC")
        .fetchall()
    )
    assert rows == [("AssumedRole", 1346), ("IAMUser", 749), ("AWSService", 161), ("Root", 11)]
    principals = dict(
        trail_ds.cursor().execute("SELECT principal, count(*) FROM trail GROUP BY 1").fetchall()
    )
    # Role sessions collapse onto the role name, service calls onto the calling service.
    assert principals["shop-web-role"] == 922
    assert principals["autoscaling.amazonaws.com"] == 120
    assert principals["root"] == 11
    assert "i-0a1b2c3d4e5f60101" not in principals
    row = (
        trail_ds.cursor()
        .execute(
            "SELECT event_time, service, aws_region, user_name, identity_arn, user_agent "
            "FROM trail WHERE principal = 'shop-web-role' LIMIT 1"
        )
        .fetchone()
    )
    assert row is not None
    time, service, region, user_name, arn, agent = row
    assert isinstance(time, datetime) and time.year == 2026
    assert (service, region) == ("ssm", "eu-west-1")
    assert user_name.startswith("i-") and arn.endswith(f"shop-web-role/{user_name}")
    assert agent.startswith("aws-sdk-java")


def test_mfa_login_result_and_root_flags(trail_ds: Dataset) -> None:
    rows = (
        trail_ds.cursor()
        .execute(
            "SELECT principal, mfa_used, login_result, is_root FROM trail "
            "WHERE event_name = 'ConsoleLogin' ORDER BY event_time"
        )
        .fetchall()
    )
    assert rows == [
        ("alice", True, "Success", False),
        ("carol", False, "Failure", False),
        ("carol", False, "Success", False),
        ("bob", True, "Success", False),
        ("root", False, "Success", True),
        ("carol", False, "Success", False),
    ]
    assert count(trail_ds, "login_result IS NOT NULL") == 6
    assert count(trail_ds, "is_root") == 11
    # Long-term access keys carry no MFA information at all.
    assert (
        count(
            trail_ds,
            "identity_type = 'IAMUser' AND user_agent LIKE 'aws-cli%' AND mfa_used IS NULL",
        )
        > 0
    )


def test_denied_and_global_flags(trail_ds: Dataset) -> None:
    assert count(trail_ds, "access_denied") == 407
    assert count(trail_ds, "access_denied AND error_code = 'Client.UnauthorizedOperation'") == 31
    assert count(trail_ds, "error_code IS NOT NULL AND NOT access_denied") == 0
    assert count(trail_ds, "global_service AND aws_region <> 'us-east-1'") == 0
    assert count(trail_ds, "service = 'iam' AND NOT global_service") == 0
    assert (
        count(
            trail_ds,
            "error_message LIKE 'User: arn:%is not authorized to perform: ssm:GetParameter on%'",
        )
        == 181
    )


def test_athena_struct_text_without_json_column(tmp_path: Path) -> None:
    text = ATHENA_HEADER + "\n" + "".join(athena_line(i) for i in range(9))
    text += athena_line(9, "RunInstances", "Client.UnauthorizedOperation")
    ds = Dataset.open(write(tmp_path, "athena.csv", text))
    assert ds.table == "trail" and ds.rows == 10
    row = (
        ds.cursor()
        .execute(
            "SELECT identity_type, identity_arn, principal, mfa_used, service, access_denied "
            "FROM trail WHERE event_name = 'RunInstances'"
        )
        .fetchone()
    )
    assert row == (
        "AssumedRole",
        "arn:aws:sts::123456789012:assumed-role/app-role/app",
        "app-role",
        False,
        "ec2",
        True,
    )
    assert "eventversion" in [c for c, _ in ds.columns]


def test_console_export_without_the_record_column(tmp_path: Path) -> None:
    header = (
        "Event ID,Event time,User name,Event name,Event source,AWS region,Source IP address,"
        "Error code,Read-only\n"
    )
    lines = "".join(
        f"e{i},2026-03-10T08:0{i}:00Z,alice,DescribeInstances,ec2.amazonaws.com,eu-west-1,"
        f"198.51.100.20,,true\n"
        for i in range(8)
    )
    lines += (
        "e9,2026-03-10T08:09:00Z,root,ConsoleLogin,signin.amazonaws.com,us-east-1,"
        "203.0.113.61,,false\n"
    )
    ds = Dataset.open(write(tmp_path, "console.csv", header + lines))
    assert ds.table == "trail"
    rows = (
        ds.cursor()
        .execute(
            "SELECT principal, identity_type, is_root, mfa_used, login_result FROM trail "
            "ORDER BY event_time"
        )
        .fetchall()
    )
    assert rows[0] == ("alice", None, False, None, None)
    assert rows[-1] == ("root", None, True, None, None)
