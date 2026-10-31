"""Build a typed ``trail`` table from a CloudTrail CSV export loaded as raw columns.

CloudTrail exports come in a few shapes: the console's event history download (one
column per headline field plus the full event record as JSON), a CloudTrail Lake or
Athena result with whatever columns the query selected, or a flattened export with
columns like ``userIdentity.type``. This gives every known column its canonical name,
then derives what the rules need and fills gaps from the JSON when a column is missing:
the identity type and ARN, whether MFA was used, the console sign-in result, and a
``principal`` that names the user or role behind the call.
"""

from __future__ import annotations

import duckdb

from logsift.flow import q
from logsift.formats import FormatInfo

BOOL_COLUMNS = {"read_only", "mfa_used", "mfa_authenticated"}
TIMESTAMP_COLUMNS = {"event_time"}

# Services whose events are recorded in us-east-1 whatever region the account works in.
GLOBAL_SERVICES = (
    "iam",
    "sts",  # the global endpoint only, see trail_derived
    "signin",
    "cloudfront",
    "route53",
    "route53domains",
    "organizations",
    "support",
    "health",
    "shield",
    "globalaccelerator",
    "waf",
    "access-analyzer",
    "budgets",
    "ce",
    "chatbot",
    "trustedadvisor",
    "account",
)

# Error codes that mean "the policy said no". Services spell it differently.
DENIED_CODES = (
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "Client.UnauthorizedOperation",
    "UnauthorizedAccess",
    "Client.UnauthorizedAccess",
    "AuthorizationError",
    "UnauthorizedException",
    "Forbidden",
    "403",
)

# Display order: the columns people look at first, then everything else in file order.
TRAIL_ORDER = [
    "event_time",
    "event_name",
    "service",
    "principal",
    "identity_type",
    "aws_region",
    "source_ip",
    "error_code",
    "error_message",
    "read_only",
    "mfa_used",
    "login_result",
    "access_denied",
    "is_root",
    "global_service",
    "user_name",
    "identity_arn",
    "access_key_id",
    "user_agent",
    "event_source",
    "event_type",
    "event_category",
    "resource_type",
    "resource_name",
    "event_id",
    "request_id",
    "recipient_account_id",
    "resources",
]
# Long JSON blobs go last so the explorer stays readable.
TRAIL_LAST = ["request_parameters", "response_elements", "additional_event_data", "event_json"]

# Regular expressions over JSON text, written so they also match the key=value rendering
# of a struct column from Athena or CloudTrail Lake (which lower-cases the keys, hence
# the case-insensitive flag).
RE_TYPE = r'(?i)(?:"type"\s*:\s*"|\btype=)([A-Za-z]+)'
RE_ARN = r'(?i)(?:"arn"\s*:\s*"|\barn=)(arn:[^",}\s]+)'
RE_USER_NAME = r'(?i)(?:"userName"\s*:\s*"|\busername=)([^",}\s]+)'
RE_IDENTITY_TYPE = r'"userIdentity"\s*:\s*\{[^{}]*?"type"\s*:\s*"([A-Za-z]+)"'
RE_IDENTITY_ARN = r'"userIdentity"\s*:\s*\{[^{}]*?"arn"\s*:\s*"(arn:[^"]+)"'
RE_MFA_USED = r'(?i)(?:"MFAUsed"\s*:\s*"|\bMFAUsed=)(Yes|No)'
RE_MFA_AUTH = r'(?i)(?:"mfaAuthenticated"\s*:\s*"?|\bmfaAuthenticated=)(true|false)'
RE_LOGIN = r'(?i)(?:"ConsoleLogin"\s*:\s*"|\bConsoleLogin=)(Success|Failure)'
RE_ERROR_MESSAGE = r'"errorMessage"\s*:\s*"((?:[^"\\]|\\.)*)"'
RE_USER_AGENT = r'"userAgent"\s*:\s*"((?:[^"\\]|\\.)*)"'
RE_SOURCE_IP = r'"sourceIPAddress"\s*:\s*"([^"]+)"'
RE_REGION = r'"awsRegion"\s*:\s*"([^"]+)"'


def boolish(expr: str) -> str:
    """true/false, yes/no, t/f and 1/0 as a BOOLEAN; anything else is NULL."""
    return (
        f"CASE lower(trim(cast({expr} AS VARCHAR))) WHEN 'true' THEN true WHEN 'yes' THEN true "
        "WHEN 't' THEN true WHEN '1' THEN true WHEN 'false' THEN false WHEN 'no' THEN false "
        "WHEN 'f' THEN false WHEN '0' THEN false END"
    )


def extract(col: str, pattern: str) -> str:
    """First capture group of ``pattern`` in ``col``, or NULL (also when col is absent)."""
    if col == "NULL":
        return "NULL"
    escaped = pattern.replace("'", "''")
    return f"nullif(regexp_extract({q(col)}, '{escaped}', 1), '')"


def flag(col: str, pattern: str, truthy: str) -> str:
    """BOOLEAN from a captured word: true when it equals ``truthy``, NULL when absent."""
    found = extract(col, pattern)
    return "NULL" if found == "NULL" else f"(lower({found}) = '{truthy.lower()}')"


def first_of(*exprs: str) -> str:
    live = [e for e in exprs if e != "NULL"]
    if not live:
        return "NULL"
    return live[0] if len(live) == 1 else f"coalesce({', '.join(live)})"


def trail_derived(available: set[str]) -> list[list[tuple[str, str]]]:
    def col(name: str) -> str:
        return name if name in available else "NULL"

    def plain(name: str) -> str:
        return q(name) if name in available else "NULL"

    identity, record = col("user_identity"), col("event_json")
    additional, response = col("additional_event_data"), col("response_elements")

    first: list[tuple[str, str]] = [
        ("aws_region", first_of(plain("aws_region"), extract(record, RE_REGION))),
        ("source_ip", first_of(plain("source_ip"), extract(record, RE_SOURCE_IP))),
        ("user_agent", first_of(plain("user_agent"), extract(record, RE_USER_AGENT))),
        ("error_message", first_of(plain("error_message"), extract(record, RE_ERROR_MESSAGE))),
        (
            "identity_type",
            first_of(
                plain("identity_type"),
                extract(identity, RE_TYPE),
                extract(record, RE_IDENTITY_TYPE),
            ),
        ),
        (
            "identity_arn",
            first_of(
                plain("identity_arn"), extract(identity, RE_ARN), extract(record, RE_IDENTITY_ARN)
            ),
        ),
        (
            "user_name",
            first_of(
                plain("user_name"), extract(identity, RE_USER_NAME), extract(record, RE_USER_NAME)
            ),
        ),
        (
            "mfa_used",
            first_of(
                plain("mfa_used"),
                plain("mfa_authenticated"),
                flag(additional, RE_MFA_USED, "Yes"),
                flag(record, RE_MFA_USED, "Yes"),
                flag(identity, RE_MFA_AUTH, "true"),
                flag(record, RE_MFA_AUTH, "true"),
            ),
        ),
        ("login_result", first_of(extract(response, RE_LOGIN), extract(record, RE_LOGIN))),
    ]
    # The raw columns these replace are dropped below, so the names can be reused.
    second: list[tuple[str, str]] = [
        ("service", "regexp_replace(event_source, '\\.amazonaws\\.com(\\.cn)?$', '')"),
        (
            "principal",
            "CASE WHEN identity_type = 'Root' OR identity_arn LIKE '%:root' "
            "OR lower(user_name) = 'root' THEN 'root' "
            "WHEN identity_arn LIKE '%:assumed-role/%' "
            "THEN regexp_extract(identity_arn, 'assumed-role/([^/]+)', 1) "
            "WHEN identity_arn LIKE '%:user/%' "
            "THEN regexp_extract(identity_arn, 'user/(?:.*/)?([^/]+)$', 1) "
            "WHEN identity_type = 'AWSService' THEN coalesce(user_name, source_ip) "
            "ELSE coalesce(user_name, identity_arn, identity_type, 'unknown') END",
        ),
        (
            "is_root",
            "coalesce(identity_type = 'Root' OR identity_arn LIKE '%:root' "
            "OR lower(user_name) = 'root', false)",
        ),
    ]
    codes = ", ".join(f"'{c}'" for c in DENIED_CODES)
    third: list[tuple[str, str]] = [
        (
            "access_denied",
            f"coalesce(error_code IN ({codes}) OR error_code ILIKE '%AccessDenied%' "
            "OR error_code ILIKE '%Unauthorized%', false)"
            if "error_code" in available
            else "false",
        ),
        (
            # STS has a global endpoint that records us-east-1 and regional ones that record
            # their own region, so only the former counts as global.
            "global_service",
            "coalesce(service IN ("
            + ", ".join(f"'{s}'" for s in GLOBAL_SERVICES if s != "sts")
            + ") OR (service = 'sts' AND aws_region = 'us-east-1'), false)",
        ),
    ]
    return [first, second, third]


def build_trail_table(
    con: duckdb.DuckDBPyConnection,
    fmt: FormatInfo,
    source: str = "raw",
    target: str = "trail",
) -> list[str]:
    """Create ``target`` with canonical column names and types. Returns its columns."""
    if not fmt.is_trail_log:
        raise ValueError("not a CloudTrail export")
    mapping = fmt.trail_columns
    available = set(mapping.values())

    base_parts: list[str] = []
    for raw, name in mapping.items():
        if name in BOOL_COLUMNS:
            expr = boolish(q(raw))
        elif name in TIMESTAMP_COLUMNS:
            expr = f"try_cast({q(raw)} AS TIMESTAMP)"
        else:
            expr = f"cast({q(raw)} AS VARCHAR)"
        base_parts.append(f"{expr} AS {q(name)}")
    sql = f"SELECT {', '.join(base_parts)} FROM {q(source)}"

    levels = trail_derived(available)
    for level in levels:
        replaced = [name for name, _ in level if name in available]
        keep = "*" + (f" EXCLUDE ({', '.join(q(c) for c in replaced)})" if replaced else "")
        extra = ", ".join(f"{expr} AS {q(name)}" for name, expr in level)
        sql = f"SELECT {keep}, {extra} FROM ({sql})"
        available |= {name for name, _ in level}

    head = [c for c in TRAIL_ORDER if c in available]
    tail = [c for c in TRAIL_LAST if c in available]
    middle = [c for c in available if c not in head and c not in tail]
    # Keep the file's own order for anything not pinned.
    file_order = list(mapping.values())
    middle.sort(key=lambda c: file_order.index(c) if c in file_order else len(file_order))
    cols = ", ".join(q(c) for c in head + middle + tail)
    con.execute(f"DROP TABLE IF EXISTS {q(target)}")
    con.execute(
        f"CREATE TABLE {q(target)} AS SELECT row_number() OVER () AS row_no, {cols} FROM ({sql})"
    )
    return [r[0] for r in con.execute(f"DESCRIBE {q(target)}").fetchall()]
