"""Build a typed ``s3`` table from an S3 server access log loaded as raw columns.

The raw table has positional ``column_N`` names. This gives every field its documented
name and type, parses the bracketed timestamp, and adds what the rules and the explorer
want: the request line split into method, path and query, the key's prefix, a
``principal`` naming the user or role behind the request (or ``anonymous``), and flags
for anonymous and failed requests.
"""

from __future__ import annotations

import duckdb

from logsift.formats.base import Format, FormatInfo
from logsift.sql import q

S3_TYPES: dict[str, str] = {
    "http_status": "INTEGER",
    "bytes_sent": "BIGINT",
    "object_size": "BIGINT",
    "total_time": "BIGINT",
    "turn_around_time": "BIGINT",
}
# Not kept in the table: S3 always logs UTC, so the offset is "+0000]" on every line.
DROPPED = {"time_offset"}

# Display order: the columns people look at first, then the rest in file order.
S3_ORDER = [
    "time",
    "remote_ip",
    "principal",
    "operation",
    "key",
    "http_status",
    "error_code",
    "bytes_sent",
    "object_size",
    "total_time",
    "turn_around_time",
    "method",
    "path",
    "prefix",
    "anonymous",
    "is_error",
    "verb",
    "target",
    "requester",
    "referer",
    "user_agent",
    "authentication_type",
    "signature_version",
    "tls_version",
    "cipher_suite",
    "host_header",
    "bucket",
    "request_id",
]
S3_LAST = ["query", "http_version", "request_uri", "bucket_owner", "host_id"]

# Up to two path segments of the key: "images/thumbs/" for images/thumbs/123.jpg.
PREFIX_RE = r"^((?:[^/]+/){1,2})"
OPERATION_RE = r"^[A-Z0-9]+\.([A-Z_]+)\.(.+)$"


def s3_derived() -> list[list[tuple[str, str]]]:
    first = [
        ("method", "nullif(regexp_extract(request_uri, '^([A-Z]+) ', 1), '')"),
        ("path", "nullif(regexp_extract(request_uri, '^[A-Z]+ ([^ ?]+)', 1), '')"),
        ("query", "nullif(regexp_extract(request_uri, '^[A-Z]+ [^ ?]+\\?([^ ]*)', 1), '')"),
        ("http_version", "nullif(regexp_extract(request_uri, ' (HTTP/[0-9.]+)$', 1), '')"),
        (
            "prefix",
            f"CASE WHEN key IS NULL THEN NULL ELSE coalesce(nullif(regexp_extract(key, "
            f"'{PREFIX_RE}', 1), ''), '(no prefix)') END",
        ),
        ("verb", f"nullif(regexp_extract(operation, '{OPERATION_RE}', 1), '')"),
        ("target", f"nullif(regexp_extract(operation, '{OPERATION_RE}', 2), '')"),
        (
            "principal",
            "CASE WHEN requester IS NULL THEN 'anonymous' "
            "WHEN requester = bucket_owner THEN 'bucket owner' "
            "WHEN requester LIKE 'arn:%:assumed-role/%' "
            "THEN regexp_extract(requester, 'assumed-role/([^/]+)', 1) "
            "WHEN requester LIKE 'arn:%:user/%' "
            "THEN regexp_extract(requester, 'user/(?:.*/)?([^/]+)$', 1) "
            "WHEN requester LIKE 'arn:%:root' THEN 'root' "
            "WHEN requester LIKE 'svc:%' THEN substr(requester, 5) "
            "ELSE requester END",
        ),
        ("anonymous", "requester IS NULL"),
        ("is_error", "coalesce(http_status >= 400, false)"),
    ]
    return [first]


def build_s3_table(
    con: duckdb.DuckDBPyConnection,
    fmt: FormatInfo,
    source: str = "raw",
    target: str = "s3",
) -> list[str]:
    """Create ``target`` with documented column names and types. Returns its columns."""
    if fmt.kind != Format.S3_ACCESS:
        raise ValueError("not an S3 server access log")
    base_parts: list[str] = []
    for raw, name in fmt.columns.items():
        if name in DROPPED:
            continue
        if name == "time":
            expr = f"try_strptime(cast({q(raw)} AS VARCHAR), '[%d/%b/%Y:%H:%M:%S')"
        else:
            expr = f"try_cast({q(raw)} AS {S3_TYPES.get(name, 'VARCHAR')})"
        base_parts.append(f"{expr} AS {q(name)}")
    sql = f"SELECT {', '.join(base_parts)} FROM {q(source)}"
    levels = s3_derived()
    for level in levels:
        extra = ", ".join(f"{expr} AS {q(name)}" for name, expr in level)
        sql = f"SELECT *, {extra} FROM ({sql})"

    available = [c for c in fmt.columns.values() if c not in DROPPED]
    available += [name for level in levels for name, _ in level]
    head = [c for c in S3_ORDER if c in available]
    tail = [c for c in S3_LAST if c in available]
    middle = [c for c in available if c not in head and c not in tail]
    cols = ", ".join(q(c) for c in head + middle + tail)
    con.execute(f"DROP TABLE IF EXISTS {q(target)}")
    con.execute(
        f"CREATE TABLE {q(target)} AS SELECT row_number() OVER () AS row_no, {cols} FROM ({sql})"
    )
    return [r[0] for r in con.execute(f"DESCRIBE {q(target)}").fetchall()]
