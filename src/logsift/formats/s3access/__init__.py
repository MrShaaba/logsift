"""Amazon S3 server access logs: one space-delimited line per request, no header, with
the timestamp in brackets and the request line, referer and user agent in quotes."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import duckdb

from logsift.formats.base import Format, FormatInfo, FormatPlugin, mostly, positional
from logsift.formats.s3access.findings import build_timeline, run_rules
from logsift.formats.s3access.table import build_s3_table
from logsift.insights.cwlogs import QuerySpec, boolean, like, parse_clause, regex_escape
from logsift.loader import Sniff

if TYPE_CHECKING:
    from logsift.dataset import Dataset
    from logsift.insights.base import Finding

# The documented fields in file order. The bracketed time "[10/Mar/2026:08:00:38 +0000]"
# contains a space, so it arrives as two tokens: the time and the offset. Older files stop
# at the version id; the TLS and access point fields were added later.
S3_FIELDS = [
    "bucket_owner",
    "bucket",
    "time",
    "time_offset",
    "remote_ip",
    "requester",
    "request_id",
    "operation",
    "key",
    "request_uri",
    "http_status",
    "error_code",
    "bytes_sent",
    "object_size",
    "total_time",
    "turn_around_time",
    "referer",
    "user_agent",
    "version_id",
    "host_id",
    "signature_version",
    "cipher_suite",
    "authentication_type",
    "host_header",
    "tls_version",
    "access_point_arn",
    "acl_required",
]
S3_MIN_FIELDS = 19

# For parsing a line in Logs Insights: the bracketed time is one field there.
S3_PARSE_FIELDS = [f for f in S3_FIELDS if f != "time_offset"]
S3_QUOTED = {"request_uri", "referer", "user_agent"}
S3_NOTE = (
    "S3 server access logs are delivered to a bucket, not CloudWatch Logs. This query "
    "assumes the lines were shipped to a log group as they are; the same conditions work "
    "in Athena."
)
S3_DISPLAY = [
    "time",
    "remote_ip",
    "requester",
    "operation",
    "key",
    "http_status",
    "error_code",
    "bytes_sent",
]
S3_STATS = {
    "errors": (
        "stats count(*) as requests by {http_status}, {error_code} | sort requests desc | limit 50"
    ),
    "missing_keys": "stats count(*) as requests by {key} | sort requests desc | limit 50",
    "access_denied": "stats count(*) as requests by {key} | sort requests desc | limit 50",
    "delete_burst": (
        "stats count(*) as deletes by {remote_ip}, {user_agent} | sort deletes desc | limit 50"
    ),
    "top_clients": (
        "stats count(*) as requests, sum({bytes_sent}) as bytes by {operation} "
        "| sort requests desc | limit 50"
    ),
}


def principal_field(op: str, value: object) -> str | None:
    if op not in ("=", "<>") or not isinstance(value, str):
        return None
    if value == "anonymous":
        text = 'requester = "-"'
    elif value == "bucket owner":
        return None
    else:
        text = f"requester like /{regex_escape(value)}/"
    return text if op == "=" else f"not ({text})"


def prefix_field(op: str, value: object) -> str | None:
    if op not in ("=", "<>") or not isinstance(value, str):
        return None
    if value == "(bucket)":
        text = 'key = "-"'
    elif value == "(no prefix)":
        text = 'key not like "/"'
    else:
        text = f"key like /^{regex_escape(value)}/"
    return text if op == "=" else f"not ({text})"


S3_DERIVED = {
    "is_error": boolean("http_status >= 400", "http_status < 400"),
    "anonymous": boolean('requester = "-"', 'requester != "-"'),
    "principal": principal_field,
    "prefix": prefix_field,
    "verb": like("operation", "^[A-Z0-9]+\\.{v}\\."),
    "target": like("operation", "^[A-Z0-9]+\\.[A-Z_]+\\.{v}$"),
    "method": like("request_uri", "^{v} "),
    "path": like("request_uri", "^[A-Z]+ {v}(\\?| )"),
    "query": lambda op, v: None,
    "http_version": like("request_uri", " {v}$"),
}

TIME_RE = re.compile(r"^\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}$")
OFFSET_RE = re.compile(r"^[+-]\d{4}\]$")
# REST.GET.OBJECT, REST.PUT.PART, WEBSITE.GET.OBJECT, BATCH.DELETE.OBJECT, S3.EXPIRE.OBJECT
OPERATION_RE = re.compile(r"^(REST|SOAP|WEBSITE|BATCH|S3)\.[A-Z_]+(\.[A-Z_]+)*$")


def looks_like_s3_line(fields: list[str]) -> bool:
    return (
        len(fields) >= S3_MIN_FIELDS
        and bool(TIME_RE.match(fields[2]))
        and bool(OFFSET_RE.match(fields[3]))
        and bool(OPERATION_RE.match(fields[7]))
        and (fields[10].isdigit() or fields[10] == "-")
    )


class S3AccessPlugin(FormatPlugin):
    name = "s3_access"
    table = "s3"
    dash_means_missing = True

    def detect(self, sn: Sniff) -> FormatInfo | None:
        if sn.has_header or sn.delimiter != " ":
            return None
        if not mostly([looks_like_s3_line(r) for r in sn.rows]):
            return None
        return self.found(
            Format.S3_ACCESS,
            "S3 server access log",
            f"{len(sn.columns)} space-separated fields with a bucket owner, a bracketed "
            "timestamp and an S3 operation",
            columns=positional(sn.columns, S3_FIELDS),
        )

    def build_table(
        self, con: duckdb.DuckDBPyConnection, fmt: FormatInfo, source: str = "raw"
    ) -> list[str]:
        return build_s3_table(con, fmt, source, self.table)

    def findings(self, ds: Dataset) -> list[Finding]:
        return run_rules(ds)

    def timeline(self, ds: Dataset) -> dict[str, Any] | None:
        return build_timeline(ds)

    def query_spec(self, fmt: FormatInfo) -> QuerySpec | None:
        return QuerySpec(
            fields={n: n for n in S3_PARSE_FIELDS},
            time_columns=("time",),
            derived=S3_DERIVED,
            parse=parse_clause(S3_PARSE_FIELDS, quoted=S3_QUOTED, brackets={"time"}),
            display=S3_DISPLAY,
            missing="-",
            stats=S3_STATS,
            notes=[S3_NOTE],
        )
