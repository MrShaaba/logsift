"""Build a typed ``lb`` table from an ALB or NLB access log loaded as raw columns.

The raw table has positional ``column_N`` names. This gives every field its documented
name and type, then adds the derived columns the rules and the explorer want: client and
target split into address and port, the request line split into method, URL, host and
path, a total processing time, and for NLB logs whether the handshake completed and what
the client's TLS alert means.
"""

from __future__ import annotations

import duckdb

from logsift.formats.base import Format, FormatInfo
from logsift.sql import q

ALB_TYPES: dict[str, str] = {
    "time": "TIMESTAMP",
    "request_processing_time": "DOUBLE",
    "target_processing_time": "DOUBLE",
    "response_processing_time": "DOUBLE",
    "elb_status_code": "INTEGER",
    "target_status_code": "INTEGER",
    "received_bytes": "BIGINT",
    "sent_bytes": "BIGINT",
    "matched_rule_priority": "INTEGER",
    "request_creation_time": "TIMESTAMP",
}
NLB_TYPES: dict[str, str] = {
    "time": "TIMESTAMP",
    "connection_time": "BIGINT",
    "tls_handshake_time": "BIGINT",
    "received_bytes": "BIGINT",
    "sent_bytes": "BIGINT",
    "incoming_tls_alert": "INTEGER",
    "tls_connection_creation_time": "TIMESTAMP",
}

# TLS alert descriptions (RFC 5246 and RFC 8446).
TLS_ALERTS: dict[int, str] = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    41: "no_certificate",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    60: "export_restriction",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    100: "no_renegotiation",
    109: "missing_extension",
    110: "unsupported_extension",
    111: "certificate_unobtainable",
    112: "unrecognized_name",
    113: "bad_certificate_status_response",
    114: "bad_certificate_hash_value",
    115: "unknown_psk_identity",
    116: "certificate_required",
    120: "no_application_protocol",
}

# Display order: the columns people look at first, then the rest in file order.
ALB_ORDER = [
    "time",
    "type",
    "client_ip",
    "client_port",
    "method",
    "host",
    "path",
    "http_version",
    "elb_status_code",
    "target_status_code",
    "target_ip",
    "target_port",
    "target_group",
    "request_processing_time",
    "target_processing_time",
    "response_processing_time",
    "total_time",
    "received_bytes",
    "sent_bytes",
    "user_agent",
    "ssl_protocol",
    "ssl_cipher",
    "actions_executed",
    "redirect_url",
    "error_reason",
    "matched_rule_priority",
    "request_creation_time",
]
NLB_ORDER = [
    "time",
    "client_ip",
    "client_port",
    "destination_ip",
    "destination_port",
    "connection_time",
    "tls_handshake_time",
    "handshake_ok",
    "received_bytes",
    "sent_bytes",
    "incoming_tls_alert",
    "alert_name",
    "tls_protocol_version",
    "tls_cipher",
    "tls_named_group",
    "domain_name",
    "alpn_fe_protocol",
    "alpn_be_protocol",
    "alpn_client_preference_list",
    "tls_connection_creation_time",
]

IP_PORT_RE = r"^(.*):([0-9]+)$"


def alert_name(code: int | None) -> str:
    if code is None:
        return "none"
    return TLS_ALERTS.get(code, f"alert {code}")


def split_address(col: str, ip: str, port: str) -> list[tuple[str, str]]:
    return [
        (ip, f"nullif(regexp_extract({q(col)}, '{IP_PORT_RE}', 1), '')"),
        (port, f"try_cast(regexp_extract({q(col)}, '{IP_PORT_RE}', 2) AS INTEGER)"),
    ]


def alb_derived() -> list[list[tuple[str, str]]]:
    first = split_address("client", "client_ip", "client_port") + split_address(
        "target", "target_ip", "target_port"
    )
    first += [
        ("method", "nullif(string_split(request, ' ')[1], '-')"),
        ("url", "nullif(string_split(request, ' ')[2], '-')"),
        ("http_version", "nullif(string_split(request, ' ')[3], '-')"),
        ("target_group", "nullif(regexp_extract(target_group_arn, 'targetgroup/([^/]+)/', 1), '')"),
        (
            "total_time",
            "CASE WHEN least(request_processing_time, target_processing_time, "
            "response_processing_time) < 0 THEN NULL ELSE request_processing_time + "
            "target_processing_time + response_processing_time END",
        ),
    ]
    second = [
        ("host", "nullif(regexp_extract(url, '^[a-zA-Z0-9+.-]+://([^/:]+)', 1), '')"),
        ("path", "nullif(regexp_extract(url, '^[a-zA-Z0-9+.-]+://[^/]+(/[^?]*)', 1), '')"),
    ]
    return [first, second]


def nlb_derived() -> list[list[tuple[str, str]]]:
    names = " ".join(f"WHEN {code} THEN '{name}'" for code, name in TLS_ALERTS.items())
    first = split_address("client", "client_ip", "client_port") + split_address(
        "destination", "destination_ip", "destination_port"
    )
    first += [
        ("handshake_ok", "tls_handshake_time IS NOT NULL"),
        (
            "alert_name",
            f"CASE incoming_tls_alert {names} ELSE 'alert ' || incoming_tls_alert END",
        ),
    ]
    return [first]


def build_lb_table(
    con: duckdb.DuckDBPyConnection,
    fmt: FormatInfo,
    source: str = "raw",
    target: str = "lb",
) -> list[str]:
    """Create ``target`` with documented column names and types. Returns its columns."""
    if fmt.kind not in (Format.ALB, Format.NLB):
        raise ValueError("not a load balancer log")
    types = ALB_TYPES if fmt.kind == Format.ALB else NLB_TYPES
    order = ALB_ORDER if fmt.kind == Format.ALB else NLB_ORDER
    levels = alb_derived() if fmt.kind == Format.ALB else nlb_derived()

    base = ", ".join(
        f"try_cast({q(raw)} AS {types.get(name, 'VARCHAR')}) AS {q(name)}"
        for raw, name in fmt.columns.items()
    )
    sql = f"SELECT {base} FROM {q(source)}"
    for level in levels:
        extra = ", ".join(f"{expr} AS {q(name)}" for name, expr in level)
        sql = f"SELECT *, {extra} FROM ({sql})"

    available = list(fmt.columns.values()) + [name for level in levels for name, _ in level]
    ordered = [c for c in order if c in available] + [c for c in available if c not in order]
    cols = ", ".join(q(c) for c in ordered)
    con.execute(f"DROP TABLE IF EXISTS {q(target)}")
    con.execute(
        f"CREATE TABLE {q(target)} AS SELECT row_number() OVER () AS row_no, {cols} FROM ({sql})"
    )
    return [r[0] for r in con.execute(f"DESCRIBE {q(target)}").fetchall()]
