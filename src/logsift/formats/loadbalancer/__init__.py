"""Application and Network Load Balancer access logs: space-delimited, no header."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import duckdb

from logsift.formats.base import Format, FormatInfo, FormatPlugin, mostly, positional
from logsift.formats.loadbalancer.findings import build_timeline, run_rules
from logsift.formats.loadbalancer.table import build_lb_table
from logsift.loader import Sniff

if TYPE_CHECKING:
    from logsift.dataset import Dataset
    from logsift.insights.base import Finding

# Application Load Balancer access log fields, in file order. Older files stop early
# (the classification and connection trace fields were added later), so a line with at
# least the first 25 fields counts.
ALB_FIELDS = [
    "type",
    "time",
    "elb",
    "client",
    "target",
    "request_processing_time",
    "target_processing_time",
    "response_processing_time",
    "elb_status_code",
    "target_status_code",
    "received_bytes",
    "sent_bytes",
    "request",
    "user_agent",
    "ssl_cipher",
    "ssl_protocol",
    "target_group_arn",
    "trace_id",
    "domain_name",
    "chosen_cert_arn",
    "matched_rule_priority",
    "request_creation_time",
    "actions_executed",
    "redirect_url",
    "error_reason",
    "target_port_list",
    "target_status_code_list",
    "classification",
    "classification_reason",
    "conn_trace_id",
]
ALB_MIN_FIELDS = 25
ALB_TYPES = {"http", "https", "h2", "grpcs", "ws", "wss"}

# Network Load Balancer access logs only cover TLS listeners; every line starts with
# "tls" and the log version.
NLB_FIELDS = [
    "type",
    "version",
    "time",
    "elb",
    "listener",
    "client",
    "destination",
    "connection_time",
    "tls_handshake_time",
    "received_bytes",
    "sent_bytes",
    "incoming_tls_alert",
    "chosen_cert_arn",
    "chosen_cert_serial",
    "tls_cipher",
    "tls_protocol_version",
    "tls_named_group",
    "domain_name",
    "alpn_fe_protocol",
    "alpn_be_protocol",
    "alpn_client_preference_list",
    "tls_connection_creation_time",
]
NLB_MIN_FIELDS = 18

ISO_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def looks_like_alb_line(fields: list[str]) -> bool:
    return (
        len(fields) >= ALB_MIN_FIELDS
        and fields[0] in ALB_TYPES
        and bool(ISO_TIME_RE.match(fields[1]))
        and fields[2].startswith("app/")
        and fields[8].isdigit()
    )


def looks_like_nlb_line(fields: list[str]) -> bool:
    return (
        len(fields) >= NLB_MIN_FIELDS
        and fields[0] == "tls"
        and bool(ISO_TIME_RE.match(fields[2]))
        and fields[3].startswith("net/")
    )


class LoadBalancerPlugin(FormatPlugin):
    name = "load_balancer"
    table = "lb"
    dash_means_missing = True

    def detect(self, sn: Sniff) -> FormatInfo | None:
        if sn.has_header or sn.delimiter != " ":
            return None
        cols = sn.columns
        if mostly([looks_like_alb_line(r) for r in sn.rows]):
            return self.found(
                Format.ALB,
                "Application Load Balancer access log",
                f"{len(cols)} space-separated fields starting with the listener type, a "
                "timestamp and app/<name>",
                columns=positional(cols, ALB_FIELDS),
            )
        if mostly([looks_like_nlb_line(r) for r in sn.rows]):
            return self.found(
                Format.NLB,
                "Network Load Balancer access log",
                f"{len(cols)} space-separated fields starting with tls, a version, a "
                "timestamp and net/<name>",
                columns=positional(cols, NLB_FIELDS),
            )
        return None

    def build_table(
        self, con: duckdb.DuckDBPyConnection, fmt: FormatInfo, source: str = "raw"
    ) -> list[str]:
        return build_lb_table(con, fmt, source, self.table)

    def findings(self, ds: Dataset) -> list[Finding]:
        return run_rules(ds)

    def timeline(self, ds: Dataset) -> dict[str, Any] | None:
        return build_timeline(ds)
