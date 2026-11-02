"""VPC Flow Logs: the default version 2 lines, custom formats with a header, and
CloudWatch Logs Insights exports that carry flow records."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

import duckdb

from logsift.formats.base import Format, FormatInfo, FormatPlugin, mostly, squash
from logsift.formats.vpcflow.cutover import flow_cutover_checks, flow_health
from logsift.formats.vpcflow.findings import build_timeline, run_rules
from logsift.formats.vpcflow.table import FLOW_FIELDS, V2_FIELDS, build_flow_table, canonical
from logsift.insights.cwlogs import QuerySpec, parse_clause, private_ip
from logsift.loader import Sniff

if TYPE_CHECKING:
    from logsift.cutover import Change, DiffContext, Health
    from logsift.dataset import Dataset
    from logsift.insights.base import Finding

__all__ = [
    "FLOW_FIELDS",
    "V2_FIELDS",
    "CloudWatchInsightsPlugin",
    "VpcFlowPlugin",
    "canonical",
    "looks_like_v2_line",
]

ACTIONS = {"ACCEPT", "REJECT", "-"}

# The field names CloudWatch Logs discovers in a default-format flow log group.
CW_FLOW_FIELDS = {
    "version": "version",
    "account_id": "accountId",
    "interface_id": "interfaceId",
    "srcaddr": "srcAddr",
    "dstaddr": "dstAddr",
    "srcport": "srcPort",
    "dstport": "dstPort",
    "protocol": "protocol",
    "packets": "packets",
    "bytes": "bytes",
    "start": "start",
    "end": "end",
    "action": "action",
    "log_status": "logStatus",
}
FLOW_DISPLAY = ["srcaddr", "srcport", "dstaddr", "dstport", "protocol", "action", "bytes"]
# SYN set and ACK clear, written as the values flow logs can hold (FIN, SYN, RST, SYN-ACK).
SYN_ONLY_SQL = r"\(tcp_flags & 2\) <> 0 AND \(tcp_flags & 16\) = 0"
SYN_ONLY_NOTE = (
    "tcp_flags 2, 3, 6 and 7 are the values with SYN set and ACK clear; flow logs only "
    "record FIN, SYN, RST and SYN-ACK."
)
FLOW_STATS = {
    "rejected_traffic": (
        "stats count(*) as flows by {dstaddr}, {dstport}, {protocol} | sort flows desc | limit 50"
    ),
    "rejected_cluster": (
        "stats count(*) as flows, sum({bytes}) as bytes by {srcaddr} | sort flows desc | limit 50"
    ),
    "top_talkers": (
        "stats sum({bytes}) as bytes, count(*) as flows by {dstaddr}, {dstport} "
        "| sort bytes desc | limit 50"
    ),
    "public_traffic": (
        "stats count(*) as flows, sum({bytes}) as bytes by {srcaddr}, {dstaddr} "
        "| sort bytes desc | limit 50"
    ),
    "port_sweep": "stats count(*) as flows by {dstport} | sort {dstport} asc | limit 1000",
}
STATUSES = {"OK", "NODATA", "SKIPDATA"}
ENI_RE = re.compile(r"^eni-[0-9a-f]{8,17}$")
ACCOUNT_RE = re.compile(r"^\d{12}$")


def looks_like_v2_line(fields: list[str]) -> bool:
    if len(fields) != 14 or fields[0] != "2":
        return False
    return bool(
        ACCOUNT_RE.match(fields[1])
        and ENI_RE.match(fields[2])
        and fields[12] in ACTIONS
        and fields[13] in STATUSES
    )


class VpcFlowPlugin(FormatPlugin):
    """Flow logs delivered as files: version 2 lines, or a custom format with a header."""

    name = "vpc_flow"
    table = "flow"
    dash_means_missing = True
    time_column = "start_ts"

    def detect(self, sn: Sniff) -> FormatInfo | None:
        cols = sn.columns
        if (
            not sn.has_header
            and sn.delimiter == " "
            and len(cols) == 14
            and mostly([looks_like_v2_line(r) for r in sn.rows])
        ):
            return self.found(
                Format.VPC_V2,
                "VPC Flow Logs, default version 2 format",
                "14 space-separated fields starting with version 2",
                columns=dict(zip(cols, V2_FIELDS, strict=True)),
                options={"flow_source": "columns"},
            )
        if sn.has_header:
            mapped = {c: canonical(c) for c in cols}
            hits = {v for v in mapped.values() if v}
            if (
                len(hits) >= 4
                and {"srcaddr", "dstaddr"} <= hits
                and ("action" in hits or "bytes" in hits)
            ):
                return self.found(
                    Format.VPC_CUSTOM,
                    "VPC Flow Logs, custom format with header",
                    f"header names {len(hits)} known VPC Flow Log fields",
                    columns={k: v for k, v in mapped.items() if v},
                    options={"flow_source": "columns"},
                )
        return None

    def build_table(
        self, con: duckdb.DuckDBPyConnection, fmt: FormatInfo, source: str = "raw"
    ) -> list[str]:
        return build_flow_table(con, fmt, source, self.table)

    def findings(self, ds: Dataset) -> list[Finding]:
        return run_rules(ds)

    def timeline(self, ds: Dataset) -> dict[str, Any] | None:
        return build_timeline(ds)

    def health(self, columns: set[str]) -> Health | None:
        return flow_health(columns)

    def cutover_checks(self, ctx: DiffContext) -> list[Change]:
        return flow_cutover_checks(ctx)

    def query_spec(self, fmt: FormatInfo) -> QuerySpec | None:
        notes: list[str] = []
        parse = ""
        if fmt.kind == Format.VPC_CUSTOM:
            # CloudWatch only discovers the default fields; a custom format is parsed out of
            # @message in the file's own order, under the canonical names.
            names = list(fmt.columns.values())
            fields = {n: n for n in names}
            parse = parse_clause(names)
            notes.append(
                "Custom format: CloudWatch does not discover these fields, so they are "
                "parsed out of @message in the file's own field order."
            )
        else:
            fields = dict(CW_FLOW_FIELDS)
        return QuerySpec(
            fields=fields,
            time_columns=("start_ts", "start"),
            funcs={"is_private": private_ip},
            parse=parse,
            display=[fields[c] for c in FLOW_DISPLAY if c in fields],
            missing="-",
            rewrites=[(SYN_ONLY_SQL, "tcp_flags IN (2, 3, 6, 7)", SYN_ONLY_NOTE)],
            stats=FLOW_STATS,
            notes=notes,
        )


class CloudWatchInsightsPlugin(VpcFlowPlugin):
    """A CloudWatch Logs Insights export. It gets the flow table and rules when the flow
    fields are there, either as parsed columns or inside @message."""

    name = "cloudwatch_insights"

    def detect(self, sn: Sniff) -> FormatInfo | None:
        cols = sn.columns
        if not (sn.has_header and any(c.startswith("@") for c in cols)):
            return None
        label = "CloudWatch Logs Insights export"
        reason = "header has CloudWatch field names starting with @"
        message = next((c for c in cols if squash(c) == "message"), "")
        if message:
            idx = cols.index(message)
            sample = [r[idx].split(" ") for r in sn.rows if idx < len(r) and r[idx]]
            if mostly([looks_like_v2_line(s) for s in sample]):
                return self.found(
                    Format.CW_INSIGHTS,
                    label,
                    reason,
                    "@message holds VPC Flow Log version 2 records",
                    columns=dict(zip(V2_FIELDS, V2_FIELDS, strict=True)),
                    options={"flow_source": "message", "message_column": message},
                )
        mapped = {c: canonical(c) for c in cols if canonical(c)}
        hits = set(mapped.values())
        if {"srcaddr", "dstaddr", "action"} <= hits:
            return self.found(
                Format.CW_INSIGHTS,
                label,
                reason,
                "parsed fields include VPC Flow Log columns",
                columns={k: v for k, v in mapped.items() if v},
                options={"flow_source": "columns"},
            )
        return self.found(Format.CW_INSIGHTS, label, reason, table="")
