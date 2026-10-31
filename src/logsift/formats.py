"""Recognise what kind of file was loaded."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from logsift.loader import Sniff


class Format(StrEnum):
    GENERIC = "generic"
    VPC_V2 = "vpc_flow_v2"
    VPC_CUSTOM = "vpc_flow_custom"
    CW_INSIGHTS = "cloudwatch_insights"
    ALB = "alb_access"
    NLB = "nlb_access"


LABELS = {
    Format.GENERIC: "Generic delimited file",
    Format.VPC_V2: "VPC Flow Logs, default version 2 format",
    Format.VPC_CUSTOM: "VPC Flow Logs, custom format with header",
    Format.CW_INSIGHTS: "CloudWatch Logs Insights export",
    Format.ALB: "Application Load Balancer access log",
    Format.NLB: "Network Load Balancer access log",
}

# Canonical flow-log field names (underscored) keyed by their squashed spelling.
FLOW_FIELDS: dict[str, str] = {
    "version": "version",
    "accountid": "account_id",
    "interfaceid": "interface_id",
    "srcaddr": "srcaddr",
    "dstaddr": "dstaddr",
    "srcport": "srcport",
    "dstport": "dstport",
    "protocol": "protocol",
    "packets": "packets",
    "bytes": "bytes",
    "start": "start",
    "end": "end",
    "action": "action",
    "logstatus": "log_status",
    "vpcid": "vpc_id",
    "subnetid": "subnet_id",
    "instanceid": "instance_id",
    "tcpflags": "tcp_flags",
    "type": "type",
    "pktsrcaddr": "pkt_srcaddr",
    "pktdstaddr": "pkt_dstaddr",
    "region": "region",
    "azid": "az_id",
    "sublocationtype": "sublocation_type",
    "sublocationid": "sublocation_id",
    "pktsrcawsservice": "pkt_src_aws_service",
    "pktdstawsservice": "pkt_dst_aws_service",
    "flowdirection": "flow_direction",
    "trafficpath": "traffic_path",
    "ecsclustername": "ecs_cluster_name",
    "ecsclusterarn": "ecs_cluster_arn",
    "ecscontainerinstanceid": "ecs_container_instance_id",
    "ecscontainerinstancearn": "ecs_container_instance_arn",
    "ecsservicename": "ecs_service_name",
    "ecstaskdefinitionarn": "ecs_task_definition_arn",
    "ecstaskid": "ecs_task_id",
    "ecstaskarn": "ecs_task_arn",
    "ecscontainerid": "ecs_container_id",
    "ecssecondcontainerid": "ecs_second_container_id",
    "rejectreason": "reject_reason",
}

V2_FIELDS = [
    "version",
    "account_id",
    "interface_id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log_status",
]

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

ACTIONS = {"ACCEPT", "REJECT", "-"}
STATUSES = {"OK", "NODATA", "SKIPDATA"}
ENI_RE = re.compile(r"^eni-[0-9a-f]{8,17}$")
ACCOUNT_RE = re.compile(r"^\d{12}$")
ISO_TIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


@dataclass
class FormatInfo:
    kind: Format
    # Raw column name -> canonical flow field, for columns that map to one.
    flow_columns: dict[str, str] = field(default_factory=dict)
    # "columns" when flow fields are regular columns, "message" when they must be
    # split out of a CloudWatch @message column, "" when the file is not a flow log.
    flow_source: str = ""
    message_column: str = ""
    # Raw column name -> load balancer field name, for ALB and NLB access logs.
    lb_columns: dict[str, str] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return LABELS[self.kind]

    @property
    def is_flow_log(self) -> bool:
        return bool(self.flow_source)

    @property
    def is_lb_log(self) -> bool:
        return self.kind in (Format.ALB, Format.NLB)

    @property
    def has_rules(self) -> bool:
        return self.is_flow_log or self.is_lb_log

    @property
    def dash_means_missing(self) -> bool:
        """AWS log formats write "-" for a field that has no value."""
        return self.is_flow_log or self.is_lb_log


def squash(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def canonical(name: str) -> str | None:
    return FLOW_FIELDS.get(squash(name))


def looks_like_v2_line(fields: list[str]) -> bool:
    if len(fields) != 14 or fields[0] != "2":
        return False
    return bool(
        ACCOUNT_RE.match(fields[1])
        and ENI_RE.match(fields[2])
        and fields[12] in ACTIONS
        and fields[13] in STATUSES
    )


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


def positional(cols: list[str], names: list[str]) -> dict[str, str]:
    """Map raw column_N names onto known field names; anything past the end is extra_N."""
    out: dict[str, str] = {}
    for i, raw in enumerate(cols):
        out[raw] = names[i] if i < len(names) else f"extra_{i - len(names) + 1}"
    return out


def mostly(checks: list[bool]) -> bool:
    return bool(checks) and sum(checks) / len(checks) >= 0.8


def detect_format(sn: Sniff) -> FormatInfo:
    """Work out which format the sniffed file is in."""
    cols = sn.columns
    squashed = [squash(c) for c in cols]

    if not sn.has_header and sn.delimiter == " ":
        if mostly([looks_like_alb_line(r) for r in sn.rows]):
            info = FormatInfo(Format.ALB, lb_columns=positional(cols, ALB_FIELDS))
            info.reasons.append(
                f"{len(cols)} space-separated fields starting with the listener type, a "
                "timestamp and app/<name>"
            )
            return info
        if mostly([looks_like_nlb_line(r) for r in sn.rows]):
            info = FormatInfo(Format.NLB, lb_columns=positional(cols, NLB_FIELDS))
            info.reasons.append(
                f"{len(cols)} space-separated fields starting with tls, a version, a "
                "timestamp and net/<name>"
            )
            return info

    if sn.has_header and any(c.startswith("@") for c in cols):
        info = FormatInfo(Format.CW_INSIGHTS)
        info.reasons.append("header has CloudWatch field names starting with @")
        mapped = {c: canonical(c) for c in cols if canonical(c)}
        message = next((c for c in cols if squash(c) == "message"), "")
        if message:
            idx = cols.index(message)
            sample = [r[idx].split(" ") for r in sn.rows if idx < len(r) and r[idx]]
            if sample and sum(looks_like_v2_line(s) for s in sample) / len(sample) >= 0.8:
                info.flow_source = "message"
                info.message_column = message
                info.flow_columns = dict(zip(V2_FIELDS, V2_FIELDS, strict=True))
                info.reasons.append("@message holds VPC Flow Log version 2 records")
                return info
        if {"srcaddr", "dstaddr"} <= set(mapped.values()) and "action" in mapped.values():
            info.flow_source = "columns"
            info.flow_columns = {k: v for k, v in mapped.items() if v}
            info.reasons.append("parsed fields include VPC Flow Log columns")
        return info

    if not sn.has_header and sn.delimiter == " " and len(cols) == 14:
        checked = [looks_like_v2_line(r) for r in sn.rows]
        if checked and sum(checked) / len(checked) >= 0.8:
            info = FormatInfo(Format.VPC_V2, flow_source="columns")
            info.flow_columns = dict(zip(cols, V2_FIELDS, strict=True))
            info.reasons.append("14 space-separated fields starting with version 2")
            return info

    if sn.has_header:
        mapped = {c: canonical(c) for c in cols}
        hits = {v for v in mapped.values() if v}
        if (
            len(hits) >= 4
            and {"srcaddr", "dstaddr"} <= hits
            and ("action" in hits or "bytes" in hits)
        ):
            info = FormatInfo(Format.VPC_CUSTOM, flow_source="columns")
            info.flow_columns = {k: v for k, v in mapped.items() if v}
            info.reasons.append(f"header names {len(hits)} known VPC Flow Log fields")
            return info

    info = FormatInfo(Format.GENERIC)
    info.reasons.append(f"{sn.delimiter_name}-separated with {len(cols)} columns")
    _ = squashed
    return info
