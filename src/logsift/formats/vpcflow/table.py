"""Build a canonical, typed ``flow`` table from whichever flow-log shape was loaded."""

from __future__ import annotations

import duckdb

from logsift.formats.base import FormatInfo, squash
from logsift.sql import q

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


def canonical(name: str) -> str | None:
    """The canonical flow-log field a header name refers to, or None."""
    return FLOW_FIELDS.get(squash(name))


FLOW_TYPES: dict[str, str] = {
    "version": "INTEGER",
    "srcport": "INTEGER",
    "dstport": "INTEGER",
    "protocol": "INTEGER",
    "packets": "BIGINT",
    "bytes": "BIGINT",
    "start": "BIGINT",
    "end": "BIGINT",
    "tcp_flags": "INTEGER",
}
CANONICAL_ORDER = list(dict.fromkeys(FLOW_FIELDS.values()))

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 132: "SCTP"}

# tcp-flags in flow logs is the OR of every flag seen in the aggregation window.
FIN, SYN, RST, PSH, ACK, URG = 1, 2, 4, 8, 16, 32


def protocol_name(number: int | None) -> str:
    if number is None:
        return "unknown"
    return PROTOCOLS.get(number, f"protocol {number}")


def build_flow_table(
    con: duckdb.DuckDBPyConnection,
    fmt: FormatInfo,
    source: str = "raw",
    target: str = "flow",
) -> list[str]:
    """Create ``target`` with canonical column names and types. Returns its columns."""
    source_kind = fmt.options.get("flow_source", "")
    if not source_kind:
        raise ValueError("not a flow log")

    raw_types = dict(
        con.execute(f"DESCRIBE {q(source)}").fetchall()
        and [(r[0], r[1]) for r in con.execute(f"DESCRIBE {q(source)}").fetchall()]
    )

    selects: list[str] = []
    present: list[str] = []

    def add(canon: str, expr: str) -> None:
        wanted = FLOW_TYPES.get(canon, "VARCHAR")
        selects.append(f"try_cast({expr} AS {wanted}) AS {q(canon)}")
        present.append(canon)

    if source_kind == "message":
        parts = f"string_split({q(fmt.options['message_column'])}, ' ')"
        for i, canon in enumerate(fmt.columns.values(), start=1):
            add(canon, f"nullif({parts}[{i}], '-')")
        stamp = next((c for c in raw_types if c.lower() in ("@timestamp", "timestamp")), None)
        if stamp:
            selects.append(f"try_cast({q(stamp)} AS TIMESTAMP) AS log_time")
    else:
        by_canon = {canon: raw for raw, canon in fmt.columns.items()}
        for canon in CANONICAL_ORDER:
            if canon in by_canon:
                raw = by_canon[canon]
                expr = q(raw)
                if raw_types.get(raw, "VARCHAR") == "VARCHAR":
                    expr = f"nullif({expr}, '-')"
                add(canon, expr)
        stamp = next((c for c in raw_types if c.lower() in ("@timestamp", "timestamp")), None)
        if stamp:
            selects.append(f"try_cast({q(stamp)} AS TIMESTAMP) AS log_time")

    if "start" in present:
        selects.append(f"to_timestamp({q('start')}) AT TIME ZONE 'UTC' AS start_ts")
    elif stamp:
        selects.append("log_time AS start_ts")
    if "end" in present:
        selects.append(f"to_timestamp({q('end')}) AT TIME ZONE 'UTC' AS end_ts")

    con.execute(f"DROP TABLE IF EXISTS {q(target)}")
    con.execute(
        f"CREATE TABLE {q(target)} AS SELECT row_number() OVER () AS row_no, * FROM "
        f"(SELECT {', '.join(selects)} FROM {q(source)})"
    )
    return [r[0] for r in con.execute(f"DESCRIBE {q(target)}").fetchall()]
