"""Build a canonical, typed ``flow`` table from whichever flow-log shape was loaded."""

from __future__ import annotations

import duckdb

from logsift.formats import FLOW_FIELDS, FormatInfo

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


def q(ident: str) -> str:
    return '"' + ident.replace('"', '""') + '"'


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
    if not fmt.is_flow_log:
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

    if fmt.flow_source == "message":
        parts = f"string_split({q(fmt.message_column)}, ' ')"
        for i, canon in enumerate(fmt.flow_columns.values(), start=1):
            add(canon, f"nullif({parts}[{i}], '-')")
        stamp = next((c for c in raw_types if c.lower() in ("@timestamp", "timestamp")), None)
        if stamp:
            selects.append(f"try_cast({q(stamp)} AS TIMESTAMP) AS log_time")
    else:
        by_canon = {canon: raw for raw, canon in fmt.flow_columns.items()}
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
