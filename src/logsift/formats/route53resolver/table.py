"""Build a typed ``dns`` table from a Route 53 Resolver query log.

The log arrives either as JSON lines (one query per object, the way Resolver writes it to
CloudWatch Logs, S3 or Firehose) or as a CSV export with one column per field. Both end
up with the same columns: the documented fields under their own names, the answers
flattened to one text column, and what the rules want: the registrable domain of the
query name, its length and label count, and flags for a failed or a blocked query.
"""

from __future__ import annotations

import duckdb

from logsift.formats.base import Format, FormatInfo
from logsift.sql import q

# Canonical columns, in display order.
DNS_ORDER = [
    "query_time",
    "srcaddr",
    "query_name",
    "query_type",
    "rcode",
    "answers",
    "answer_count",
    "domain",
    "is_error",
    "blocked",
    "firewall_action",
    "transport",
    "srcport",
    "instance_id",
    "name_length",
    "labels",
    "query_class",
    "vpc_id",
    "region",
    "account_id",
    "firewall_rule_group_id",
    "firewall_domain_list_id",
]
DNS_TYPES = {"query_time": "TIMESTAMP", "srcport": "INTEGER", "answer_count": "INTEGER"}

# JSON paths for the documented record fields.
JSON_FIELDS: dict[str, str] = {
    "query_time": "$.query_timestamp",
    "query_name": "$.query_name",
    "query_type": "$.query_type",
    "query_class": "$.query_class",
    "rcode": "$.rcode",
    "srcaddr": "$.srcaddr",
    "srcport": "$.srcport",
    "transport": "$.transport",
    "instance_id": "$.srcids.instance",
    "vpc_id": "$.vpc_id",
    "region": "$.region",
    "account_id": "$.account_id",
    "firewall_action": "$.firewall_rule_action",
    "firewall_rule_group_id": "$.firewall_rule_group_id",
    "firewall_domain_list_id": "$.firewall_domain_list_id",
}

# Second-level labels under which the registrable domain has three labels (co.uk and
# friends), so "shop.example.co.uk" groups as example.co.uk and not co.uk.
SECOND_LEVEL = ("co", "com", "org", "net", "ac", "gov", "edu", "ne", "or")


def domain_expr(name: str) -> str:
    """SQL for the registrable domain of a query name (trailing dot removed)."""
    bare = f"rtrim({name}, '.')"
    parts = f"string_split({bare}, '.')"
    n = f"len({parts})"
    last2 = f"array_to_string({parts}[-2:], '.')"
    last3 = f"array_to_string({parts}[-3:], '.')"
    seconds = ", ".join(f"'{s}'" for s in SECOND_LEVEL)
    return (
        f"CASE WHEN {bare} LIKE '%.in-addr.arpa' THEN 'in-addr.arpa' "
        f"WHEN {bare} LIKE '%.ip6.arpa' THEN 'ip6.arpa' "
        f"WHEN {n} <= 2 THEN {bare} "
        f"WHEN len({parts}[-1]) = 2 AND {parts}[-2] IN ({seconds}) AND {n} >= 3 THEN {last3} "
        f"ELSE {last2} END"
    )


def answers_expr(col: str) -> str:
    """The answers as one space-separated text: a JSON array of records, or as given."""
    return (
        f"CASE WHEN {col} IS NULL THEN NULL "
        f"WHEN ltrim({col}) LIKE '[%' THEN array_to_string("
        f"CAST(json_extract_string({col}, '$[*].Rdata') AS VARCHAR[]), ' ') "
        f"ELSE {col} END"
    )


def build_dns_table(
    con: duckdb.DuckDBPyConnection,
    fmt: FormatInfo,
    source: str = "raw",
    target: str = "dns",
) -> list[str]:
    """Create ``target`` with the canonical columns and types. Returns its columns."""
    if fmt.kind != Format.ROUTE53_RESOLVER:
        raise ValueError("not a Route 53 Resolver query log")
    parts: list[str] = []
    present: set[str] = set()

    def add(name: str, expr: str) -> None:
        parts.append(f"try_cast({expr} AS {DNS_TYPES.get(name, 'VARCHAR')}) AS {q(name)}")
        present.add(name)

    if fmt.options.get("source") == "json":
        line = q(fmt.options.get("line_column", "line"))
        for name, path in JSON_FIELDS.items():
            add(name, f"{line}->>'{path}'")
        add(
            "answers",
            f"array_to_string(CAST(json_extract_string({line}, '$.answers[*].Rdata') "
            f"AS VARCHAR[]), ' ')",
        )
        add("answer_count", f"json_array_length({line}->'$.answers')")
    else:
        for raw, name in fmt.columns.items():
            if name == "answers":
                add("answers", answers_expr(f"cast({q(raw)} AS VARCHAR)"))
            else:
                add(name, f"cast({q(raw)} AS VARCHAR)")
        if "answers" in present:
            add(
                "answer_count",
                f"CASE WHEN {q('answers')} IS NULL OR {q('answers')} = '' THEN 0 "
                f"ELSE len(string_split({q('answers')}, ' ')) END",
            )
    if "answer_count" in present and fmt.options.get("source") != "json":
        # answer_count refers to the derived answers column, so it goes in a second level.
        inner = ", ".join(p for p in parts if ' AS "answer_count"' not in p)
        count = next(p for p in parts if ' AS "answer_count"' in p)
        sql = f"SELECT *, {count} FROM (SELECT {inner} FROM {q(source)})"
    else:
        sql = f"SELECT {', '.join(parts)} FROM {q(source)}"

    derived = []
    if "query_name" in present:
        derived += [
            ("domain", domain_expr(q("query_name"))),
            ("name_length", f"len(rtrim({q('query_name')}, '.'))"),
            ("labels", f"len(string_split(rtrim({q('query_name')}, '.'), '.'))"),
        ]
    if "rcode" in present:
        derived.append(("is_error", f"coalesce({q('rcode')} <> 'NOERROR', false)"))
    if "firewall_action" in present:
        derived.append(("blocked", f"coalesce({q('firewall_action')} = 'BLOCK', false)"))
    else:
        derived.append(("blocked", "false"))
    extra = ", ".join(f"{expr} AS {q(name)}" for name, expr in derived)
    sql = f"SELECT *, {extra} FROM ({sql})"
    present |= {name for name, _ in derived}

    ordered = [c for c in DNS_ORDER if c in present] + sorted(present - set(DNS_ORDER))
    cols = ", ".join(q(c) for c in ordered)
    con.execute(f"DROP TABLE IF EXISTS {q(target)}")
    con.execute(
        f"CREATE TABLE {q(target)} AS SELECT row_number() OVER () AS row_no, {cols} FROM ({sql})"
    )
    return [r[0] for r in con.execute(f"DESCRIBE {q(target)}").fetchall()]
