"""Route 53 Resolver query logs: JSON lines as Resolver writes them, or a CSV export."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import duckdb

from logsift.formats.base import Format, FormatInfo, FormatPlugin, mostly, squash
from logsift.formats.route53resolver.findings import build_timeline, run_rules
from logsift.formats.route53resolver.table import build_dns_table
from logsift.insights.cwlogs import QuerySpec, boolean, regex_escape
from logsift.loader import Sniff

if TYPE_CHECKING:
    from logsift.dataset import Dataset
    from logsift.insights.base import Finding

# CSV column names keyed by their squashed spelling (an Athena result, or a flattened
# export of the JSON records).
CSV_FIELDS: dict[str, str] = {
    "querytimestamp": "query_time",
    "querytime": "query_time",
    "timestamp": "query_time",
    "queryname": "query_name",
    "querytype": "query_type",
    "queryclass": "query_class",
    "rcode": "rcode",
    "responsecode": "rcode",
    "answers": "answers",
    "srcaddr": "srcaddr",
    "sourceaddress": "srcaddr",
    "srcport": "srcport",
    "transport": "transport",
    "srcidsinstance": "instance_id",
    "instanceid": "instance_id",
    "instance": "instance_id",
    "vpcid": "vpc_id",
    "region": "region",
    "accountid": "account_id",
    "firewallruleaction": "firewall_action",
    "firewallrulegroupid": "firewall_rule_group_id",
    "firewalldomainlistid": "firewall_domain_list_id",
}
REQUIRED = {"query_name", "rcode", "srcaddr"}

# The record's own JSON names, as CloudWatch Logs discovers them in the log group.
CW_DNS_FIELDS = {
    "query_time": "query_timestamp",
    "query_name": "query_name",
    "query_type": "query_type",
    "query_class": "query_class",
    "rcode": "rcode",
    "srcaddr": "srcaddr",
    "srcport": "srcport",
    "transport": "transport",
    "instance_id": "srcids.instance",
    "vpc_id": "vpc_id",
    "region": "region",
    "account_id": "account_id",
    "firewall_action": "firewall_rule_action",
    "firewall_rule_group_id": "firewall_rule_group_id",
    "firewall_domain_list_id": "firewall_domain_list_id",
}
DNS_DISPLAY = [
    "query_timestamp",
    "srcaddr",
    "query_name",
    "query_type",
    "rcode",
    "firewall_rule_action",
]
DNS_STATS = {
    "firewall_blocks": (
        "stats count(*) as queries by {query_name}, {srcaddr} | sort queries desc | limit 50"
    ),
    "nxdomain_burst": "stats count(*) as queries by {query_name} | sort queries desc | limit 100",
    "name_sweep": "stats count(*) as queries by {query_name} | sort queries desc | limit 100",
    "servfail": (
        "stats count(*) as queries by {query_name}, {srcaddr} | sort queries desc | limit 50"
    ),
    "errors": "stats count(*) as queries by {rcode}, {query_name} | sort queries desc | limit 50",
    "top_clients": "stats count(*) as queries by {query_name} | sort queries desc | limit 50",
}


def domain_field(op: str, value: object) -> str | None:
    """``domain`` is the registrable domain cut out of the query name."""
    if op not in ("=", "<>") or not isinstance(value, str):
        return None
    text = f"query_name like /(^|\\.){regex_escape(value)}\\.?$/"
    return text if op == "=" else f"not ({text})"


DNS_DERIVED = {
    "domain": domain_field,
    "is_error": boolean('rcode != "NOERROR"', 'rcode = "NOERROR"'),
    "blocked": boolean(
        'firewall_rule_action = "BLOCK"',
        '(not ispresent(firewall_rule_action) or firewall_rule_action != "BLOCK")',
    ),
    "answers": lambda op, v: None,
    "answer_count": lambda op, v: None,
    "name_length": lambda op, v: None,
    "labels": lambda op, v: None,
}


def looks_like_resolver_record(line: str) -> bool:
    try:
        rec = json.loads(line)
    except ValueError:
        return False
    return isinstance(rec, dict) and {"query_name", "rcode", "srcaddr"} <= set(rec)


class Route53ResolverPlugin(FormatPlugin):
    name = "route53_resolver"
    table = "dns"
    dash_means_missing = False

    def detect(self, sn: Sniff) -> FormatInfo | None:
        if sn.json_lines:
            if not mostly([looks_like_resolver_record(r[0]) for r in sn.rows if r]):
                return None
            return self.found(
                Format.ROUTE53_RESOLVER,
                "Route 53 Resolver query log",
                "JSON records with query_name, rcode and srcaddr",
                columns={sn.columns[0]: "line"},
                options={"source": "json", "line_column": sn.columns[0]},
            )
        if sn.has_header:
            mapped = {c: CSV_FIELDS[squash(c)] for c in sn.columns if squash(c) in CSV_FIELDS}
            if set(mapped.values()) >= REQUIRED and len(set(mapped.values())) >= 4:
                return self.found(
                    Format.ROUTE53_RESOLVER,
                    "Route 53 Resolver query log, CSV export",
                    f"header names {len(set(mapped.values()))} Resolver query log fields",
                    columns=mapped,
                    options={"source": "csv"},
                )
        return None

    def build_table(
        self, con: duckdb.DuckDBPyConnection, fmt: FormatInfo, source: str = "raw"
    ) -> list[str]:
        return build_dns_table(con, fmt, source, self.table)

    def findings(self, ds: Dataset) -> list[Finding]:
        return run_rules(ds)

    def timeline(self, ds: Dataset) -> dict[str, Any] | None:
        return build_timeline(ds)

    def query_spec(self, fmt: FormatInfo) -> QuerySpec | None:
        return QuerySpec(
            fields=dict(CW_DNS_FIELDS),
            time_columns=("query_time",),
            derived=DNS_DERIVED,
            display=DNS_DISPLAY,
            stats=DNS_STATS,
        )
