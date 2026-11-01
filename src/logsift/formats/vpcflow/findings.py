"""Rule-based findings for VPC Flow Logs.

Every rule is plain SQL over the canonical ``flow`` table built by ``table.py`` next door.
Thresholds are deliberately simple and written down next to each rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

import duckdb

from logsift.formats.vpcflow.table import ACK, SYN, protocol_name
from logsift.insights.base import (
    Finding,
    Severity,
    Table,
    fmt_bytes,
    fmt_ts,
    pick_bucket,
    sort_findings,
    utc,
)
from logsift.sql import lit, q

if TYPE_CHECKING:
    from logsift.dataset import Dataset

OK = "(log_status IS NULL OR log_status = 'OK')"


def ok_for(alias: str) -> str:
    return f"({alias}.log_status IS NULL OR {alias}.log_status = 'OK')"


PAIR_TIME_WINDOW = 120  # seconds between a request and its reply
SWEEP_WINDOW = 300  # seconds
SWEEP_PORTS = 15  # distinct destination ports from one source to one host
SWEEP_HOSTS = 15  # distinct destination hosts from one source
SYN_MIN_ATTEMPTS = 5
CLUSTER_MIN = 10

PRIVATE_RE = (
    r"^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|"
    r"100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|22[4-9]\.|2[3-5][0-9]\.|"
    r"fe80:|fd|fc|::1$)"
)


@dataclass
class Context:
    con: duckdb.DuckDBPyConnection
    columns: set[str]
    total: int
    ok_rows: int
    accepted: int
    rejected: int
    total_bytes: int
    start: datetime | None
    end: datetime | None

    def has(self, *cols: str) -> bool:
        return all(c in self.columns for c in cols)

    def sql(self, query: str, params: list[Any] | None = None) -> list[tuple[Any, ...]]:
        return self.con.execute(query, params or []).fetchall()

    def one(self, query: str) -> tuple[Any, ...]:
        row = self.con.execute(query).fetchone()
        return row if row is not None else ()

    def count(self, where: str) -> int:
        return int(self.one(f"SELECT count(*) FROM flow WHERE {where}")[0])

    def share(self, n: int) -> str:
        return f"{100.0 * n / self.ok_rows:.1f}%" if self.ok_rows else "0%"


def make_context(ds: Dataset) -> Context:
    con = ds.cursor()
    con.execute(
        "CREATE OR REPLACE MACRO is_private(ip) AS "
        f"ip IS NULL OR regexp_matches(ip, {lit(PRIVATE_RE)})"
    )
    columns = {c for c, _ in ds.columns}
    has_action = "action" in columns
    row = con.execute(
        f"""
        SELECT count(*),
               count(*) FILTER (WHERE {OK}),
               count(*) FILTER (WHERE {OK} AND {"action = 'ACCEPT'" if has_action else "false"}),
               count(*) FILTER (WHERE {OK} AND {"action = 'REJECT'" if has_action else "false"}),
               coalesce(sum(bytes), 0),
               min(start_ts), max(start_ts)
        FROM flow
        """
        if "bytes" in columns and "start_ts" in columns
        else f"""
        SELECT count(*),
               count(*) FILTER (WHERE {OK}),
               count(*) FILTER (WHERE {OK} AND {"action = 'ACCEPT'" if has_action else "false"}),
               count(*) FILTER (WHERE {OK} AND {"action = 'REJECT'" if has_action else "false"}),
               0, NULL, NULL
        FROM flow
        """
    ).fetchone() or (0, 0, 0, 0, 0, None, None)
    return Context(
        con,
        columns,
        int(row[0]),
        int(row[1]),
        int(row[2]),
        int(row[3]),
        int(row[4]),
        row[5],
        row[6],
    )


# --------------------------------------------------------------------------- rules


def rule_rejected(ctx: Context) -> list[Finding]:
    if not ctx.has("action"):
        return []
    n = ctx.rejected
    if n == 0:
        return [
            Finding(
                "rejected",
                "rejected_traffic",
                "No rejected traffic",
                Severity.INFO,
                "Every flow in this file was accepted.",
                "Nothing was blocked by a security group or network ACL in this window.",
                "",
                0,
                "action = 'REJECT'",
            )
        ]
    share = n / ctx.ok_rows if ctx.ok_rows else 0
    sev = Severity.HIGH if share >= 0.2 else Severity.MEDIUM if share >= 0.05 else Severity.LOW
    tables: list[Table] = []

    group = ["srcaddr", "dstaddr", "dstport", "protocol"]
    if ctx.has(*group):
        rows = ctx.sql(
            f"""
            SELECT srcaddr, dstaddr, dstport, protocol, count(*) AS flows,
                   coalesce(sum(packets), 0) AS packets
            FROM flow WHERE {OK} AND action = 'REJECT'
            GROUP BY ALL ORDER BY flows DESC LIMIT 15
            """
        )
        tables.append(
            Table(
                "By source, destination, port and protocol",
                ["source", "destination", "port", "protocol", "flows", "packets"],
                [(s, d, p, protocol_name(pr), f, pk) for s, d, p, pr, f, pk in rows],
            )
        )
    for col, title in (("interface_id", "By network interface"), ("subnet_id", "By subnet")):
        if ctx.has(col):
            rows = ctx.sql(
                f"""
                SELECT {q(col)}, count(*) AS flows,
                       round(100.0 * count(*) / sum(count(*)) OVER (), 1) AS share
                FROM flow WHERE {OK} AND action = 'REJECT' AND {q(col)} IS NOT NULL
                GROUP BY 1 ORDER BY flows DESC LIMIT 10
                """
            )
            tables.append(Table(title, [col, "rejected flows", "share of rejects (%)"], rows))

    return [
        Finding(
            "rejected",
            "rejected_traffic",
            f"{n:,} rejected flows ({ctx.share(n)} of traffic)",
            sev,
            f"{n:,} of {ctx.ok_rows:,} flows were rejected. The tables show where "
            "the rejects concentrate.",
            "A REJECT means a security group or a network ACL dropped the packets. "
            "Rejects clustered on one destination and port usually mean a missing allow "
            "rule. Rejects spread thinly over many ports from the internet are ordinary "
            "background noise.",
            "Check the security group and network ACL attached to the destination for the "
            "top rows in the first table.",
            n,
            f"{OK} AND action = 'REJECT'",
            tables,
        )
    ]


def rule_reject_clusters(ctx: Context) -> list[Finding]:
    """One destination and port rejected many times."""
    if not ctx.has("action", "dstaddr", "dstport", "protocol", "srcaddr"):
        return []
    # Judge "ever accepted" on the interface where the rejects happened, otherwise the
    # client side's own egress ACCEPT would hide a block at the destination.
    eni = "interface_id" if ctx.has("interface_id") else "NULL AS interface_id"
    eni_join = ", interface_id" if ctx.has("interface_id") else ""
    first_last = (
        "min(start_ts) AS first_seen, max(start_ts) AS last_seen"
        if ctx.has("start_ts")
        else "NULL AS first_seen, NULL AS last_seen"
    )
    rows = ctx.sql(
        f"""
        WITH rej AS (
            SELECT dstaddr, dstport, protocol, {eni}, count(*) AS flows,
                   count(DISTINCT srcaddr) AS sources,
                   count(DISTINCT srcaddr) FILTER (WHERE NOT is_private(srcaddr)) AS public_src,
                   {first_last}
            FROM flow WHERE {OK} AND action = 'REJECT' GROUP BY ALL
        ),
        acc AS (
            SELECT dstaddr, dstport, protocol, {eni}, count(*) AS accepted
            FROM flow WHERE {OK} AND action = 'ACCEPT' GROUP BY ALL
        )
        SELECT rej.dstaddr, rej.dstport, rej.protocol, rej.interface_id, flows, sources,
               public_src, first_seen, last_seen, coalesce(accepted, 0) AS accepted
        FROM rej LEFT JOIN acc USING (dstaddr, dstport, protocol{eni_join})
        WHERE flows >= {CLUSTER_MIN}
        ORDER BY flows DESC LIMIT 6
        """
    )
    findings: list[Finding] = []
    for i, row in enumerate(rows, 1):
        dst, port, proto, iface, flows, sources, public_src, first, last, accepted = row
        if dst is None or port is None:
            continue
        where = f"{OK} AND action = 'REJECT' AND dstaddr = {lit(dst)} AND dstport = {lit(port)}"
        if proto is not None:
            where += f" AND protocol = {lit(proto)}"
        if iface is not None:
            where += f" AND interface_id = {lit(iface)}"
        srcs = ctx.sql(
            f"SELECT srcaddr, count(*) AS flows FROM flow WHERE {where} "
            "GROUP BY 1 ORDER BY flows DESC LIMIT 10"
        )
        pname = protocol_name(proto)
        per_source = flows / sources if sources else 0
        noise = public_src == sources and per_source <= 2
        never = accepted == 0
        span = f"between {fmt_ts(first)} and {fmt_ts(last)}" if first else "in this file"
        if noise:
            sev = Severity.LOW
            summary = (
                f"{sources} different public addresses each tried {pname} port {port} on {dst} "
                f"once or twice {span}. Nothing was accepted."
            )
            cause = (
                "Unsolicited connection attempts from the internet. The security group or "
                "network ACL is doing its job; nothing to fix unless this port should be open."
            )
        elif never:
            sev = Severity.HIGH if flows >= 50 else Severity.MEDIUM
            who = "these sources" if sources > 1 else srcs[0][0]
            summary = (
                f"{sources} source{'s' if sources != 1 else ''} tried {pname} port {port} on "
                f"{dst} {span} and were rejected every time."
            )
            cause = (
                f"The security group or network ACL in front of {dst} has no rule allowing "
                f"{pname} port {port} from {who}. Nothing on this port was accepted at that "
                "interface, so this is a missing rule rather than an intermittent problem."
            )
        else:
            sev = Severity.MEDIUM if flows >= 50 else Severity.LOW
            summary = (
                f"{sources} source{'s' if sources != 1 else ''} were rejected on {pname} port "
                f"{port} of {dst} {span}, while {accepted:,} other flows to the same port were "
                "accepted."
            )
            cause = (
                f"Port {port} on {dst} is open to some sources but not to these. The allow "
                "rule probably lists specific CIDRs or security groups that do not cover them."
            )
        findings.append(
            Finding(
                f"reject-cluster-{i}",
                "rejected_cluster",
                f"{pname} port {port} to {dst} rejected {flows:,} times",
                sev,
                summary,
                "Repeated rejects on one destination and port are the clearest signal in flow "
                "logs. If the sources are hosts you expect to talk to this port, a rule is "
                "missing. If they are unknown public addresses, the rule set is doing its job.",
                cause,
                int(flows),
                where,
                [Table("Sources", ["source", "rejected flows"], srcs)],
            )
        )
    return findings


def rule_asymmetric(ctx: Context) -> list[Finding]:
    """ACCEPT one way and REJECT on the reply path, seen on the same interface."""
    needed = ["action", "srcaddr", "dstaddr", "srcport", "dstport", "protocol"]
    if not ctx.has(*needed):
        return []
    same_eni = "AND a.interface_id = b.interface_id" if ctx.has("interface_id") else ""
    time_ok = f"AND abs(a.start - b.start) <= {PAIR_TIME_WINDOW}" if ctx.has("start") else ""
    subnet = (
        ", any_value(a.subnet_id) AS subnet_id" if ctx.has("subnet_id") else ", NULL AS subnet_id"
    )
    eni = (
        ", any_value(a.interface_id) AS interface_id"
        if ctx.has("interface_id")
        else ", NULL AS interface_id"
    )
    rows = ctx.sql(
        f"""
        SELECT a.srcaddr AS client, a.dstaddr AS server, a.dstport AS port, a.protocol,
               count(DISTINCT a.row_no) AS requests, count(DISTINCT b.row_no) AS blocked_replies
               {eni}{subnet}
        FROM flow a JOIN flow b
          ON b.srcaddr = a.dstaddr AND b.dstaddr = a.srcaddr
         AND b.srcport = a.dstport AND b.dstport = a.srcport
         AND b.protocol = a.protocol {same_eni} {time_ok}
        WHERE a.action = 'ACCEPT' AND b.action = 'REJECT' AND {ok_for("a")} AND {ok_for("b")}
        GROUP BY ALL ORDER BY requests DESC LIMIT 20
        """
    )
    if not rows:
        return []
    total_pairs = sum(int(r[4]) for r in rows)
    filters: list[str] = []
    for client, server, port, proto, *_ in rows:
        fwd = f"(srcaddr = {lit(client)} AND dstaddr = {lit(server)} AND dstport = {lit(port)})"
        rev = f"(srcaddr = {lit(server)} AND dstaddr = {lit(client)} AND srcport = {lit(port)})"
        filters.append(f"(({fwd} OR {rev}) AND protocol = {lit(proto)})")
    where = "(" + " OR ".join(filters) + ")"
    servers = sorted({r[1] for r in rows})
    ports = [str(p) for p in dict.fromkeys(r[2] for r in rows)][:3]
    enis = sorted({r[6] for r in rows if r[6]})
    subnets = sorted({r[7] for r in rows if r[7]})
    place = (
        f"subnet {', '.join(subnets)}"
        if subnets
        else f"the subnet holding {', '.join(enis[:3])}"
        if enis
        else "the client subnet"
    )
    sev = Severity.HIGH if total_pairs >= 20 else Severity.MEDIUM
    table = Table(
        "Request accepted, reply rejected",
        [
            "client",
            "server",
            "port",
            "protocol",
            "requests",
            "blocked replies",
            "interface",
            "subnet",
        ],
        [(c, s, p, protocol_name(pr), rq, br, e, sn) for c, s, p, pr, rq, br, e, sn in rows],
    )
    return [
        Finding(
            "asymmetric",
            "asymmetric_flows",
            f"Return traffic blocked: {total_pairs:,} requests accepted but replies rejected",
            sev,
            f"Connections to {', '.join(servers[:3])} on port "
            f"{', '.join(ports)} leave fine (ACCEPT) but the reply coming "
            "back on the same interface is REJECTed. The client sees a hang or timeout.",
            "Security groups are stateful: once an outbound request is allowed, the reply is "
            "allowed automatically. Network ACLs are stateless: the reply has to match an "
            "explicit inbound rule for the ephemeral port range (1024-65535). An ACCEPT followed "
            "by a REJECT of the matching reply on the same interface therefore almost always "
            "points at a network ACL, not a security group.",
            f"The network ACL on {place} is missing an inbound allow for TCP/UDP ports 1024-65535 "
            f"from {', '.join(servers[:3])} (or the matching outbound rule on the server side).",
            ctx.count(where),
            where,
            [table],
        )
    ]


def rule_syn_no_synack(ctx: Context) -> list[Finding]:
    """TCP flows that only ever carried a SYN and got nothing back."""
    if not ctx.has("tcp_flags", "protocol", "srcaddr", "dstaddr", "srcport", "dstport"):
        return []
    time_ok = f"AND abs(a.start - b.start) <= {PAIR_TIME_WINDOW}" if ctx.has("start") else ""
    action_ok = "AND action = 'ACCEPT'" if ctx.has("action") else ""
    reject_excl = (
        "AND NOT EXISTS (SELECT 1 FROM flow r WHERE r.action = 'REJECT' "
        "AND r.dstaddr = a.dstaddr AND r.dstport = a.dstport AND r.protocol = 6)"
        if ctx.has("action")
        else ""
    )
    base = f"""
        FROM flow a
        WHERE {OK} AND protocol = 6 AND (tcp_flags & {SYN}) <> 0 AND (tcp_flags & {ACK}) = 0
          {action_ok}
          AND NOT EXISTS (
              SELECT 1 FROM flow b
              WHERE b.srcaddr = a.dstaddr AND b.dstaddr = a.srcaddr
                AND b.srcport = a.dstport AND b.dstport = a.srcport
                AND b.protocol = 6 AND (b.tcp_flags & {ACK}) <> 0 {time_ok}
          )
          {reject_excl}
    """
    rows = ctx.sql(
        f"""
        SELECT dstaddr, dstport, count(*) AS attempts, count(DISTINCT srcaddr) AS sources,
               min(start_ts) AS first_seen, max(start_ts) AS last_seen
        {base}
        GROUP BY ALL HAVING count(*) >= {SYN_MIN_ATTEMPTS}
        ORDER BY attempts DESC LIMIT 10
        """
        if ctx.has("start_ts")
        else f"""
        SELECT dstaddr, dstport, count(*) AS attempts, count(DISTINCT srcaddr) AS sources,
               NULL, NULL
        {base}
        GROUP BY ALL HAVING count(*) >= {SYN_MIN_ATTEMPTS}
        ORDER BY attempts DESC LIMIT 10
        """
    )
    if not rows:
        return []
    total = sum(int(r[2]) for r in rows)
    where_parts = [f"(dstaddr = {lit(d)} AND dstport = {lit(p)})" for d, p, *_ in rows]
    where = (
        f"{OK} AND protocol = 6 AND (tcp_flags & {SYN}) <> 0 AND (tcp_flags & {ACK}) = 0 "
        f"AND ({' OR '.join(where_parts)})"
    )
    top_dst, top_port = rows[0][0], rows[0][1]
    return [
        Finding(
            "syn-no-synack",
            "syn_without_synack",
            f"{total:,} connection attempts never completed (SYN without SYN-ACK)",
            Severity.MEDIUM,
            f"TCP flows to {top_dst} port {top_port}"
            + (
                f" and {len(rows) - 1} other target{'s' if len(rows) > 2 else ''}"
                if len(rows) > 1
                else ""
            )
            + " carried only a SYN and no reply with ACK was ever seen in the same window.",
            "The flow was allowed by the security group (it is not a REJECT), but the other "
            "side never answered. The TCP handshake did not complete, so the client saw a "
            "timeout rather than a refusal.",
            f"Nothing is listening on port {top_port} of {top_dst}, the host is down or "
            "unhealthy, or a firewall on the host itself (iptables, Windows Firewall) is "
            "silently dropping the packets.",
            total,
            where,
            [
                Table(
                    "Targets that never answered",
                    ["destination", "port", "attempts", "sources", "first seen", "last seen"],
                    rows,
                )
            ],
        )
    ]


def rule_top_talkers(ctx: Context) -> list[Finding]:
    if not ctx.has("srcaddr", "bytes"):
        return []
    rows = ctx.sql(
        f"""
        SELECT srcaddr, sum(bytes) AS bytes, coalesce(sum(packets), 0) AS packets,
               count(*) AS flows,
               round(100.0 * sum(bytes) / nullif(sum(sum(bytes)) OVER (), 0), 1) AS share
        FROM flow WHERE {OK} AND srcaddr IS NOT NULL
        GROUP BY 1 ORDER BY bytes DESC LIMIT 10
        """
    )
    if not rows:
        return []
    top_src, top_bytes, _, _, top_share = rows[0]
    tables = [
        Table(
            "Top sources by bytes",
            ["source", "bytes", "packets", "flows", "share of bytes (%)"],
            [(s, fmt_bytes(b), p, f, sh) for s, b, p, f, sh in rows],
        )
    ]
    if ctx.has("dstaddr", "dstport"):
        convo = ctx.sql(
            f"""
            SELECT srcaddr, dstaddr, dstport, sum(bytes) AS bytes, count(*) AS flows
            FROM flow WHERE {OK} GROUP BY ALL ORDER BY bytes DESC LIMIT 10
            """
        )
        tables.append(
            Table(
                "Top conversations by bytes",
                ["source", "destination", "port", "bytes", "flows"],
                [(s, d, p, fmt_bytes(b), f) for s, d, p, b, f in convo],
            )
        )
    if ctx.has("packets"):
        pk = ctx.sql(
            f"SELECT srcaddr, sum(packets) AS packets, count(*) FROM flow WHERE {OK} "
            "AND srcaddr IS NOT NULL GROUP BY 1 ORDER BY packets DESC LIMIT 10"
        )
        tables.append(Table("Top sources by packets", ["source", "packets", "flows"], pk))
    dominant = top_share is not None and float(top_share) >= 50
    sev = Severity.LOW if dominant else Severity.INFO
    return [
        Finding(
            "top-talkers",
            "top_talkers",
            f"Top talker: {top_src} sent {fmt_bytes(top_bytes)} ({top_share}% of all bytes)",
            sev,
            f"Total traffic in the file is {fmt_bytes(ctx.total_bytes)}. "
            + (
                f"One source accounts for {top_share}% of it, which is worth a look."
                if dominant
                else "Volume is spread across several sources."
            ),
            "Top talkers are a fact about volume, not a verdict. A backup job, a log shipper "
            "or a NAT instance can legitimately dominate. A workstation or a web server "
            "sending gigabytes to one public address is less usual.",
            f"Look at what {top_src} is and whether its destination in the conversations table "
            "is expected."
            if dominant
            else "",
            int(rows[0][3]),
            f"{OK} AND srcaddr = {lit(top_src)}",
            tables,
        )
    ]


def rule_public_ips(ctx: Context) -> list[Finding]:
    if not ctx.has("srcaddr", "dstaddr"):
        return []
    where = f"{OK} AND (NOT is_private(srcaddr) OR NOT is_private(dstaddr))"
    n = ctx.count(where)
    if n == 0:
        return [
            Finding(
                "public-ips",
                "public_traffic",
                "No traffic to or from public IP addresses",
                Severity.INFO,
                "Every flow is between private addresses.",
                "",
                "",
                0,
                where,
            )
        ]
    bytes_expr = "bytes" if ctx.has("bytes") else "0"
    rej_expr = "CASE WHEN action = 'REJECT' THEN 1 ELSE 0 END" if ctx.has("action") else "0"
    rows = ctx.sql(
        f"""
        SELECT ip, count(*) AS flows, sum(b) AS bytes, sum(rej) AS rejected
        FROM (
            SELECT CASE WHEN NOT is_private(srcaddr) THEN srcaddr ELSE dstaddr END AS ip,
                   {bytes_expr} AS b, {rej_expr} AS rej
            FROM flow WHERE {where}
        ) GROUP BY ip ORDER BY flows DESC LIMIT 15
        """
    )
    inbound = ctx.count(f"{where} AND NOT is_private(srcaddr) AND is_private(dstaddr)")
    outbound = ctx.count(f"{where} AND is_private(srcaddr) AND NOT is_private(dstaddr)")
    return [
        Finding(
            "public-ips",
            "public_traffic",
            f"{n:,} flows ({ctx.share(n)}) involve public IP addresses",
            Severity.INFO,
            f"{inbound:,} flows arrive from public addresses and {outbound:,} go out to them.",
            "Public addresses here are anything outside RFC 1918, link-local, loopback and "
            "carrier NAT space. Inbound public traffic to a private subnet means something "
            "is reachable through an internet gateway or load balancer.",
            "",
            n,
            where,
            [
                Table(
                    "Public addresses by flows",
                    ["public address", "flows", "bytes", "rejected"],
                    [(ip, f, fmt_bytes(b), r) for ip, f, b, r in rows],
                )
            ],
        )
    ]


def rule_sweeps(ctx: Context) -> list[Finding]:
    """One source touching many ports or many hosts inside a short window."""
    if not ctx.has("srcaddr", "dstaddr", "dstport", "srcport", "start"):
        return []
    findings: list[Finding] = []
    # Only count flows aimed at a service port (dstport below the source's ephemeral port),
    # so replies from a server to many client ports do not look like a sweep.
    aimed = f"{OK} AND dstport IS NOT NULL AND srcport IS NOT NULL AND dstport < srcport"
    action_cols = (
        ", count(*) FILTER (WHERE action = 'REJECT') AS rejected, "
        "count(*) FILTER (WHERE action = 'ACCEPT') AS accepted"
        if ctx.has("action")
        else ", 0 AS rejected, 0 AS accepted"
    )
    ports = ctx.sql(
        f"""
        WITH w AS (
            SELECT srcaddr, dstaddr, (start // {SWEEP_WINDOW}) * {SWEEP_WINDOW} AS win,
                   count(DISTINCT dstport) AS ports, count(*) AS flows,
                   min(dstport) AS lo, max(dstport) AS hi {action_cols}
            FROM flow WHERE {aimed}
            GROUP BY ALL HAVING count(DISTINCT dstport) >= {SWEEP_PORTS}
        )
        SELECT srcaddr, dstaddr, count(*) AS windows, max(ports) AS ports, sum(flows) AS flows,
               min(lo) AS lo, max(hi) AS hi, sum(rejected) AS rejected, sum(accepted) AS accepted,
               min(win) AS first_win, max(win) AS last_win
        FROM w GROUP BY ALL ORDER BY ports DESC, flows DESC LIMIT 10
        """
    )
    for i, row in enumerate(ports, 1):
        src, dst, windows, nports, flows, lo, hi, rejected, accepted, first_win, last_win = row
        t0, t1 = utc(int(first_win)), utc(int(last_win) + SWEEP_WINDOW)
        where = (
            f"{aimed} AND srcaddr = {lit(src)} AND dstaddr = {lit(dst)} "
            f"AND start >= {int(first_win)} AND start < {int(last_win) + SWEEP_WINDOW}"
        )
        when = (
            f"Between {fmt_ts(t0)} and {fmt_ts(t1)} UTC"
            if windows == 1
            else f"In {windows} separate five-minute windows between {fmt_ts(t0)} and "
            f"{fmt_ts(t1)} UTC"
        )
        findings.append(
            Finding(
                f"port-sweep-{i}",
                "port_sweep",
                f"{src} reached {nports} different ports on {dst} within 5 minutes",
                Severity.MEDIUM,
                f"{when}, {src} sent {flows:,} flows to ports {lo} through {hi} on {dst}: "
                f"{rejected:,} rejected, {accepted:,} accepted.",
                "This is presented as a fact to look at, not as a verdict. Touching many "
                "ports on one host in a short window is what a port scan looks like, but a "
                "vulnerability scanner you run yourself, a monitoring agent or a misconfigured "
                "client can produce the same pattern.",
                f"If {src} is not a scanner you know about, check which ports were accepted and "
                "whether the host should be reachable from that address at all.",
                int(ctx.count(where)),
                where,
                [
                    Table(
                        "Ports touched",
                        [
                            "source",
                            "target",
                            "first window",
                            "windows",
                            "most ports in one window",
                            "flows",
                            "rejected",
                            "accepted",
                        ],
                        [(src, dst, t0, windows, nports, flows, rejected, accepted)],
                    )
                ],
            )
        )
    hosts = ctx.sql(
        f"""
        WITH w AS (
            SELECT srcaddr, (start // {SWEEP_WINDOW}) * {SWEEP_WINDOW} AS win,
                   count(DISTINCT dstaddr) AS hosts, count(*) AS flows,
                   count(DISTINCT dstport) AS ports {action_cols}
            FROM flow WHERE {aimed}
            GROUP BY ALL HAVING count(DISTINCT dstaddr) >= {SWEEP_HOSTS}
        )
        SELECT srcaddr, count(*) AS windows, max(hosts) AS hosts, sum(flows) AS flows,
               max(ports) AS ports, sum(rejected) AS rejected, sum(accepted) AS accepted,
               min(win) AS first_win, max(win) AS last_win
        FROM w GROUP BY ALL ORDER BY hosts DESC, flows DESC LIMIT 10
        """
    )
    for i, row in enumerate(hosts, 1):
        src, windows, nhosts, flows, nports, rejected, accepted, first_win, last_win = row
        t0 = utc(int(first_win))
        where = (
            f"{aimed} AND srcaddr = {lit(src)} AND start >= {int(first_win)} "
            f"AND start < {int(last_win) + SWEEP_WINDOW}"
        )
        findings.append(
            Finding(
                f"host-sweep-{i}",
                "host_sweep",
                f"{src} reached {nhosts} different hosts within 5 minutes",
                Severity.MEDIUM,
                f"Starting {fmt_ts(t0)} UTC{'' if windows == 1 else f' and in {windows} windows'}, "
                f"{src} sent {flows:,} flows to {nhosts} hosts on {nports} "
                f"port{'s' if nports != 1 else ''}: {rejected:,} rejected, {accepted:,} accepted.",
                "One source talking to many hosts in a short burst is what host discovery "
                "looks like. It is also what a load balancer health check, a configuration "
                "management server or a backup server looks like, so treat it as a fact to "
                "check.",
                f"Confirm what {src} is. If it is unexpected and the flows were accepted, review "
                "the security groups that let it in.",
                int(ctx.count(where)),
                where,
                [
                    Table(
                        "Hosts touched",
                        [
                            "source",
                            "first window",
                            "windows",
                            "most hosts in one window",
                            "flows",
                            "ports",
                            "rejected",
                            "accepted",
                        ],
                        [(src, t0, windows, nhosts, flows, nports, rejected, accepted)],
                    )
                ],
            )
        )
    return findings


def rule_log_status(ctx: Context) -> list[Finding]:
    if not ctx.has("log_status"):
        return []
    nodata = ctx.count("log_status = 'NODATA'")
    skip = ctx.count("log_status = 'SKIPDATA'")
    findings: list[Finding] = []
    if skip:
        by_eni = (
            ctx.sql(
                "SELECT interface_id, count(*) FROM flow WHERE log_status = 'SKIPDATA' "
                "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
            )
            if ctx.has("interface_id")
            else []
        )
        share = skip / ctx.total if ctx.total else 0
        findings.append(
            Finding(
                "skipdata",
                "skipdata",
                f"{skip:,} SKIPDATA records: some flows were not captured",
                Severity.MEDIUM if share >= 0.01 else Severity.LOW,
                f"{skip:,} records say the flow log service skipped data in that window.",
                "SKIPDATA means records were dropped because of an internal capacity problem or "
                "error in the flow log service. Any analysis of those windows is incomplete, so "
                "an absence of rejects there does not prove there were none.",
                "Usually a burst of traffic above what the capture could handle. Nothing to fix "
                "in your network, but treat those windows as having gaps.",
                skip,
                "log_status = 'SKIPDATA'",
                [Table("By interface", ["interface", "records"], by_eni)] if by_eni else [],
            )
        )
    if nodata:
        by_eni = (
            ctx.sql(
                "SELECT interface_id, count(*) FROM flow WHERE log_status = 'NODATA' "
                "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
            )
            if ctx.has("interface_id")
            else []
        )
        findings.append(
            Finding(
                "nodata",
                "nodata",
                f"{nodata:,} NODATA records from idle interfaces",
                Severity.INFO,
                f"{nodata:,} records say an interface had no traffic at all in that window.",
                "NODATA is normal for an interface with nothing happening. It only matters if "
                "the interface is one you expect to be busy.",
                "",
                nodata,
                "log_status = 'NODATA'",
                [Table("By interface", ["interface", "records"], by_eni)] if by_eni else [],
            )
        )
    return findings


def rule_time_gaps(ctx: Context) -> list[Finding]:
    if not ctx.has("start_ts") or ctx.start is None or ctx.end is None:
        return []
    rows = ctx.sql(
        """
        WITH t AS (SELECT DISTINCT date_trunc('minute', start_ts) AS m FROM flow
                   WHERE start_ts IS NOT NULL),
        d AS (SELECT m, lead(m) OVER (ORDER BY m) AS nxt FROM t)
        SELECT m, nxt, epoch(nxt - m) AS secs FROM d WHERE nxt IS NOT NULL
        """
    )
    if not rows:
        return []
    secs = sorted(int(r[2]) for r in rows)
    typical = secs[len(secs) // 2]
    threshold = max(300, 5 * typical)
    gaps = [(m, nxt, s) for m, nxt, s in rows if int(s) > threshold]
    span = (ctx.end - ctx.start).total_seconds() or 1
    missing = sum(int(s) for _, _, s in gaps)
    where = (
        "("
        + " OR ".join(
            f"(start_ts >= {lit(m.strftime('%Y-%m-%d %H:%M:%S'))} "
            f"AND start_ts <= {lit(n.strftime('%Y-%m-%d %H:%M:%S'))})"
            for m, n, _ in gaps[:20]
        )
        + ")"
        if gaps
        else "FALSE"
    )
    header = (
        f"Records run from {fmt_ts(ctx.start)} to {fmt_ts(ctx.end)} UTC with a record roughly "
        f"every {typical} seconds."
    )
    if not gaps:
        return [
            Finding(
                "time-range",
                "time_gaps",
                "Continuous time range, no gaps",
                Severity.INFO,
                header + " There are no gaps larger than the normal interval.",
                "",
                "",
                0,
                where,
            )
        ]
    sev = Severity.MEDIUM if missing / span >= 0.1 else Severity.LOW
    return [
        Finding(
            "time-gaps",
            "time_gaps",
            f"{len(gaps)} gap{'s' if len(gaps) != 1 else ''} in the time range "
            f"({missing / 60:.0f} minutes with no records)",
            sev,
            header + f" {len(gaps)} stretch{'es' if len(gaps) != 1 else ''} had no records at all.",
            "A gap means no interface produced a record for that time. Either nothing happened "
            "(unlikely on a busy VPC), the flow log was turned off or recreated, the export "
            "query missed a window, or delivery to the log group failed.",
            "Check the flow log's creation time and the IAM role used for delivery. If this is "
            "a CloudWatch export, check the query time range.",
            ctx.count(where),
            where,
            [
                Table(
                    "Gaps",
                    ["last record before", "first record after", "minutes missing"],
                    [(m, n, round(int(s) / 60)) for m, n, s in gaps[:20]],
                )
            ],
        )
    ]


def timeline(ctx: Context) -> dict[str, Any] | None:
    """Accepted against rejected flows per time bucket."""
    if not ctx.has("start") or ctx.start is None or ctx.end is None:
        return None
    span = (ctx.end - ctx.start).total_seconds()
    name, secs = pick_bucket(span)
    rows = ctx.sql(
        f"""
        SELECT (start // {secs}) * {secs} AS b,
               count(*) FILTER (WHERE action = 'ACCEPT') AS accepted,
               count(*) FILTER (WHERE action = 'REJECT') AS rejected
        FROM flow WHERE {OK} AND start IS NOT NULL GROUP BY b ORDER BY b
        """
        if ctx.has("action")
        else f"""
        SELECT (start // {secs}) * {secs} AS b, count(*) AS accepted, 0 AS rejected
        FROM flow WHERE {OK} AND start IS NOT NULL GROUP BY b ORDER BY b
        """
    )
    if not rows:
        return None
    first, last = int(rows[0][0]), int(rows[-1][0])
    by_bucket = {int(b): (int(a), int(r)) for b, a, r in rows}
    labels: list[str] = []
    accepted: list[int] = []
    rejected: list[int] = []
    b = first
    while b <= last:
        a, r = by_bucket.get(b, (0, 0))
        labels.append(utc(b).strftime("%H:%M" if span < 86400 else "%m-%d %H:%M"))
        accepted.append(a)
        rejected.append(r)
        b += secs
    return {
        "bucket": name,
        "labels": labels,
        "series": {"accepted": accepted, "rejected": rejected},
    }


RULES = [
    rule_asymmetric,
    rule_reject_clusters,
    rule_rejected,
    rule_syn_no_synack,
    rule_sweeps,
    rule_top_talkers,
    rule_public_ips,
    rule_log_status,
    rule_time_gaps,
]


def run_rules(ds: Dataset) -> list[Finding]:
    ctx = make_context(ds)
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(ctx))
    return sort_findings(findings)


def build_timeline(ds: Dataset) -> dict[str, Any] | None:
    return timeline(make_context(ds))
