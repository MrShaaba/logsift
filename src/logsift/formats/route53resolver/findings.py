"""Rule-based findings for Route 53 Resolver query logs.

Every rule is plain SQL over the ``dns`` table built by ``table.py`` next door. One row is
one DNS query from one host in the VPC, so the rules talk about clients, names, domains
and response codes. Thresholds are simple and written next to each rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

import duckdb

from logsift.insights.base import (
    Finding,
    Severity,
    Table,
    fmt_ts,
    pick_bucket,
    plural,
    sort_findings,
    span,
    ts,
)
from logsift.sql import lit

if TYPE_CHECKING:
    from logsift.dataset import Dataset

BLOCK_HIGH = 50  # blocked queries before the firewall finding is high
BURST_BUCKET = 300  # seconds; NXDOMAIN answers are counted per client per bucket
BURST_MIN = 100  # NXDOMAIN answers in one bucket that make a burst
BURST_HIGH_NAMES = 500  # distinct names in a burst that make it high
SWEEP_MIN_NAMES = 300  # distinct names one client asked for
SWEEP_RATIO = 5  # ... compared with the median client
TUNNEL_MIN = 100  # long-labelled queries under one domain from one client
TUNNEL_LABEL = 30  # characters in the left-most label, on average
TUNNEL_UNIQUE = 0.9  # share of those queries that were for a name never seen before
SERVFAIL_MIN = 20  # SERVFAIL answers for one domain
SERVFAIL_GAP = 2  # minutes between SERVFAIL minutes that still count as one outage
ERROR_MEDIUM_SHARE = 0.10
MAX_PER_RULE = 5
SAMPLE_NAMES = 15


@dataclass
class Context:
    con: duckdb.DuckDBPyConnection
    columns: set[str]
    total: int
    start: datetime | None
    end: datetime | None
    errors: int
    blocked: int

    def has(self, *cols: str) -> bool:
        return all(c in self.columns for c in cols)

    def sql(self, query: str) -> list[tuple[Any, ...]]:
        return self.con.execute(query).fetchall()

    def one(self, query: str) -> tuple[Any, ...]:
        row = self.con.execute(query).fetchone()
        return row if row is not None else ()

    def count(self, where: str) -> int:
        return int(self.one(f"SELECT count(*) FROM dns WHERE {where}")[0])

    def share(self, n: int, of: int | None = None) -> str:
        of = self.total if of is None else of
        return f"{100.0 * n / of:.1f}%" if of else "0%"


def make_context(ds: Dataset) -> Context:
    con = ds.cursor()
    columns = {c for c, _ in ds.columns}
    time = "min(query_time), max(query_time)" if "query_time" in columns else "NULL, NULL"
    errors = "count(*) FILTER (WHERE is_error)" if "is_error" in columns else "0"
    blocked = "count(*) FILTER (WHERE blocked)" if "blocked" in columns else "0"
    row = con.execute(f"SELECT count(*), {time}, {errors}, {blocked} FROM dns").fetchone()
    total, start, end, n_err, n_blocked = row or (0, None, None, 0, 0)
    return Context(con, columns, int(total), start, end, int(n_err), int(n_blocked))


def listing(items: list[Any], limit: int = 4) -> str:
    items = [str(i) for i in items]
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"


def minutes_between(first: datetime | None, last: datetime | None) -> int:
    if not first or not last:
        return 1
    return max(1, int((last - first).total_seconds() // 60) + 1)


def window(first: datetime, last: datetime) -> str:
    """A WHERE fragment for [first, last + 1 minute)."""
    return f"query_time >= {ts(first)} AND query_time < {ts(last + timedelta(minutes=1))}"


# --------------------------------------------------------------------- firewall


def rule_firewall_blocks(ctx: Context) -> list[Finding]:
    """Queries DNS Firewall refused: something asked for a name on a block list."""
    if not ctx.has("blocked") or ctx.blocked == 0:
        return []
    n = ctx.blocked
    by_name = ctx.sql(
        "SELECT query_name, count(*), count(DISTINCT srcaddr), min(query_time), max(query_time) "
        "FROM dns WHERE blocked GROUP BY 1 ORDER BY 2 DESC LIMIT 20"
    )
    by_client = ctx.sql(
        "SELECT srcaddr, any_value(instance_id), count(*), count(DISTINCT query_name), "
        "min(query_time), max(query_time) FROM dns WHERE blocked GROUP BY 1 ORDER BY 3 DESC "
        "LIMIT 10"
    )
    by_domain = ctx.sql(
        "SELECT domain, count(*), count(DISTINCT query_name) FROM dns WHERE blocked "
        "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
    )
    per_bucket = ctx.sql(
        "SELECT date_trunc('hour', query_time), count(*) FROM dns WHERE blocked "
        "GROUP BY 1 ORDER BY 1"
    )
    clients = [r[0] for r in by_client]
    domains = [r[0] for r in by_domain]
    first = min(r[3] for r in by_name)
    last = max(r[4] for r in by_name)
    minutes = minutes_between(first, last)
    steady = n >= 20 and minutes >= 30 and n / minutes >= 0.5
    top_ip, top_instance, top_n, _, _, _ = by_client[0]
    who = f"{top_ip}" + (f" ({top_instance})" if top_instance else "")
    if len(clients) == 1:
        source = f"all from {who}"
    else:
        source = f"from {plural(len(clients), 'host')}, {top_n:,} of them from {who}"
    rhythm = (
        f" The queries came steadily, about {n / minutes:.1f} a minute for {minutes} minutes, "
        "which is a process on a timer rather than a person."
        if steady
        else ""
    )
    findings = [
        Finding(
            "firewall-blocks",
            "firewall_blocks",
            f"DNS Firewall blocked {n:,} queries for {plural(len(by_name), 'name')} under "
            f"{listing(domains, 2)}",
            Severity.HIGH if n >= BLOCK_HIGH else Severity.MEDIUM,
            f"Between {fmt_ts(first)} and {fmt_ts(last)} the resolver refused {n:,} queries "
            f"({ctx.share(n)} of all queries) because the name is on a DNS Firewall block list: "
            f"{listing([r[0] for r in by_name], 3)}, {source}.{rhythm}",
            "A BLOCK action means a rule group attached to this VPC matched the query name "
            "against a domain list and answered it without resolving it. The host never "
            "reached the name, but it did try, which is the part worth knowing: block lists "
            "hold malware controllers, trackers and names a policy forbids.",
            f"Something on {who} wants to talk to {listing(domains, 2)} and keeps trying. Find "
            "the process behind the queries (on Linux, `ss -p` while a query fires, or "
            "resolver logs on the host); a browser extension, an agent phoning home or a "
            "cron job are the usual answers, malware the one to rule out first.",
            n,
            "blocked",
            [
                Table(
                    "Blocked names",
                    ["name", "queries", "hosts", "first", "last"],
                    by_name,
                ),
                Table(
                    "By host",
                    ["address", "instance", "queries", "names", "first", "last"],
                    by_client,
                ),
                Table("By domain", ["domain", "queries", "names"], by_domain),
                Table("Per hour", ["hour", "queries"], per_bucket),
            ],
        )
    ]
    return findings


# --------------------------------------------------------------- NXDOMAIN bursts


def rule_nxdomain_bursts(ctx: Context) -> tuple[list[Finding], set[str]]:
    """Clients that got NXDOMAIN hundreds of times in a few minutes, and what they asked."""
    if not ctx.has("rcode", "srcaddr", "query_time"):
        return [], set()
    base = "rcode = 'NXDOMAIN' AND NOT blocked"
    buckets = ctx.sql(
        f"SELECT srcaddr, to_timestamp(floor(epoch(query_time) / {BURST_BUCKET}) * "
        f"{BURST_BUCKET}) AT TIME ZONE 'UTC' AS b, count(*) FROM dns WHERE {base} "
        f"GROUP BY 1, 2 HAVING count(*) >= {BURST_MIN} ORDER BY 1, 2"
    )
    if not buckets:
        return [], set()
    # Merge a client's consecutive hot buckets into one burst.
    bursts: list[tuple[str, datetime, datetime]] = []
    for ip, bucket, _ in buckets:
        if (
            bursts
            and bursts[-1][0] == ip
            and bucket - bursts[-1][2] <= timedelta(seconds=BURST_BUCKET)
        ):
            bursts[-1] = (ip, bursts[-1][1], bucket)
        else:
            bursts.append((ip, bucket, bucket))
    findings: list[Finding] = []
    reported: set[str] = set()
    for ip, b_first, b_last in bursts[: MAX_PER_RULE * 2]:
        where = (
            f"{base} AND srcaddr = {lit(ip)} AND query_time >= {ts(b_first)} AND "
            f"query_time < {ts(b_last + timedelta(seconds=BURST_BUCKET))}"
        )
        n, names, first, last, instance, mean_len = ctx.one(
            "SELECT count(*), count(DISTINCT query_name), min(query_time), max(query_time), "
            f"any_value(instance_id), avg(name_length) FROM dns WHERE {where}"
        )
        by_domain = ctx.sql(
            f"SELECT domain, count(*), count(DISTINCT query_name) FROM dns WHERE {where} "
            "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        )
        sample = ctx.sql(
            f"SELECT query_time, query_name, query_type FROM dns WHERE {where} "
            f"ORDER BY query_time LIMIT {SAMPLE_NAMES}"
        )
        per_minute = ctx.sql(
            f"SELECT date_trunc('minute', query_time), count(*), count(DISTINCT query_name) "
            f"FROM dns WHERE {where} GROUP BY 1 ORDER BY 1"
        )
        all_from_client = ctx.count(
            f"srcaddr = {lit(ip)} AND query_time >= {ts(first)} AND query_time <= {ts(last)}"
        )
        by_tld = ctx.sql(
            f"SELECT '.' || string_split(rtrim(query_name, '.'), '.')[-1], count(*) FROM dns "
            f"WHERE {where} GROUP BY 1 ORDER BY 2 DESC LIMIT 6"
        )
        minutes = minutes_between(first, last)
        zones = [r[0] for r in by_domain if r[0] not in ("in-addr.arpa", "ip6.arpa")]
        one_zone = sum(r[1] for r in by_domain[:2]) / n >= 0.8
        ptr = ctx.count(f"{where} AND query_type = 'PTR'")
        who = f"{ip}" + (f" ({instance})" if instance else "")
        if one_zone:
            top_domain = zones[0] if zones else by_domain[0][0]
            shape = (
                f"Nearly all of the names were under {top_domain}"
                + (f", and {ptr:,} were reverse lookups" if ptr else "")
                + ": the host was walking through a zone, asking for names in turn to see "
                "which exist."
            )
            cause = (
                f"Someone or something on {who} is enumerating {top_domain}: a scanner, an "
                "inventory script, or a person with a shell mapping the network. If nobody "
                "owns it, treat the host as compromised and look at what else it did in the "
                "flow logs around this time."
            )
        else:
            shape = (
                f"The names were spread across {listing([r[0] for r in by_tld], 3)} with "
                f"random-looking labels about {mean_len:.0f} characters long, and almost every "
                "one was new: what a domain "
                "generation algorithm produces while malware hunts for a controller that is "
                "registered under one of thousands of possible names."
            )
            cause = (
                f"Malware on {who} is the likely answer; a misconfigured search path or a "
                "fuzzing test are the benign ones. Isolate the host, check the few names that "
                "did resolve (they are the controllers that exist), and look for outbound "
                "connections to those addresses in the flow logs."
            )
        severity = Severity.HIGH if names >= BURST_HIGH_NAMES else Severity.MEDIUM
        findings.append(
            Finding(
                f"nxdomain-burst-{len(findings) + 1}",
                "nxdomain_burst",
                f"{ip} got NXDOMAIN for {plural(int(names), 'different name')} in "
                f"{plural(minutes, 'minute')}",
                severity,
                f"Between {fmt_ts(first)} and {fmt_ts(last)}, {who} sent {n:,} queries that "
                f"came back NXDOMAIN, for {names:,} distinct names ({ctx.share(n, all_from_client)}"
                f" of everything the host asked in that window). {shape}",
                "NXDOMAIN means the name does not exist. A normal host gets a handful a day, "
                "from typos and stale configuration. Hundreds in minutes from one host means "
                "the host is generating names, not looking up ones it was given.",
                cause,
                int(n),
                where,
                [
                    Table("First names asked", ["time", "name", "type"], sample),
                    Table("By top-level domain", ["tld", "queries"], by_tld),
                    Table("By domain", ["domain", "queries", "names"], by_domain),
                    Table("Per minute", ["minute", "queries", "names"], per_minute),
                ],
            )
        )
        reported.add(ip)
    return findings[:MAX_PER_RULE], reported


# ------------------------------------------------------------------- name sweeps


def rule_name_sweep(ctx: Context, skip: set[str]) -> list[Finding]:
    """One client asking for far more different names than any other."""
    if not ctx.has("srcaddr", "query_name"):
        return []
    per_client = ctx.sql(
        "SELECT srcaddr, count(DISTINCT query_name), count(*), any_value(instance_id), "
        "min(query_time), max(query_time) FROM dns WHERE NOT blocked GROUP BY 1 ORDER BY 2 DESC"
    )
    if len(per_client) < 2:
        return []
    counts = sorted(r[1] for r in per_client)
    median = counts[len(counts) // 2]
    findings: list[Finding] = []
    for ip, names, n, instance, first, last in per_client:
        if ip in skip or names < SWEEP_MIN_NAMES or names < SWEEP_RATIO * max(1, median):
            continue
        where = f"srcaddr = {lit(ip)} AND NOT blocked"
        by_domain = ctx.sql(
            f"SELECT domain, count(DISTINCT query_name), count(*), "
            f"count(*) FILTER (WHERE rcode = 'NXDOMAIN') FROM dns WHERE {where} "
            "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        )
        sample = ctx.sql(
            f"SELECT query_time, query_name, query_type, rcode FROM dns WHERE {where} "
            f"ORDER BY query_time LIMIT {SAMPLE_NAMES}"
        )
        per_minute = ctx.sql(
            f"SELECT date_trunc('minute', query_time), count(*), count(DISTINCT query_name) "
            f"FROM dns WHERE {where} GROUP BY 1 ORDER BY 1"
        )
        who = f"{ip}" + (f" ({instance})" if instance else "")
        findings.append(
            Finding(
                f"name-sweep-{len(findings) + 1}",
                "name_sweep",
                f"{ip} looked up {names:,} different names; the typical host asked for {median:,}",
                Severity.MEDIUM,
                f"Between {fmt_ts(first)} and {fmt_ts(last)}, {who} asked for {names:,} "
                f"distinct names in {n:,} queries, mostly under "
                f"{listing([r[0] for r in by_domain], 3)}. The median host in this file asked "
                f"for {median:,} names in the same period.",
                "Servers ask for the same few dozen names over and over: their dependencies. "
                "A host that asks for hundreds of different names is either a resolver or "
                "proxy for others, or is discovering names rather than using them.",
                f"If {who} is a DNS forwarder, a proxy or a crawler this is its job. Otherwise "
                "someone is enumerating the names it can see: check who was logged in and "
                "what the host connected to afterwards.",
                int(n),
                where,
                [
                    Table("By domain", ["domain", "names", "queries", "NXDOMAIN"], by_domain),
                    Table("First names asked", ["time", "name", "type", "rcode"], sample),
                    Table("Per minute", ["minute", "queries", "names"], per_minute),
                ],
            )
        )
        if len(findings) == MAX_PER_RULE:
            break
    return findings


# -------------------------------------------------------------------- tunnelling


def rule_tunnelling(ctx: Context) -> tuple[list[Finding], set[str]]:
    """Many long, never-repeated names under one domain from one host: data over DNS."""
    if not ctx.has("srcaddr", "domain", "query_name", "labels"):
        return [], set()
    label = "len(string_split(rtrim(query_name, '.'), '.')[1])"
    pairs = ctx.sql(
        f"SELECT srcaddr, domain, count(*), count(DISTINCT query_name), avg({label}), "
        "avg(name_length), min(query_time), max(query_time), any_value(instance_id), "
        "mode(query_type), count(*) FILTER (WHERE rcode = 'NOERROR'), "
        "avg(len(coalesce(answers, ''))) FROM dns WHERE NOT blocked AND labels >= 3 "
        f"GROUP BY 1, 2 HAVING count(*) >= {TUNNEL_MIN} AND avg({label}) >= {TUNNEL_LABEL} "
        f"AND count(DISTINCT query_name) >= {TUNNEL_UNIQUE} * count(*) ORDER BY 3 DESC"
    )
    findings: list[Finding] = []
    reported: set[str] = set()
    for ip, domain, n, names, label_len, name_len, first, last, inst, qtype, ok, ans in pairs[
        :MAX_PER_RULE
    ]:
        where = f"srcaddr = {lit(ip)} AND domain = {lit(domain)} AND NOT blocked"
        # The part of the name the queries share, if there is one deeper than the domain.
        suffix, suffix_n = ctx.one(
            "SELECT array_to_string(string_split(rtrim(query_name, '.'), '.')[-3:], '.'), "
            f"count(*) FROM dns WHERE {where} GROUP BY 1 ORDER BY 2 DESC LIMIT 1"
        )
        under = suffix if suffix_n >= 0.8 * n else domain
        sample = ctx.sql(
            f"SELECT query_time, query_name, query_type, rcode, answers FROM dns WHERE {where} "
            f"ORDER BY query_time LIMIT {SAMPLE_NAMES}"
        )
        per_minute = ctx.sql(
            f"SELECT date_trunc('minute', query_time), count(*), "
            f"sum(name_length) AS name_bytes, sum(len(coalesce(answers, ''))) AS answer_bytes "
            f"FROM dns WHERE {where} GROUP BY 1 ORDER BY 1"
        )
        by_type = ctx.sql(
            f"SELECT query_type, rcode, count(*) FROM dns WHERE {where} GROUP BY 1, 2 "
            "ORDER BY 3 DESC"
        )
        minutes = minutes_between(first, last)
        who = f"{ip}" + (f" ({inst})" if inst else "")
        up = int(sum(r[2] for r in per_minute))
        down = int(sum(r[3] for r in per_minute))
        findings.append(
            Finding(
                f"tunnel-{len(findings) + 1}",
                "tunnelling",
                f"Possible DNS tunnel: {ip} sent {n:,} {qtype} queries with "
                f"{label_len:.0f}-character labels under {under}",
                Severity.HIGH,
                f"Between {fmt_ts(first)} and {fmt_ts(last)} ({plural(minutes, 'minute')}), "
                f"{who} asked for {names:,} different names under {under}, each about "
                f"{name_len:.0f} characters long with a left-most label of about "
                f"{label_len:.0f}. {ok:,} were answered"
                + (f", with answers averaging {ans:.0f} characters" if ans else "")
                + f". That is roughly {up / 1024:.0f} KB carried in the questions and "
                f"{down / 1024:.0f} KB in the answers.",
                "Names are a channel: whatever a host puts in the left-most label travels to "
                "the authoritative server for that domain, and TXT answers carry data back. A "
                "real service repeats the same names; a tunnel never asks the same thing "
                "twice because every query is a new chunk.",
                f"Treat {who} as exfiltrating or being remotely controlled until shown "
                f"otherwise. Block {under} in DNS Firewall, keep the host's disk, and find the "
                "process holding the UDP sockets. Some legitimate tools (anti-virus "
                "reputation lookups, certain CDNs) also encode data in names, so check who "
                f"owns {domain} before escalating.",
                int(n),
                where,
                [
                    Table("First queries", ["time", "name", "type", "rcode", "answers"], sample),
                    Table(
                        "Per minute",
                        ["minute", "queries", "name bytes", "answer bytes"],
                        per_minute,
                    ),
                    Table("By type and response", ["type", "rcode", "queries"], by_type),
                ],
            )
        )
        reported.add(ip)
    return findings, reported


# ---------------------------------------------------------------------- SERVFAIL


def rule_servfail(ctx: Context) -> list[Finding]:
    """A domain that failed to resolve for a while: the resolver could not get an answer."""
    if not ctx.has("rcode", "domain", "query_time"):
        return []
    minutes = ctx.sql(
        "SELECT domain, date_trunc('minute', query_time) AS m, count(*) FROM dns "
        "WHERE rcode = 'SERVFAIL' GROUP BY 1, 2 ORDER BY 1, 2"
    )
    runs: list[tuple[str, datetime, datetime, int]] = []
    for domain, minute, n in minutes:
        if (
            runs
            and runs[-1][0] == domain
            and minute - runs[-1][2] <= timedelta(minutes=SERVFAIL_GAP)
        ):
            runs[-1] = (domain, runs[-1][1], minute, runs[-1][3] + n)
        else:
            runs.append((domain, minute, minute, n))
    runs = [r for r in runs if r[3] >= SERVFAIL_MIN]
    runs.sort(key=lambda r: -r[3])
    findings: list[Finding] = []
    for domain, first, last, n in runs[:MAX_PER_RULE]:
        where = f"rcode = 'SERVFAIL' AND domain = {lit(domain)} AND {window(first, last)}"
        all_for_domain = ctx.count(f"domain = {lit(domain)} AND {window(first, last)}")
        by_name = ctx.sql(
            f"SELECT query_name, count(*), count(DISTINCT srcaddr) FROM dns WHERE {where} "
            "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        )
        by_client = ctx.sql(
            f"SELECT srcaddr, count(*) FROM dns WHERE {where} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        )
        per_minute = ctx.sql(
            f"SELECT date_trunc('minute', query_time), count(*), "
            f"count(*) FILTER (WHERE rcode = 'NOERROR') FROM dns WHERE domain = {lit(domain)} "
            f"AND {window(first, last)} GROUP BY 1 ORDER BY 1"
        )
        length = minutes_between(first, last)
        share = n / all_for_domain if all_for_domain else 0
        internal = domain.endswith((".internal", ".local", ".lan", ".corp", ".home.arpa"))
        findings.append(
            Finding(
                f"servfail-{len(findings) + 1}",
                "servfail",
                f"SERVFAIL for {n:,} queries under {domain} over {plural(length, 'minute')}",
                Severity.HIGH if share >= 0.5 and n >= 100 else Severity.MEDIUM,
                f"Between {fmt_ts(first)} and {fmt_ts(last)}, {n:,} of the {all_for_domain:,} "
                f"queries for names under {domain} ({100 * share:.0f}%) came back SERVFAIL, "
                f"from {plural(len(by_client), 'host')}: {listing([r[0] for r in by_name], 3)}.",
                "SERVFAIL is the resolver saying it tried and could not get an answer: the "
                "authoritative servers did not respond, DNSSEC validation failed, or a "
                "forwarding rule points at an endpoint that is down. The client gets no "
                "address and usually retries, so an outage shows up as a burst.",
                (
                    f"{domain} is a private zone, so this is almost certainly a Resolver rule "
                    "forwarding to on-premises or VPC DNS servers that were unreachable: check "
                    "the outbound endpoint's health, its security group and the target servers "
                    "for exactly this window."
                    if internal
                    else f"Look at the authoritative servers for {domain} and their DNSSEC "
                    "state for this window; if the zone is yours, this is your outage, if "
                    "not, your dependency's."
                ),
                int(n),
                where,
                [
                    Table("Names that failed", ["name", "SERVFAIL", "hosts"], by_name),
                    Table("By host", ["address", "SERVFAIL"], by_client),
                    Table(
                        "Per minute", ["minute", "queries for the domain", "answered"], per_minute
                    ),
                ],
            )
        )
    return findings


# ------------------------------------------------------------------------ errors


def rule_errors(ctx: Context) -> list[Finding]:
    if not ctx.has("rcode", "is_error"):
        return []
    n = ctx.errors
    if n == 0:
        return [
            Finding(
                "errors",
                "errors",
                "Every query was answered",
                Severity.INFO,
                "No query in this file came back with an error code.",
                "",
                "",
                0,
                "is_error",
            )
        ]
    by_rcode = ctx.sql(
        "SELECT rcode, count(*), count(DISTINCT query_name), count(DISTINCT srcaddr) FROM dns "
        "WHERE is_error GROUP BY 1 ORDER BY 2 DESC"
    )
    by_domain = ctx.sql(
        "SELECT domain, rcode, count(*), count(DISTINCT query_name) FROM dns WHERE is_error "
        "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15"
    )
    by_client = ctx.sql(
        "SELECT srcaddr, count(*) FILTER (WHERE is_error), count(*) FROM dns GROUP BY 1 "
        "ORDER BY 2 DESC LIMIT 10"
    )
    codes = ", ".join(f"{r[0]} {r[1]:,}" for r in by_rcode)
    share = n / ctx.total if ctx.total else 0
    return [
        Finding(
            "errors",
            "errors",
            f"{n:,} queries failed ({ctx.share(n)} of queries)",
            Severity.MEDIUM if share >= ERROR_MEDIUM_SHARE else Severity.LOW,
            f"{n:,} of {ctx.total:,} queries {span(ctx.start, ctx.end)} came back with an "
            f"error: {codes}. The domains with the most failures were "
            f"{listing([r[0] for r in by_domain], 3)}.",
            "NXDOMAIN is a name that does not exist (typos, stale configuration, or a host "
            "generating names), SERVFAIL is the resolver failing to get an answer, REFUSED a "
            "server declining to answer. A few percent of NXDOMAIN is normal in any fleet; "
            "concentrations under one domain or from one host are the findings above.",
            "Fix the stale names first (they are free), then look at whichever host or "
            "domain carries most of the rest.",
            n,
            "is_error",
            [
                Table("By response code", ["rcode", "queries", "names", "hosts"], by_rcode),
                Table("By domain and code", ["domain", "rcode", "queries", "names"], by_domain),
                Table("By host", ["address", "failed", "queries"], by_client),
            ],
        )
    ]


# -------------------------------------------------------------------- top clients


def rule_top_clients(ctx: Context) -> list[Finding]:
    if not ctx.has("srcaddr", "query_name") or ctx.total == 0:
        return []
    by_client = ctx.sql(
        "SELECT srcaddr, any_value(instance_id), count(*), count(DISTINCT query_name), "
        "count(*) FILTER (WHERE is_error) FROM dns GROUP BY 1 ORDER BY 3 DESC LIMIT 10"
    )
    by_name = ctx.sql(
        "SELECT query_name, query_type, count(*), count(DISTINCT srcaddr) FROM dns "
        "GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15"
    )
    by_type = ctx.sql(
        "SELECT query_type, count(*), count(*) FILTER (WHERE is_error) FROM dns GROUP BY 1 "
        "ORDER BY 2 DESC"
    )
    by_transport = (
        ctx.sql("SELECT transport, count(*) FROM dns GROUP BY 1 ORDER BY 2 DESC")
        if ctx.has("transport")
        else []
    )
    top_ip, instance, n, names, _ = by_client[0]
    who = f"{top_ip}" + (f" ({instance})" if instance else "")
    return [
        Finding(
            "top-clients",
            "top_clients",
            f"Top client: {top_ip} made {n:,} queries ({ctx.share(n)})",
            Severity.INFO,
            f"{who} asked for {names:,} different names in {n:,} queries. The most asked "
            f"name overall was {by_name[0][0]} ({by_name[0][2]:,} queries from "
            f"{plural(int(by_name[0][3]), 'host')}).",
            "A plain ranking so the busy hosts and the popular names are visible at a glance.",
            "",
            int(n),
            f"srcaddr = {lit(top_ip)}",
            [
                Table("By host", ["address", "instance", "queries", "names", "failed"], by_client),
                Table("Most asked names", ["name", "type", "queries", "hosts"], by_name),
                Table("By query type", ["type", "queries", "failed"], by_type),
                *(
                    [Table("By transport", ["transport", "queries"], by_transport)]
                    if by_transport
                    else []
                ),
            ],
        )
    ]


# ---------------------------------------------------------------------- timeline


def timeline(ctx: Context) -> dict[str, Any] | None:
    if not ctx.has("query_time", "is_error") or not ctx.start or not ctx.end:
        return None
    name, secs = pick_bucket((ctx.end - ctx.start).total_seconds())
    rows = ctx.sql(
        f"SELECT to_timestamp(floor(epoch(query_time) / {secs}) * {secs}) AT TIME ZONE 'UTC', "
        "count(*) FILTER (WHERE NOT is_error AND NOT blocked), "
        "count(*) FILTER (WHERE is_error OR blocked) FROM dns WHERE query_time IS NOT NULL "
        "GROUP BY 1 ORDER BY 1"
    )
    if not rows:
        return None
    fmt = "%H:%M" if secs < 86400 else "%m-%d"
    return {
        "bucket": name,
        "labels": [r[0].strftime(fmt) for r in rows],
        "series": {"accepted": [int(r[1]) for r in rows], "rejected": [int(r[2]) for r in rows]},
        "title": "Answered queries against failed or blocked ones",
        "good": "answered",
        "bad": "failed or blocked",
        "unit": "queries",
    }


def run_rules(ds: Dataset) -> list[Finding]:
    ctx = make_context(ds)
    findings: list[Finding] = []
    findings += rule_firewall_blocks(ctx)
    bursts, reported = rule_nxdomain_bursts(ctx)
    findings += bursts
    tunnels, tunnelling = rule_tunnelling(ctx)
    findings += tunnels
    findings += rule_name_sweep(ctx, reported | tunnelling)
    findings += rule_servfail(ctx)
    findings += rule_errors(ctx)
    findings += rule_top_clients(ctx)
    return sort_findings(findings)


def build_timeline(ds: Dataset) -> dict[str, Any] | None:
    return timeline(make_context(ds))
