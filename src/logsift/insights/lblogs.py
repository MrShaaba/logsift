"""Rule-based findings for Application and Network Load Balancer access logs.

Every rule is plain SQL over the ``lb`` table built by ``logsift.lb``. ALB logs are one
line per request, so the rules talk about status codes, targets and paths. NLB logs are
one line per TLS connection, so they talk about handshakes, alerts and connection churn.
Thresholds are simple and written next to each rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

import duckdb

from logsift.formats import Format
from logsift.insights.base import (
    Finding,
    Severity,
    Table,
    fmt_bytes,
    fmt_ts,
    pick_bucket,
    plural,
    sort_findings,
    span,
    ts,
    utc,
)
from logsift.sql import lit

if TYPE_CHECKING:
    from logsift.dataset import Dataset

IS_5XX = "(elb_status_code BETWEEN 500 AND 599)"
IS_4XX = "(elb_status_code BETWEEN 400 AND 499)"
TARGET = "coalesce(target_ip || ':' || target_port, 'load balancer')"

BURST_MIN_ERRORS = 10  # 5xx in one minute before a minute counts as hot
BURST_MIN_SHARE = 0.05  # and at least this share of that minute's requests
TARGET_MIN_REQUESTS = 20
TARGET_MIN_ERRORS = 10
TARGET_MIN_RATE = 0.10
SLOW_FLOOR_SECONDS = 2.0  # a request is slow at max(2 s, 5 x the file's p95)
SLOW_MIN_REQUESTS = 10  # per path before its percentiles are shown
PROBE_MIN_ERRORS = 30
PROBE_MIN_PATHS = 15
CHURN_MIN_CONNECTIONS = 200
CHURN_MAX_MEDIAN_MS = 100
CHURN_MIN_PER_MINUTE = 20  # a minute this busy from one client counts as part of a burst
OLD_TLS = ("SSLv3", "TLSv1", "TLSv1.1", "sslv3", "tlsv1", "tlsv11")


@dataclass
class Context:
    con: duckdb.DuckDBPyConnection
    kind: Format
    columns: set[str]
    total: int
    start: datetime | None
    end: datetime | None

    def has(self, *cols: str) -> bool:
        return all(c in self.columns for c in cols)

    def sql(self, query: str) -> list[tuple[Any, ...]]:
        return self.con.execute(query).fetchall()

    def one(self, query: str) -> tuple[Any, ...]:
        row = self.con.execute(query).fetchone()
        return row if row is not None else ()

    def count(self, where: str) -> int:
        return int(self.one(f"SELECT count(*) FROM lb WHERE {where}")[0])

    def share(self, n: int, of: int | None = None) -> str:
        of = self.total if of is None else of
        return f"{100.0 * n / of:.1f}%" if of else "0%"

    @property
    def unit(self) -> str:
        return "requests" if self.kind == Format.ALB else "connections"


def make_context(ds: Dataset) -> Context:
    con = ds.cursor()
    columns = {c for c, _ in ds.columns}
    if "time" in columns:
        row = con.execute("SELECT count(*), min(time), max(time) FROM lb").fetchone()
    else:
        row = con.execute("SELECT count(*), NULL, NULL FROM lb").fetchone()
    total, start, end = row or (0, None, None)
    return Context(con, ds.format.kind, columns, int(total), start, end)


# ------------------------------------------------------------------------ ALB rules


def rule_server_errors(ctx: Context) -> list[Finding]:
    if not ctx.has("elb_status_code"):
        return []
    n = ctx.count(IS_5XX)
    if n == 0:
        return [
            Finding(
                "server-errors",
                "server_errors",
                "No server errors",
                Severity.INFO,
                f"None of the {ctx.total:,} requests got a 5xx response.",
                "Every request was answered by a target or by the load balancer itself with a "
                "non-error status.",
                "",
                0,
                IS_5XX,
            )
        ]
    share = n / ctx.total
    sev = Severity.HIGH if share >= 0.05 else Severity.MEDIUM if share >= 0.01 else Severity.LOW
    first, last = ctx.one(f"SELECT min(time), max(time) FROM lb WHERE {IS_5XX}") or (None, None)
    tables: list[Table] = []
    codes = ctx.sql(
        f"""
        SELECT elb_status_code,
               CASE WHEN target_status_code IS NULL THEN 'load balancer' ELSE 'target' END,
               count(*), round(100.0 * count(*) / {n}, 1)
        FROM lb WHERE {IS_5XX} GROUP BY ALL ORDER BY 3 DESC
        """
    )
    tables.append(
        Table("By status code", ["status", "answered by", "requests", "share (%)"], codes)
    )
    if ctx.has("path"):
        tables.append(
            Table(
                "By path",
                ["path", "5xx", "clients"],
                ctx.sql(
                    f"SELECT path, count(*), count(DISTINCT client_ip) FROM lb WHERE {IS_5XX} "
                    "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
                ),
            )
        )
    if ctx.has("target_ip"):
        tables.append(
            Table(
                "By target",
                ["target", "5xx", "requests", "5xx share of its requests (%)"],
                ctx.sql(
                    f"""
                    SELECT {TARGET}, count(*) FILTER (WHERE {IS_5XX}) AS errors, count(*),
                           round(100.0 * count(*) FILTER (WHERE {IS_5XX}) / count(*), 1)
                    FROM lb GROUP BY 1 HAVING errors > 0 ORDER BY errors DESC LIMIT 10
                    """
                ),
            )
        )
    code, origin = codes[0][0], codes[0][1]
    if origin == "load balancer":
        cause = {
            502: "The load balancer could not get a valid response from the target: it closed "
            "the connection, reset it, or sent a malformed reply. Look at the target's process "
            "restarts and at any keep-alive timeout shorter than the load balancer's idle "
            "timeout.",
            503: "No healthy target was registered when these requests arrived. Check the target "
            "group's health check history and whether a deployment deregistered everything "
            "at once.",
            504: "The target did not start answering before the idle timeout (60 s by default). "
            "Either the target is overloaded, the request does slow work, or the timeout is "
            "too short for it.",
        }.get(int(code), "The load balancer generated the error itself; see the status code.")
    else:
        cause = (
            f"The targets themselves returned {code}: an application error, not a load balancer "
            "one. The target's own logs for the paths in the second table have the stack trace."
        )
    return [
        Finding(
            "server-errors",
            "server_errors",
            f"{n:,} server errors ({ctx.share(n)} of requests)",
            sev,
            f"{n:,} of {ctx.total:,} requests got a 5xx response {span(first, last)}, mostly "
            f"{code} answered by the {origin}.",
            "A 5xx means the request reached the load balancer but no good answer came back. "
            "When target_status_code is empty the load balancer produced the error itself: 502 "
            "when the target closed the connection or replied badly, 503 when no healthy target "
            "existed, 504 when the target did not answer in time. When it is set, the target "
            "returned the error.",
            cause,
            n,
            IS_5XX,
            tables,
        )
    ]


def rule_error_bursts(ctx: Context) -> list[Finding]:
    """Minutes where 5xx responses pile up far above the file's own baseline."""
    if not ctx.has("elb_status_code", "time"):
        return []
    rows = ctx.sql(
        f"""
        SELECT date_trunc('minute', time) AS m, count(*),
               count(*) FILTER (WHERE {IS_5XX})
        FROM lb WHERE time IS NOT NULL GROUP BY 1 ORDER BY 1
        """
    )
    total_errors = sum(int(e) for _, _, e in rows)
    if not rows or total_errors == 0:
        return []
    baseline = total_errors / ctx.total
    floor = max(3 * baseline, BURST_MIN_SHARE)
    hot = [(m, int(r), int(e)) for m, r, e in rows if e >= BURST_MIN_ERRORS and e / r >= floor]
    if not hot:
        return []
    # Merge hot minutes that are at most one minute apart into windows.
    windows: list[list[Any]] = []
    for m, r, e in hot:
        if windows and (m - windows[-1][1]).total_seconds() <= 120:
            windows[-1][1] = m
            windows[-1][2] += r
            windows[-1][3] += e
        else:
            windows.append([m, m, r, e])
    details: list[tuple[Any, ...]] = []
    filters: list[str] = []
    for start, end, _, _ in windows:
        stop = end.replace(second=0) + timedelta(minutes=1)
        where = f"time >= {ts(start)} AND time < {ts(stop)}"
        filters.append(f"({where})")
        # Count over the merged window so the table agrees with the rows behind it.
        requests, errors = (
            int(v)
            for v in ctx.one(
                f"SELECT count(*), count(*) FILTER (WHERE {IS_5XX}) FROM lb WHERE {where}"
            )
        )
        code, target, _ = ctx.one(
            f"SELECT elb_status_code, {TARGET}, count(*) FROM lb WHERE {IS_5XX} AND {where} "
            "GROUP BY ALL ORDER BY 3 DESC LIMIT 1"
        )
        details.append(
            (start, stop, requests, errors, round(100.0 * errors / requests, 1), code, target)
        )
    biggest = max(details, key=lambda d: d[3])
    start, stop, requests, errors, pct, code, target = biggest
    burst_errors = sum(d[3] for d in details)
    minutes = sum(int((d[1] - d[0]).total_seconds() // 60) for d in details)
    sev = Severity.HIGH if errors >= 50 else Severity.MEDIUM
    lb_made = int(code) in (502, 503, 504)
    where = f"{IS_5XX} AND ({' OR '.join(filters)})"
    return [
        Finding(
            "error-burst",
            "error_bursts",
            f"{plural(len(details), 'burst')} of server errors: {burst_errors:,} 5xx in "
            f"{plural(minutes, 'minute')}",
            sev,
            f"Between {fmt_ts(start)} and {fmt_ts(stop)}, {errors:,} of {requests:,} requests "
            f"({pct}%) failed with 5xx, mostly {code} on {target}. Across the whole file the "
            f"rate is {ctx.share(total_errors)}.",
            "Errors packed into a short window usually have one cause: a deployment, a target "
            "restarting, a dependency going away or a traffic spike. Errors spread evenly over "
            "the file point at an application bug instead.",
            (
                f"{target} stopped answering properly for that window. Check its deployments, "
                "restarts and health check history for the same minutes."
                if lb_made and target != "load balancer"
                else "Look at what changed at the start of the window: a deployment, a "
                "configuration change or an upstream dependency."
            ),
            ctx.count(where),
            where,
            [
                Table(
                    "Bursts",
                    ["from", "to", "requests", "5xx", "share (%)", "mostly", "target"],
                    details,
                )
            ],
        )
    ]


def rule_failing_targets(ctx: Context) -> list[Finding]:
    """One target failing far more of its requests than the others in its group."""
    if not ctx.has("target_ip", "target_port", "elb_status_code"):
        return []
    group_col = "target_group" if ctx.has("target_group") else "NULL"
    rows = ctx.sql(
        f"""
        SELECT {group_col} AS grp, target_ip, target_port, count(*) AS requests,
               count(*) FILTER (WHERE {IS_5XX}) AS errors,
               count(*) FILTER (WHERE {IS_5XX} AND target_status_code IS NULL) AS no_answer,
               min(time) FILTER (WHERE {IS_5XX}), max(time) FILTER (WHERE {IS_5XX}),
               round(median(target_processing_time) FILTER (WHERE target_processing_time >= 0), 3)
        FROM lb WHERE target_ip IS NOT NULL GROUP BY ALL ORDER BY errors DESC
        """
    )
    by_group: dict[Any, tuple[int, int]] = {}
    for grp, _, _, requests, errors, *_ in rows:
        r, e = by_group.get(grp, (0, 0))
        by_group[grp] = (r + int(requests), e + int(errors))
    findings: list[Finding] = []
    for grp, ip, port, requests, errors, no_answer, first, last, _median in rows:
        requests, errors, no_answer = int(requests), int(errors), int(no_answer)
        if requests < TARGET_MIN_REQUESTS or errors < TARGET_MIN_ERRORS:
            continue
        rate = errors / requests
        g_req, g_err = by_group[grp]
        sib_req, sib_err = g_req - requests, g_err - errors
        sib_rate = sib_err / sib_req if sib_req else None
        if rate < TARGET_MIN_RATE or (sib_rate is not None and rate < 3 * sib_rate):
            continue
        target = f"{ip}:{port}"
        where = f"{IS_5XX} AND target_ip = {lit(ip)} AND target_port = {lit(port)}"
        code, _, first, last = ctx.one(
            f"SELECT elb_status_code, count(*), min(time), max(time) FROM lb WHERE {where} "
            "GROUP BY 1 ORDER BY 2 DESC LIMIT 1"
        )
        siblings = [
            (f"{i}:{p}", int(r), int(e), round(100.0 * int(e) / int(r), 1), int(na), med)
            for g, i, p, r, e, na, _, _, med in rows
            if g == grp
        ]
        group_name = f"target group {grp}" if grp else "its target group"
        others = (
            f"The other targets in {group_name} failed {ctx.share(sib_err, sib_req)} of theirs."
            if sib_req
            else f"It is the only target in {group_name}."
        )
        no_reply = (
            f", {no_answer:,} of them with no response from the target at all" if no_answer else ""
        )
        if no_answer >= errors / 2:
            cause = (
                f"The process on {target} accepts connections but closes them before answering, "
                "which is what a crash loop, an out-of-memory restart or a half-finished "
                "deployment look like from the load balancer. Its health check must still be "
                "passing or it would have been taken out of rotation, so compare the health "
                "check path with the paths that fail and read the target's own logs for "
                f"{fmt_ts(first)} to {fmt_ts(last)}."
            )
        else:
            cause = (
                f"The application on {target} returns errors that its siblings do not: a bad "
                "deployment on that one host, a missing dependency or configuration, or a "
                "disk or memory problem local to it."
            )
        findings.append(
            Finding(
                f"failing-target-{len(findings) + 1}",
                "failing_target",
                f"Target {target} failed {100 * rate:.0f}% of its requests "
                f"({errors:,} of {requests:,})",
                Severity.HIGH if rate >= 0.5 or errors >= 100 else Severity.MEDIUM,
                f"{errors:,} requests sent to {target} in {group_name} came back 5xx, mostly "
                f"{code} {span(first, last)}{no_reply}. {others}",
                "The load balancer only stops sending traffic to a target when its health check "
                "fails. A target whose health check passes while its real requests fail keeps "
                "getting its share, and clients see errors for as long as that lasts.",
                cause,
                errors,
                where,
                [
                    Table(
                        "Targets in the same group",
                        [
                            "target",
                            "requests",
                            "5xx",
                            "5xx share (%)",
                            "no response",
                            "median target time (s)",
                        ],
                        siblings,
                    )
                ],
            )
        )
    return findings


def rule_slow_requests(ctx: Context) -> list[Finding]:
    if not ctx.has("target_processing_time"):
        return []
    p50, p95, slowest, n_timed = ctx.one(
        "SELECT round(quantile_cont(target_processing_time, 0.5), 3), "
        "round(quantile_cont(target_processing_time, 0.95), 3), max(target_processing_time), "
        "count(*) FROM lb WHERE target_processing_time >= 0"
    ) or (None, None, None, 0)
    if not n_timed:
        return []
    threshold = max(SLOW_FLOOR_SECONDS, 5 * float(p95))
    where = f"target_processing_time >= {threshold:g}"
    n = ctx.count(where)
    timeouts = ctx.count("elb_status_code = 504") if ctx.has("elb_status_code") else 0
    tables: list[Table] = []
    timeout_expr = (
        "count(*) FILTER (WHERE elb_status_code = 504)" if ctx.has("elb_status_code") else "0"
    )
    for col, title in (("path", "Slowest paths"), (TARGET, "By target")):
        if col == "path" and not ctx.has("path"):
            continue
        if col == TARGET and not ctx.has("target_ip"):
            continue
        tables.append(
            Table(
                title,
                [title.split()[-1].rstrip("s"), "requests", "p50 (s)", "p95 (s)", "max (s)", "504"],
                ctx.sql(
                    f"""
                    SELECT {col}, count(*), round(quantile_cont(target_processing_time, 0.5), 3),
                           round(quantile_cont(target_processing_time, 0.95), 3),
                           round(max(target_processing_time), 3), {timeout_expr}
                    FROM lb WHERE target_processing_time >= 0
                    GROUP BY 1 HAVING count(*) >= {SLOW_MIN_REQUESTS} ORDER BY 4 DESC LIMIT 10
                    """
                ),
            )
        )
    if n == 0 and timeouts == 0:
        return [
            Finding(
                "slow-requests",
                "slow_requests",
                "Target response times look healthy",
                Severity.INFO,
                f"The typical request takes {p50} s, 95% finish within {p95} s and the slowest "
                f"took {slowest} s. Nothing reached {threshold:g} s.",
                "target_processing_time is how long the target took to start answering after "
                "the load balancer sent it the request.",
                "",
                0,
                where,
                tables,
            )
        ]
    top_path, top_share = "", ""
    if ctx.has("path") and n:
        row = ctx.one(
            f"SELECT path, count(*) FROM lb WHERE {where} AND path IS NOT NULL "
            "GROUP BY 1 ORDER BY 2 DESC LIMIT 1"
        )
        if row:
            top_path, top_share = str(row[0]), ctx.share(int(row[1]), n)
    timed_out = f", {timeouts:,} of which timed out (504)" if timeouts else ""
    return [
        Finding(
            "slow-requests",
            "slow_requests",
            f"{n:,} slow requests took {threshold:g} s or more"
            + (f", {timeouts} timed out" if timeouts else ""),
            Severity.MEDIUM if timeouts or n / ctx.total >= 0.01 else Severity.LOW,
            f"The typical request takes {p50} s and 95% finish within {p95} s, but {n:,} took "
            f"{threshold:g} s or more{timed_out}."
            + (f" {top_share} of those were for {top_path}." if top_path else ""),
            "target_processing_time is how long the target took to start answering. A few slow "
            "requests spread over many paths is load; one slow path with everything else normal "
            "is that endpoint's own work, such as a heavy query, a report or an upstream call. "
            "A 504 means the target passed the idle timeout and the client got nothing.",
            (
                f"{top_path} does expensive work per request. Profile it, cache it or move it "
                "to a background job; if it is legitimately slow, raise the idle timeout for it "
                "or stream the response."
                if top_path
                else "Look at the slowest targets: one slow target with normal siblings is a "
                "capacity or noisy-neighbour problem on that host."
            ),
            n,
            where,
            tables,
        )
    ]


def rule_client_errors(ctx: Context) -> list[Finding]:
    if not ctx.has("elb_status_code"):
        return []
    n = ctx.count(IS_4XX)
    if n == 0:
        return []
    tables = [
        Table(
            "By status code",
            ["status", "answered by", "requests"],
            ctx.sql(
                f"""
                SELECT elb_status_code,
                       CASE WHEN target_status_code IS NULL THEN 'load balancer' ELSE 'target' END,
                       count(*)
                FROM lb WHERE {IS_4XX} GROUP BY ALL ORDER BY 3 DESC
                """
            ),
        )
    ]
    if ctx.has("path"):
        tables.append(
            Table(
                "By path",
                ["path", "requests", "clients"],
                ctx.sql(
                    f"SELECT path, count(*), count(DISTINCT client_ip) FROM lb WHERE {IS_4XX} "
                    "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
                ),
            )
        )
    clients: list[tuple[Any, ...]] = []
    if ctx.has("client_ip"):
        clients = ctx.sql(
            f"SELECT client_ip, count(*), count(DISTINCT path) FROM lb WHERE {IS_4XX} "
            "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        )
        tables.append(Table("By client", ["client", "requests", "different paths"], clients))
    code = int(tables[0].rows[0][0])
    top_client_share = int(clients[0][1]) / n if clients else 0
    if code == 404 and top_client_share >= 0.5:
        cause = (
            f"{clients[0][0]} alone produced {ctx.share(int(clients[0][1]), n)} of the client "
            "errors, across many paths: see the probing finding. The remaining 404s are the "
            "ordinary broken links in the paths table."
        )
    elif code == 404:
        cause = "Broken links, removed pages or stale caches: the paths table shows which."
    elif code in (401, 403):
        cause = (
            "Clients sending missing or stale credentials. A cluster from one client is usually "
            "an integration whose token expired or whose IAM permissions changed."
        )
    else:
        cause = "Clients sending requests the application rejects; the paths table shows where."
    return [
        Finding(
            "client-errors",
            "client_errors",
            f"{n:,} client errors ({ctx.share(n)} of requests)",
            Severity.MEDIUM if n / ctx.total >= 0.10 else Severity.LOW,
            f"{n:,} of {ctx.total:,} requests got a 4xx response, mostly {code}.",
            "4xx responses are the client's fault by definition, but what they reveal differs: "
            "404s on paths you never served are scanning, 404s on paths you do serve are broken "
            "links, and 401 or 403 clusters from one client are a misconfigured integration.",
            cause,
            n,
            IS_4XX,
            tables,
        )
    ]


def rule_probing(ctx: Context) -> list[Finding]:
    """One client walking through many different paths and getting client errors."""
    if not ctx.has("client_ip", "path", "elb_status_code"):
        return []
    agent = "any_value(user_agent)" if ctx.has("user_agent") else "NULL"
    rows = ctx.sql(
        f"""
        SELECT client_ip, count(*) AS requests, count(*) FILTER (WHERE {IS_4XX}) AS errors,
               count(DISTINCT path) FILTER (WHERE {IS_4XX}) AS paths, min(time), max(time),
               {agent}
        FROM lb GROUP BY 1
        HAVING errors >= {PROBE_MIN_ERRORS} AND paths >= {PROBE_MIN_PATHS}
           AND errors >= 0.8 * requests
        ORDER BY errors DESC LIMIT 5
        """
    )
    findings: list[Finding] = []
    for i, (client, requests, errors, paths, first, last, ua) in enumerate(rows, 1):
        where = f"client_ip = {lit(client)} AND {IS_4XX}"
        tried = ctx.sql(
            f"SELECT coalesce(path, '(malformed request)'), elb_status_code, count(*) FROM lb "
            f"WHERE {where} GROUP BY ALL ORDER BY 3 DESC, 1 LIMIT 25"
        )
        examples = ", ".join([str(r[0]) for r in tried if str(r[0]).startswith("/")][:3])
        findings.append(
            Finding(
                f"probing-{i}",
                "path_probing",
                f"{client} tried {paths} different paths and got {errors:,} client errors",
                Severity.LOW,
                f"Between {fmt_ts(first)} and {fmt_ts(last)}, {client} made {requests:,} requests "
                f"and {errors:,} of them ({ctx.share(int(errors), int(requests))}) came back 4xx, "
                f"across {paths} different paths such as {examples}."
                + (f" User agent: {ua}." if ua else ""),
                "Stated as a fact to look at, not as a verdict: one address walking through many "
                "paths that do not exist is what automated scanning looks like, but it is also "
                "what a broken crawler or a misconfigured monitoring job looks like.",
                "Internet background scanning for known applications (WordPress, phpMyAdmin, "
                "exposed .env and .git files). The targets answered 404 each time, so nothing "
                "was found, but every one of those requests still reached a target. A WAF "
                "rate-based rule or a fixed-response rule on the load balancer would stop them "
                "earlier.",
                int(errors),
                where,
                [Table("Paths tried", ["path", "status", "requests"], tried)],
            )
        )
    return findings


# ------------------------------------------------------------------------ NLB rules

TRUST_ALERTS = ("unknown_ca", "certificate_unknown", "unsupported_certificate")
REJECT_ALERTS = ("bad_certificate", "certificate_expired", "certificate_revoked")
POLICY_ALERTS = ("handshake_failure", "protocol_version", "insufficient_security")


def alert_cause(alert: str) -> str:
    if alert in TRUST_ALERTS:
        return (
            f"{alert}: the client does not trust the certificate chain the load balancer "
            "presents, so a private CA, a missing intermediate certificate or an outdated "
            "trust store on the client. Check the chain on the certificate in ACM and the "
            "client's CA bundle."
        )
    if alert in REJECT_ALERTS:
        return (
            f"{alert}: the client received the certificate and rejected it. Clients that "
            "connected without a server name (SNI shows as none) were given the default "
            "certificate, which does not match the name they used; otherwise look for an "
            "expired or wrong certificate."
        )
    if alert in POLICY_ALERTS:
        return (
            f"{alert}: no protocol version or cipher in common, so the client is too old for "
            "the listener's security policy, or the policy is older than the client accepts."
        )
    if alert == "no client hello":
        return (
            "No client hello: plain TCP or the wrong protocol sent to a TLS listener, which is "
            "a port scan, a health checker pointed at the wrong port, or a client missing its "
            "TLS wrapper."
        )
    return f"{alert}: the client closed the handshake with this alert; see RFC 8446 section 6."


def rule_handshake_failures(ctx: Context) -> list[Finding]:
    if not ctx.has("handshake_ok"):
        return []
    where = "NOT handshake_ok"
    n = ctx.count(where)
    if n == 0:
        return [
            Finding(
                "tls-failures",
                "tls_handshake_failures",
                "Every TLS handshake completed",
                Severity.INFO,
                f"All {ctx.total:,} connections negotiated TLS successfully.",
                "A failed handshake would show up with no handshake time and, usually, the TLS "
                "alert the client sent when it gave up.",
                "",
                0,
                where,
            )
        ]
    alert = "coalesce(alert_name, 'no client hello')"
    by_alert = ctx.sql(
        f"SELECT {alert}, count(*), count(DISTINCT client_ip), min(time), max(time) FROM lb "
        f"WHERE {where} GROUP BY 1 ORDER BY 2 DESC"
    )
    by_client = ctx.sql(
        f"""
        SELECT client_ip, {alert}, coalesce(domain_name, '(none)'),
               coalesce(tls_protocol_version, '-'), count(*)
        FROM lb WHERE {where} GROUP BY ALL ORDER BY 5 DESC LIMIT 10
        """
    )
    parts = []
    for name, count, clients, _, _ in by_alert:
        if name == "no client hello":
            parts.append(f"{count:,} sent no valid client hello")
        else:
            parts.append(f"{count:,} ended with {name} from {plural(int(clients), 'client')}")
    cause = " ".join(dict.fromkeys(alert_cause(str(name)) for name, *_ in by_alert))
    sev = (
        Severity.HIGH
        if n >= 100 or n / ctx.total >= 0.10
        else Severity.MEDIUM
        if n >= 20
        else Severity.LOW
    )
    return [
        Finding(
            "tls-failures",
            "tls_handshake_failures",
            f"{n:,} TLS handshakes failed ({ctx.share(n)} of connections)",
            sev,
            f"{n:,} of {ctx.total:,} connections never completed the TLS handshake: "
            + "; ".join(parts)
            + ".",
            "A handshake that never completes carries no application data. The log records the "
            "TLS alert the client sent when it gave up, which is the client's own reason for "
            "closing, or nothing at all when no valid client hello arrived.",
            cause,
            n,
            where,
            [
                Table(
                    "By TLS alert", ["alert", "connections", "clients", "first", "last"], by_alert
                ),
                Table(
                    "By client",
                    ["client", "alert", "server name (SNI)", "protocol", "connections"],
                    by_client,
                ),
            ],
        )
    ]


def rule_connection_churn(ctx: Context) -> list[Finding]:
    """One client opening a very large number of very short connections."""
    if not ctx.has("client_ip", "connection_time", "handshake_ok"):
        return []
    alpn = "mode(alpn_fe_protocol)" if ctx.has("alpn_fe_protocol") else "NULL"
    rows = ctx.sql(
        f"""
        SELECT client_ip, count(*) AS n, median(connection_time) AS med,
               coalesce(sum(received_bytes), 0) + coalesce(sum(sent_bytes), 0),
               min(time), max(time), {alpn}
        FROM lb WHERE handshake_ok GROUP BY 1
        HAVING n >= {CHURN_MIN_CONNECTIONS} AND med <= {CHURN_MAX_MEDIAN_MS}
        ORDER BY n DESC LIMIT 5
        """
    )
    if not rows:
        return []
    overall = ctx.one("SELECT median(connection_time) FROM lb WHERE handshake_ok")[0]
    busiest = ctx.sql(
        """
        SELECT client_ip, count(*), median(connection_time),
               coalesce(sum(received_bytes), 0) + coalesce(sum(sent_bytes), 0), min(time), max(time)
        FROM lb WHERE handshake_ok GROUP BY 1 ORDER BY 2 DESC LIMIT 10
        """
    )
    findings: list[Finding] = []
    for i, (client, n, med, total_bytes, first, last, proto) in enumerate(rows, 1):
        where = f"client_ip = {lit(client)} AND handshake_ok"
        # Narrow to the busiest run of minutes when the churn is a burst, not a steady drip.
        hot = ctx.sql(
            f"SELECT date_trunc('minute', time), count(*) FROM lb WHERE {where} "
            f"GROUP BY 1 HAVING count(*) >= {CHURN_MIN_PER_MINUTE} ORDER BY 1"
        )
        runs: list[list[Any]] = []
        for minute, count in hot:
            if runs and (minute - runs[-1][1]).total_seconds() <= 120:
                runs[-1][1], runs[-1][2] = minute, runs[-1][2] + int(count)
            else:
                runs.append([minute, minute, int(count)])
        if runs:
            start, end, _ = max(runs, key=lambda r: r[2])
            stop = end + timedelta(minutes=1)
            where = f"{where} AND time >= {ts(start)} AND time < {ts(stop)}"
            n, med, total_bytes, first, last = ctx.one(
                "SELECT count(*), median(connection_time), coalesce(sum(received_bytes), 0) + "
                f"coalesce(sum(sent_bytes), 0), min(time), max(time) FROM lb WHERE {where}"
            )
        minutes = max(1.0, (last - first).total_seconds() / 60) if first and last else 1.0
        findings.append(
            Finding(
                f"connection-churn-{i}",
                "connection_churn",
                f"{client} opened {int(n):,} connections in {minutes:.0f} minutes, median "
                f"lifetime {med:.0f} ms",
                Severity.MEDIUM,
                f"Between {fmt_ts(first)} and {fmt_ts(last)}, {client} opened {int(n):,} TLS "
                f"connections, about {int(n) / minutes:.0f} a minute, each living {med:.0f} ms "
                f"and carrying {fmt_bytes(total_bytes)} in total. Other clients' connections "
                f"live {float(overall):,.0f} ms on median.",
                "Every connection costs a full TLS handshake on both ends and counts against the "
                "load balancer's new-flow capacity. A client that opens a connection per request "
                "instead of reusing one wastes CPU on both sides, and when the pattern is a "
                "retry loop it also means something is failing quietly upstream.",
                "A client with keep-alive turned off, a connection pool sized to zero, or a "
                "health checker or retry loop aimed at the listener."
                + (
                    f" The negotiated protocol was {proto}, so check that client's HTTP settings."
                    if proto
                    else ""
                ),
                int(n),
                where,
                [
                    Table(
                        "Busiest clients",
                        ["client", "connections", "median lifetime (ms)", "bytes", "first", "last"],
                        [(c, int(k), float(m), int(b), f, t) for c, k, m, b, f, t in busiest],
                    )
                ],
            )
        )
    return findings


# --------------------------------------------------------------------- shared rules


def rule_tls_versions(ctx: Context) -> list[Finding]:
    if ctx.has("ssl_protocol"):
        col, cipher = "ssl_protocol", "ssl_cipher"
    elif ctx.has("tls_protocol_version"):
        col, cipher = "tls_protocol_version", "tls_cipher"
    else:
        return []
    old = ", ".join(lit(v) for v in OLD_TLS)
    where = f"{col} IN ({old})"
    n = ctx.count(where)
    by_version = ctx.sql(
        f"SELECT {col}, {cipher}, count(*) FROM lb WHERE {col} IS NOT NULL "
        "GROUP BY ALL ORDER BY 3 DESC"
    )
    tables = [Table("By protocol and cipher", ["protocol", "cipher", ctx.unit], by_version)]
    plain = ""
    if ctx.has("type"):
        http = ctx.count("type = 'http'")
        if http:
            plain = f" {http:,} requests arrived over plain HTTP on the http listener."
    if n == 0:
        return [
            Finding(
                "tls-versions",
                "tls_versions",
                "All TLS connections used TLS 1.2 or 1.3",
                Severity.INFO,
                f"No client negotiated TLS 1.0, 1.1 or SSL 3.{plain}",
                "The protocol column records what each client actually negotiated, which is the "
                "evidence you need before tightening the security policy.",
                "",
                0,
                where,
                tables,
            )
        ]
    agent = ", any_value(user_agent)" if ctx.has("user_agent") else ""
    clients = ctx.sql(
        f"SELECT client_ip, {col}, count(*){agent} FROM lb WHERE {where} "
        "GROUP BY ALL ORDER BY 3 DESC LIMIT 10"
    )
    versions = ", ".join(sorted({str(r[1]) for r in clients}))
    columns = ["client", "protocol", ctx.unit] + (["user agent"] if agent else [])
    tables.insert(0, Table("Clients on old TLS versions", columns, clients))
    return [
        Finding(
            "tls-versions",
            "tls_versions",
            f"{n:,} {ctx.unit} still used {versions}",
            Severity.LOW,
            f"{n:,} of {ctx.total:,} {ctx.unit} ({ctx.share(n)}) negotiated {versions}, from "
            f"{plural(len({r[0] for r in clients}), 'client')}.{plain}",
            "TLS 1.0 and 1.1 were deprecated in 2021 (RFC 8996) and current security policies "
            "disable them. Knowing which clients still depend on them is the hard part of "
            "switching policies; this is that list.",
            "An old runtime or embedded device on the client side; the user agent, where there "
            "is one, says which. These clients will stop working when the security policy "
            "drops old versions, so contact their owners before changing it.",
            n,
            where,
            tables,
        )
    ]


def rule_top_clients(ctx: Context) -> list[Finding]:
    if not ctx.has("client_ip"):
        return []
    by_count = ctx.sql(
        "SELECT client_ip, count(*), coalesce(sum(received_bytes), 0), "
        "coalesce(sum(sent_bytes), 0) FROM lb WHERE client_ip IS NOT NULL "
        "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
    )
    if not by_count:
        return []
    by_bytes = ctx.sql(
        "SELECT client_ip, coalesce(sum(sent_bytes), 0), count(*) FROM lb "
        "WHERE client_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
    )
    distinct = int(ctx.one("SELECT count(DISTINCT client_ip) FROM lb")[0])
    top_ten = sum(int(r[1]) for r in by_count)
    tables = [
        Table(f"Top clients by {ctx.unit}", ["client", ctx.unit, "received", "sent"], by_count),
        Table("Top clients by bytes sent", ["client", "bytes sent", ctx.unit], by_bytes),
    ]
    if ctx.has("user_agent"):
        tables.append(
            Table(
                "Top user agents",
                ["user agent", "requests", "clients"],
                ctx.sql(
                    "SELECT user_agent, count(*), count(DISTINCT client_ip) FROM lb "
                    "WHERE user_agent IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
                ),
            )
        )
    top = by_count[0]
    return [
        Finding(
            "top-clients",
            "top_clients",
            f"Top client: {top[0]} made {int(top[1]):,} {ctx.unit} ({ctx.share(int(top[1]))})",
            Severity.INFO,
            f"{distinct:,} different clients appear in this file. The ten busiest account for "
            f"{ctx.share(top_ten)} of {ctx.unit}; {top[0]} alone sent {fmt_bytes(top[2])} and "
            f"received {fmt_bytes(top[3])}.",
            "Who talks to the load balancer most. A single address far ahead of the rest is "
            "either a NAT gateway in front of many users, a partner integration, or a problem.",
            "",
            int(top[1]),
            f"client_ip = {lit(top[0])}",
            tables,
        )
    ]


# ------------------------------------------------------------------------ timeline


def timeline(ctx: Context) -> dict[str, Any] | None:
    if not ctx.has("time") or ctx.start is None or ctx.end is None:
        return None
    if ctx.kind == Format.ALB and ctx.has("elb_status_code"):
        bad, title, good_label, bad_label = (
            IS_5XX,
            "Requests against server errors (5xx)",
            "ok",
            "5xx",
        )
    elif ctx.kind == Format.NLB and ctx.has("handshake_ok"):
        bad, title, good_label, bad_label = (
            "NOT handshake_ok",
            "Completed connections against failed TLS handshakes",
            "completed",
            "failed handshake",
        )
    else:
        return None
    span_s = (ctx.end - ctx.start).total_seconds()
    name, secs = pick_bucket(span_s)
    rows = ctx.sql(
        f"""
        SELECT (epoch(time)::BIGINT // {secs}) * {secs} AS b,
               count(*) FILTER (WHERE NOT {bad}), count(*) FILTER (WHERE {bad})
        FROM lb WHERE time IS NOT NULL GROUP BY b ORDER BY b
        """
    )
    if not rows:
        return None
    first, last = int(rows[0][0]), int(rows[-1][0])
    by_bucket = {int(b): (int(g), int(r)) for b, g, r in rows}
    labels: list[str] = []
    good: list[int] = []
    failed: list[int] = []
    b = first
    while b <= last:
        g, r = by_bucket.get(b, (0, 0))
        labels.append(utc(b).strftime("%H:%M" if span_s < 86400 else "%m-%d %H:%M"))
        good.append(g)
        failed.append(r)
        b += secs
    return {
        "bucket": name,
        "labels": labels,
        "series": {"accepted": good, "rejected": failed},
        "title": title,
        "good": good_label,
        "bad": bad_label,
        "unit": ctx.unit,
    }


ALB_RULES = [
    rule_server_errors,
    rule_error_bursts,
    rule_failing_targets,
    rule_slow_requests,
    rule_client_errors,
    rule_probing,
    rule_tls_versions,
    rule_top_clients,
]
NLB_RULES = [
    rule_handshake_failures,
    rule_connection_churn,
    rule_tls_versions,
    rule_top_clients,
]


def run_rules(ds: Dataset) -> list[Finding]:
    ctx = make_context(ds)
    rules = ALB_RULES if ctx.kind == Format.ALB else NLB_RULES
    findings: list[Finding] = []
    for rule in rules:
        findings.extend(rule(ctx))
    return sort_findings(findings)


def build_timeline(ds: Dataset) -> dict[str, Any] | None:
    return timeline(make_context(ds))
