"""Cutover checks for VPC Flow Logs: what changed between a before and an after file."""

from __future__ import annotations

from logsift.cutover import Change, DiffContext, Health, Verdict, describe_change, pct
from logsift.formats.vpcflow.table import protocol_name
from logsift.insights.base import Table, fmt_bytes, plural
from logsift.sql import lit

OK = "(log_status IS NULL OR log_status = 'OK')"
NEW_REJECT_MIN = 10  # rejected flows to a destination in the after window
NEW_REJECT_REGRESSION = 20  # ... that was accepted before: a regression
RETURN_PATH_MIN = 5  # requests whose replies are now rejected
GONE_MIN = 20  # accepted flows before, none after
TALKER_MIN_FLOWS = 20
TALKER_MIN_BYTES = 1024 * 1024
PAIR_TIME_WINDOW = 120
MAX_ROWS = 20


def flow_health(columns: set[str]) -> Health | None:
    if "action" not in columns:
        return None
    ok = OK if "log_status" in columns else "TRUE"
    return Health("action = 'REJECT'", "accepted", "rejected", "flows", ok)


def ok_for(ctx: DiffContext) -> str:
    return OK if ctx.has("log_status") else "TRUE"


def destination(dst: str, port: int | None, proto: int | None) -> str:
    return f"{dst}:{port} {protocol_name(proto)}" if port is not None else dst


def check_new_rejects(ctx: DiffContext) -> list[Change]:
    """Destinations rejecting traffic after that were not rejecting it before."""
    if not ctx.has("action", "dstaddr", "dstport", "protocol", "srcaddr"):
        return []
    ok = ok_for(ctx)
    rows = ctx.sql(
        f"""
        WITH after AS (
            SELECT dstaddr, dstport, protocol, count(*) AS n, count(DISTINCT srcaddr) AS sources
            FROM a WHERE {ok} AND action = 'REJECT' GROUP BY ALL
        ), before AS (
            SELECT dstaddr, dstport, protocol,
                   count(*) FILTER (WHERE action = 'REJECT') AS rejected,
                   count(*) FILTER (WHERE action = 'ACCEPT') AS accepted
            FROM b WHERE {ok} GROUP BY ALL
        )
        SELECT after.dstaddr, after.dstport, after.protocol, after.n, after.sources,
               coalesce(before.rejected, 0), coalesce(before.accepted, 0)
        FROM after LEFT JOIN before USING (dstaddr, dstport, protocol)
        WHERE after.n >= {NEW_REJECT_MIN}
          AND after.n >= 5 * coalesce(before.rejected, 0) + {NEW_REJECT_MIN}
        ORDER BY after.n DESC LIMIT {MAX_ROWS}
        """
    )
    if not rows:
        return [
            Change(
                "new-rejects",
                "new_rejects",
                "No destination started rejecting traffic",
                Verdict.CLEAN,
                "Every destination and port rejecting flows after was rejecting them at a "
                "similar rate before.",
                "A security group or network ACL change shows up here first: traffic that "
                "used to be accepted is refused at the same destination and port.",
                0,
                0,
                "flows",
            )
        ]
    total = sum(int(r[3]) for r in rows)
    was_accepted = [r for r in rows if int(r[6]) > 0]
    filters = [
        f"(dstaddr = {lit(d)} AND dstport = {lit(p)} AND protocol = {lit(pr)})"
        for d, p, pr, *_ in rows
    ]
    where = f"{ok} AND action = 'REJECT' AND (" + " OR ".join(filters) + ")"
    before_where = f"{ok} AND (" + " OR ".join(filters) + ")"
    regression = any(int(r[3]) >= NEW_REJECT_REGRESSION for r in was_accepted)
    worst = was_accepted[0] if was_accepted else rows[0]
    top = destination(worst[0], worst[1], worst[2])
    if was_accepted:
        detail = (
            f"{plural(len(was_accepted), 'destination')} that accepted this traffic before now "
            f"reject{'s' if len(was_accepted) == 1 else ''} it: {top} was accepted "
            f"{int(worst[6]):,} times before and rejected "
            f"{int(worst[3]):,} times after, from {plural(int(worst[4]), 'source')}."
        )
        cause = (
            "Traffic that was accepted before the cutover and is rejected after it at the same "
            "destination and port is the signature of a security group or network ACL that no "
            "longer allows it: a rule dropped, a reference to a group that was replaced, or a "
            "NACL rewritten by the change."
        )
    else:
        detail = (
            f"The destinations are new in this file ({top} and others), so this may be new "
            "traffic that was never allowed rather than a lost rule."
        )
        cause = (
            "Rejected flows to a destination the before file never saw mean either a new "
            "client or a new dependency that was never allowed; check whether something "
            "should be talking to it."
        )
    return [
        Change(
            "new-rejects",
            "new_rejects",
            f"New rejected traffic: {total:,} flows to {plural(len(rows), 'destination')} "
            "that were not rejected before",
            Verdict.REGRESSION if regression else Verdict.REVIEW,
            detail,
            cause,
            sum(int(r[5]) for r in rows),
            total,
            "flows",
            [
                Table(
                    "Destinations now rejecting",
                    [
                        "destination",
                        "port",
                        "protocol",
                        "rejected after",
                        "sources",
                        "rejected before",
                        "accepted before",
                    ],
                    [(d, p, protocol_name(pr), n, s, rb, ab) for d, p, pr, n, s, rb, ab in rows],
                )
            ],
            f"{before_where} AND {ctx.window('before')}",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def check_lost_return_paths(ctx: DiffContext) -> list[Change]:
    """Request accepted, reply rejected, for pairs that worked before."""
    needed = ["action", "srcaddr", "dstaddr", "srcport", "dstport", "protocol"]
    if not ctx.has(*needed):
        return []
    ok = ok_for(ctx)
    same_eni = "AND x.interface_id = y.interface_id" if ctx.has("interface_id") else ""
    time_ok = f"AND abs(x.start - y.start) <= {PAIR_TIME_WINDOW}" if ctx.has("start") else ""

    def pairs(side: str) -> str:
        return f"""
            SELECT x.srcaddr AS client, x.dstaddr AS server, x.dstport AS port, x.protocol,
                   count(DISTINCT x.row_no) AS requests
            FROM {side} x JOIN {side} y
              ON y.srcaddr = x.dstaddr AND y.dstaddr = x.srcaddr
             AND y.srcport = x.dstport AND y.dstport = x.srcport
             AND y.protocol = x.protocol {same_eni} {time_ok}
            WHERE x.action = 'ACCEPT' AND y.action = 'REJECT'
              AND ({ok.replace("log_status", "x.log_status")})
              AND ({ok.replace("log_status", "y.log_status")})
            GROUP BY ALL
        """

    rows = ctx.sql(
        f"""
        WITH after AS ({pairs("a")}), before AS ({pairs("b")}),
        worked AS (
            SELECT srcaddr AS client, dstaddr AS server, dstport AS port, protocol, count(*) AS n
            FROM b WHERE {ok} AND action = 'ACCEPT' GROUP BY ALL
        )
        SELECT after.client, after.server, after.port, after.protocol, after.requests,
               coalesce(before.requests, 0), coalesce(worked.n, 0)
        FROM after LEFT JOIN before USING (client, server, port, protocol)
        LEFT JOIN worked USING (client, server, port, protocol)
        WHERE after.requests >= {RETURN_PATH_MIN} AND coalesce(before.requests, 0) = 0
        ORDER BY after.requests DESC LIMIT {MAX_ROWS}
        """
    )
    if not rows:
        return [
            Change(
                "return-paths",
                "lost_return_paths",
                "No return path was lost",
                Verdict.CLEAN,
                "No connection that is accepted outbound has its reply rejected after when it "
                "was not already so before.",
                "A network ACL change is the usual way a return path breaks: the request leaves "
                "fine and the reply is refused on the ephemeral port.",
                0,
                0,
                "requests",
            )
        ]
    total = sum(int(r[4]) for r in rows)
    servers = sorted({f"{r[1]}:{r[2]}" for r in rows})
    filters = []
    for client, server, port, proto, *_ in rows:
        fwd = f"(srcaddr = {lit(client)} AND dstaddr = {lit(server)} AND dstport = {lit(port)})"
        rev = f"(srcaddr = {lit(server)} AND dstaddr = {lit(client)} AND srcport = {lit(port)})"
        filters.append(f"(({fwd} OR {rev}) AND protocol = {lit(proto)})")
    where = f"{ok} AND (" + " OR ".join(filters) + ")"
    worked = sum(int(r[6]) for r in rows)
    return [
        Change(
            "return-paths",
            "lost_return_paths",
            f"Lost return path: replies to {total:,} requests are now rejected "
            f"({', '.join(servers[:3])})",
            Verdict.REGRESSION if total >= 20 else Verdict.REVIEW,
            f"After the cutover, {plural(len(rows), 'client-server pair')} have their requests "
            f"accepted and the replies rejected on the same interface; before, "
            + (
                f"these pairs completed {worked:,} exchanges normally"
                if worked
                else "none of them showed this"
            )
            + ". The clients see hangs and timeouts.",
            "Security groups are stateful, network ACLs are not: once a NACL loses its inbound "
            "allow for the ephemeral port range (1024-65535), every reply is refused while "
            "every request still leaves. A NACL rewritten or replaced in the cutover is the "
            "thing to check first.",
            0,
            total,
            "requests",
            [
                Table(
                    "Pairs whose replies are rejected after",
                    ["client", "server", "port", "protocol", "requests after", "worked before"],
                    [(c, s, p, protocol_name(pr), n, w) for c, s, p, pr, n, _, w in rows],
                )
            ],
            f"{where} AND {ctx.window('before')}",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def check_disappeared(ctx: DiffContext) -> list[Change]:
    """Destinations that carried accepted traffic before and none after."""
    if not ctx.has("action", "dstaddr", "dstport", "protocol", "srcaddr"):
        return []
    ok = ok_for(ctx)
    bytes_col = "sum(bytes)" if ctx.has("bytes") else "0"
    rows = ctx.sql(
        f"""
        WITH before AS (
            SELECT dstaddr, dstport, protocol, count(*) AS n, {bytes_col} AS bytes,
                   count(DISTINCT srcaddr) AS sources, mode(srcaddr) AS top_source
            FROM b WHERE {ok} AND action = 'ACCEPT' GROUP BY ALL
        ), after AS (
            SELECT dstaddr, dstport, protocol, count(*) AS n FROM a WHERE {ok} GROUP BY ALL
        )
        SELECT before.dstaddr, before.dstport, before.protocol, before.n, before.bytes,
               before.sources, before.top_source
        FROM before LEFT JOIN after USING (dstaddr, dstport, protocol)
        WHERE before.n >= {GONE_MIN} AND coalesce(after.n, 0) = 0
        ORDER BY before.n DESC LIMIT {MAX_ROWS}
        """
    )
    if not rows:
        return [
            Change(
                "disappeared",
                "disappeared",
                "No destination lost its traffic",
                Verdict.CLEAN,
                "Every destination and port that carried accepted traffic before still sees "
                "traffic after.",
                "Traffic that stops entirely after a cutover is either the intended retirement "
                "of a path or a client that can no longer reach its dependency.",
                0,
                0,
                "flows",
            )
        ]
    total = sum(int(r[3]) for r in rows)
    filters = [
        f"(dstaddr = {lit(d)} AND dstport = {lit(p)} AND protocol = {lit(pr)})"
        for d, p, pr, *_ in rows
    ]
    where = f"{ok} AND action = 'ACCEPT' AND (" + " OR ".join(filters) + ")"
    top = rows[0]
    return [
        Change(
            "disappeared",
            "disappeared",
            f"Traffic that disappeared: {plural(len(rows), 'destination')} carried {total:,} "
            "flows before and none after",
            Verdict.REVIEW,
            f"{destination(top[0], top[1], top[2])} received {int(top[3]):,} accepted flows "
            f"({fmt_bytes(top[4])}) from {plural(int(top[5]), 'source')} in the before window "
            f"and nothing at all after; {top[6]} was its busiest client.",
            "If the path was retired on purpose this is the confirmation; if not, the clients "
            "have either been pointed elsewhere (look for a new destination under new "
            "talkers) or cannot connect at all (look under new rejected traffic and lost "
            "return paths). Silence is not the same as success.",
            total,
            0,
            "flows",
            [
                Table(
                    "Destinations with no traffic after",
                    [
                        "destination",
                        "port",
                        "protocol",
                        "flows before",
                        "bytes before",
                        "sources",
                        "top source",
                    ],
                    [(d, p, protocol_name(pr), n, by, s, t) for d, p, pr, n, by, s, t in rows],
                )
            ],
            f"{where} AND {ctx.window('before')}",
            "",
            evidence="before",
            rows=ctx.count("before", where),
        )
    ]


def check_new_talkers(ctx: DiffContext) -> list[Change]:
    """Sources sending accepted traffic after that sent none before."""
    if not ctx.has("action", "srcaddr", "dstaddr"):
        return []
    ok = ok_for(ctx)
    bytes_col = "sum(bytes)" if ctx.has("bytes") else "0"
    port = "dstport" if ctx.has("dstport") else "NULL"
    rows = ctx.sql(
        f"""
        WITH after AS (
            SELECT srcaddr, count(*) AS n, {bytes_col} AS bytes,
                   count(DISTINCT dstaddr) AS destinations,
                   mode(dstaddr || ':' || coalesce(cast({port} AS VARCHAR), '?')) AS top_destination
            FROM a WHERE {ok} AND action = 'ACCEPT' GROUP BY 1
        ), before AS (SELECT DISTINCT srcaddr FROM b WHERE {ok})
        SELECT after.* FROM after ANTI JOIN before USING (srcaddr)
        WHERE after.n >= {TALKER_MIN_FLOWS} OR after.bytes >= {TALKER_MIN_BYTES}
        ORDER BY after.bytes DESC, after.n DESC LIMIT {MAX_ROWS}
        """
    )
    if not rows:
        return [
            Change(
                "new-talkers",
                "new_talkers",
                "No new talkers",
                Verdict.CLEAN,
                "Every source sending a meaningful amount of traffic after was already seen "
                "before.",
                "A new source address after a cutover is a new instance, a new NAT path or "
                "something that should not be there.",
                0,
                0,
                "flows",
            )
        ]
    total = sum(int(r[1]) for r in rows)
    total_bytes = sum(int(r[2]) for r in rows)
    where = f"{ok} AND srcaddr IN ({', '.join(lit(r[0]) for r in rows)})"
    top = rows[0]
    public = [r for r in rows if not str(r[0]).startswith(("10.", "172.", "192.168."))]
    return [
        Change(
            "new-talkers",
            "new_talkers",
            f"New talkers: {plural(len(rows), 'source')} not seen before sent {total:,} flows "
            f"({fmt_bytes(total_bytes)})",
            Verdict.REVIEW,
            f"{top[0]} is the biggest, with {int(top[1]):,} accepted flows and "
            f"{fmt_bytes(top[2])} to {plural(int(top[3]), 'destination')}, mostly "
            f"{top[4]}."
            + (
                f" {plural(len(public), 'of them is' if len(public) == 1 else 'of them are')} "
                "public addresses."
                if public
                else ""
            ),
            "New private sources are usually the instances the cutover brought up (check they "
            "are the expected ones and that their traffic replaces, not duplicates, the old "
            "hosts'); a new public source talking into the VPC deserves a closer look.",
            0,
            total,
            "flows",
            [
                Table(
                    "Sources new in the after window",
                    ["source", "flows", "bytes", "destinations", "top destination"],
                    [(s, n, by, d, t) for s, n, by, d, t in rows],
                )
            ],
            "",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def flow_cutover_checks(ctx: DiffContext) -> list[Change]:
    changes: list[Change] = []
    changes += check_new_rejects(ctx)
    changes += check_lost_return_paths(ctx)
    changes += check_disappeared(ctx)
    changes += check_new_talkers(ctx)
    return changes


__all__ = ["describe_change", "flow_cutover_checks", "flow_health", "pct"]
