"""Cutover checks for Route 53 Resolver query logs."""

from __future__ import annotations

from logsift.cutover import Change, DiffContext, Health, Verdict
from logsift.cutover_checks import MIN_BAD, gone_and_new, sql_list
from logsift.insights.base import Table, plural
from logsift.sql import lit

FAILURE_CODES = ("NXDOMAIN", "SERVFAIL", "REFUSED")
NEW_FAILURE_REGRESSION = 100  # new NXDOMAIN for one domain; any SERVFAIL run is one
MAX_ROWS = 20


def dns_health(columns: set[str]) -> Health | None:
    if "is_error" not in columns:
        return None
    bad = "is_error OR blocked" if "blocked" in columns else "is_error"
    return Health(bad, "answered", "failed or blocked", "queries")


def check_new_failures(ctx: DiffContext) -> list[Change]:
    """Domains failing (NXDOMAIN, SERVFAIL, REFUSED) after that did not fail before."""
    if not ctx.has("domain", "rcode", "srcaddr"):
        return []
    codes = sql_list(list(FAILURE_CODES))
    blocked = "AND NOT blocked" if ctx.has("blocked") else ""
    rows = ctx.sql(
        f"""
        WITH after AS (
            SELECT domain, rcode, count(*) AS n, count(DISTINCT srcaddr) AS hosts,
                   mode(query_name) AS example
            FROM a WHERE rcode IN ({codes}) {blocked} GROUP BY ALL
        ), before AS (
            SELECT domain, rcode, count(*) AS n FROM b WHERE rcode IN ({codes}) {blocked}
            GROUP BY ALL
        )
        SELECT after.domain, after.rcode, coalesce(before.n, 0), after.n, after.hosts,
               after.example
        FROM after LEFT JOIN before USING (domain, rcode)
        WHERE after.n >= {MIN_BAD} AND after.n >= 5 * coalesce(before.n, 0) + {MIN_BAD}
        ORDER BY after.n DESC LIMIT {MAX_ROWS}
        """
    )
    if not rows:
        return [
            Change(
                "new-failures",
                "new_failures",
                "No domain started failing to resolve",
                Verdict.CLEAN,
                "No domain gets NXDOMAIN, SERVFAIL or REFUSED after at a rate it did not before.",
                "A zone that stopped resolving, a forwarding rule that broke or a name the new "
                "build asks for that does not exist all show up here first.",
                0,
                0,
                "queries",
            )
        ]
    regression = any(r[1] == "SERVFAIL" or int(r[3]) >= NEW_FAILURE_REGRESSION for r in rows)
    top = rows[0]
    pairs = " OR ".join(f"(domain = {lit(d)} AND rcode = {lit(c)})" for d, c, *_ in rows)
    where = f"({pairs}) {blocked}"
    total = sum(int(r[3]) for r in rows)
    return [
        Change(
            "new-failures",
            "new_failures",
            f"New failures: {total:,} {top[1]} and other answers for "
            f"{plural(len({r[0] for r in rows}), 'domain')} that resolved before",
            Verdict.REGRESSION if regression else Verdict.REVIEW,
            f"{top[0]} got {int(top[3]):,} {top[1]} answers after ({int(top[2]):,} before) "
            f"from {plural(int(top[4]), 'host')}, for names like {top[5]}.",
            "SERVFAIL after a cutover is a resolver that can no longer reach the zone's "
            "servers (a forwarding rule, an outbound endpoint, a security group); NXDOMAIN is "
            "a name that no longer exists or a client asking for one it never should, such as "
            "a stale search suffix on the new hosts.",
            sum(int(r[2]) for r in rows),
            total,
            "queries",
            [
                Table(
                    "Domains failing after",
                    ["domain", "rcode", "before", "after", "hosts", "example name"],
                    rows,
                )
            ],
            f"{where} AND {ctx.window('before')}",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def check_names_disappeared(ctx: DiffContext) -> list[Change]:
    """Domains the fleet asked for before and never after."""
    if not ctx.has("domain"):
        return []
    gone, _ = gone_and_new(ctx, "domain", extra=[("count(DISTINCT srcaddr)", "hosts")])
    if not gone:
        return [
            Change(
                "names-gone",
                "names_disappeared",
                "Every domain asked for before is still asked for",
                Verdict.CLEAN,
                "No domain with meaningful query volume before has disappeared from the "
                "after window.",
                "A dependency that is no longer looked up is either retired on purpose or no "
                "longer called at all.",
                0,
                0,
                "queries",
            )
        ]
    where = f"domain IN ({sql_list([r[0] for r in gone])})"
    total = sum(int(r[1]) for r in gone)
    return [
        Change(
            "names-gone",
            "names_disappeared",
            f"Names that disappeared: {plural(len(gone), 'domain')} with {total:,} queries "
            "before and none after",
            Verdict.REVIEW,
            f"{gone[0][0]} was asked for {int(gone[0][1]):,} times by "
            f"{plural(int(gone[0][2]), 'host')} before and never after.",
            "If the cutover retired the dependency this confirms it; if the new hosts should "
            "still be calling it, they are not, which is worth a look before anyone notices.",
            total,
            0,
            "queries",
            [Table("Domains with no queries after", ["domain", "queries before", "hosts"], gone)],
            f"{where} AND {ctx.window('before')}",
            "",
            evidence="before",
            rows=ctx.count("before", where),
        )
    ]


def check_new_talkers(ctx: DiffContext) -> list[Change]:
    """Clients that resolve names after and did not exist before."""
    if not ctx.has("srcaddr"):
        return []
    _, new = gone_and_new(
        ctx,
        "srcaddr",
        extra=[("count(DISTINCT query_name)", "names"), ("mode(query_name)", "top")],
    )
    if not new:
        return [
            Change(
                "new-talkers",
                "new_talkers",
                "No new clients",
                Verdict.CLEAN,
                "Every host sending a meaningful number of queries after was already seen before.",
                "A new client address after a cutover is a new instance, or something that "
                "should not be resolving names in this VPC.",
                0,
                0,
                "queries",
            )
        ]
    where = f"srcaddr IN ({sql_list([r[0] for r in new])})"
    total = sum(int(r[1]) for r in new)
    return [
        Change(
            "new-talkers",
            "new_talkers",
            f"New clients: {plural(len(new), 'host')} not seen before sent {total:,} queries",
            Verdict.REVIEW,
            f"{new[0][0]} is the busiest, with {int(new[0][1]):,} queries for "
            f"{plural(int(new[0][2]), 'name')}, most often {new[0][3]}.",
            "New private clients are usually the instances the cutover brought up; check that "
            "what they ask for matches what the old hosts asked for.",
            0,
            total,
            "queries",
            [Table("Clients new after", ["address", "queries", "names", "top name"], new)],
            "",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def check_blocked(ctx: DiffContext) -> list[Change]:
    """DNS Firewall blocks that are new."""
    if not ctx.has("blocked", "query_name"):
        return []
    b_n, a_n = ctx.count("before", "blocked"), ctx.count("after", "blocked")
    if a_n == 0:
        return [
            Change(
                "blocked",
                "blocked",
                "No DNS Firewall blocks after" + (f" ({b_n:,} before)" if b_n else ""),
                Verdict.CLEAN,
                "Nothing asked for a blocked name in the after window.",
                "DNS Firewall blocks after a cutover mean a new host is asking for something "
                "on a block list.",
                b_n,
                0,
                "queries",
            )
        ]
    by_name = ctx.sql(
        "SELECT query_name, count(*), count(DISTINCT srcaddr) FROM a WHERE blocked "
        f"GROUP BY 1 ORDER BY 2 DESC LIMIT {MAX_ROWS}"
    )
    new_names = ctx.sql(
        "SELECT query_name FROM a WHERE blocked AND query_name NOT IN "
        "(SELECT query_name FROM b WHERE blocked) GROUP BY 1"
    )
    if b_n and not new_names:
        verdict = Verdict.CLEAN
        note = "The same names were blocked before, so nothing new is asking."
    else:
        verdict = Verdict.REGRESSION if a_n >= MIN_BAD else Verdict.REVIEW
        note = f"{plural(len(new_names), 'blocked name')} not seen before."
    return [
        Change(
            "blocked",
            "blocked",
            f"DNS Firewall blocked {a_n:,} queries after, {b_n:,} before",
            verdict,
            f"{by_name[0][0]} was blocked {int(by_name[0][1]):,} times from "
            f"{plural(int(by_name[0][2]), 'host')}. {note}",
            "A block list hit from a new host is the new host carrying whatever the old one "
            "had, or something that came with the new image.",
            b_n,
            a_n,
            "queries",
            [Table("Blocked names after", ["name", "queries", "hosts"], by_name)],
            f"blocked AND {ctx.window('before')}",
            f"blocked AND {ctx.window('after')}",
            rows=a_n,
        )
    ]


def dns_cutover_checks(ctx: DiffContext) -> list[Change]:
    changes: list[Change] = []
    changes += check_new_failures(ctx)
    changes += check_blocked(ctx)
    changes += check_names_disappeared(ctx)
    changes += check_new_talkers(ctx)
    return changes
