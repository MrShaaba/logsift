"""Cutover checks for ALB and NLB access logs."""

from __future__ import annotations

from logsift.cutover import Change, DiffContext, Health, Verdict, describe_change, worst
from logsift.cutover_checks import gone_and_new, share, share_changes, share_verdict, sql_list
from logsift.insights.base import Table, plural
from logsift.sql import lit

SLOW_REVIEW = 2.0  # p95 target time doubled ...
SLOW_MIN_SECONDS = 0.5  # ... and is at least this long after


def lb_health(columns: set[str]) -> Health | None:
    if "elb_status_code" in columns:
        return Health("elb_status_code >= 500", "ok", "5xx", "requests")
    if "handshake_ok" in columns:
        return Health("NOT handshake_ok", "completed", "failed", "connections")
    return None


TARGET = "target_ip || ':' || cast(target_port AS VARCHAR)"
DESTINATION = "destination_ip || ':' || cast(destination_port AS VARCHAR)"


def check_target_errors(ctx: DiffContext) -> list[Change]:
    """5xx per target: a target that fails more of its requests after the cutover."""
    if not ctx.has("elb_status_code", "target_ip", "target_port"):
        return []
    rows = share_changes(ctx, TARGET, "elb_status_code >= 500", extra=[("mode(path)", "top_path")])
    if not rows:
        return [
            Change(
                "target-errors",
                "target_errors",
                "No target fails more of its requests than before",
                Verdict.CLEAN,
                "Every target's share of 5xx responses after is within a quarter of its share "
                "before, or below 20 errors.",
                "A target that starts failing after a deploy is the thing a cutover report "
                "exists to catch; the health check often keeps passing while real requests fail.",
                0,
                0,
                "requests",
            )
        ]
    verdict = worst([share_verdict(int(r[1]), int(r[2]), int(r[3]), int(r[4])) for r in rows])
    key, b_n, b_bad, a_n, a_bad, top_path = rows[0]
    targets = [r[0] for r in rows]
    where = f"elb_status_code >= 500 AND ({TARGET}) IN ({sql_list(targets)})"
    total_after = sum(int(r[4]) for r in rows)
    total_before = sum(int(r[2]) for r in rows)
    return [
        Change(
            "target-errors",
            "target_errors",
            f"5xx per target: {key} fails {share(a_bad, a_n)} of its requests after, "
            f"{share(b_bad, b_n)} before",
            verdict,
            f"{plural(len(rows), 'target')} fail{'s' if len(rows) == 1 else ''} more of "
            f"{'its' if len(rows) == 1 else 'their'} requests after the cutover. "
            f"{key} answered {int(a_bad):,} of {int(a_n):,} requests with a 5xx after "
            f"({share(a_bad, a_n)}) against {int(b_bad):,} of {int(b_n):,} before "
            f"({share(b_bad, b_n)}); its most common path was {top_path}.",
            "A target whose 5xx share doubles after a change is failing requests the health "
            "check does not exercise: a dependency the new build cannot reach, a config "
            "difference between the old and new instances, or a target group pointed at "
            "the wrong port. The load balancer keeps sending it traffic as long as the "
            "health check passes.",
            total_before,
            total_after,
            "requests",
            [
                Table(
                    "Targets with a higher 5xx share after",
                    [
                        "target",
                        "requests before",
                        "5xx before",
                        "share before",
                        "requests after",
                        "5xx after",
                        "share after",
                        "top path",
                    ],
                    [
                        (k, bn, bb, share(bb, bn), an, ab, share(ab, an), tp)
                        for k, bn, bb, an, ab, tp in rows
                    ],
                )
            ],
            f"{where} AND {ctx.window('before')}",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def check_path_errors(ctx: DiffContext) -> list[Change]:
    """5xx per path, for errors that follow the request rather than the target."""
    if not ctx.has("elb_status_code", "path"):
        return []
    rows = share_changes(ctx, "path", "elb_status_code >= 500")
    if not rows:
        return []
    verdict = worst([share_verdict(int(r[1]), int(r[2]), int(r[3]), int(r[4])) for r in rows])
    key, b_n, b_bad, a_n, a_bad = rows[0]
    where = f"elb_status_code >= 500 AND path IN ({sql_list([r[0] for r in rows])})"
    return [
        Change(
            "path-errors",
            "path_errors",
            f"5xx per path: {key} fails {share(a_bad, a_n)} after, {share(b_bad, b_n)} before",
            verdict,
            f"{plural(len(rows), 'path')} return{'s' if len(rows) == 1 else ''} more 5xx after "
            f"the cutover; {key} answered "
            f"{int(a_bad):,} of {int(a_n):,} requests with a 5xx after against {int(b_bad):,} "
            f"of {int(b_n):,} before.",
            "When the failing requests share a path rather than a target, the new code path "
            "behind that route is the suspect: a handler, a query or an upstream call that "
            "changed with the release.",
            sum(int(r[2]) for r in rows),
            sum(int(r[4]) for r in rows),
            "requests",
            [
                Table(
                    "Paths with a higher 5xx share after",
                    ["path", "requests before", "5xx before", "requests after", "5xx after"],
                    rows,
                )
            ],
            f"{where} AND {ctx.window('before')}",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def check_targets_changed(ctx: DiffContext) -> list[Change]:
    """Targets that stopped receiving traffic, and targets that are new."""
    group = TARGET if ctx.has("target_ip", "target_port") else ""
    unit = "requests"
    if not group and ctx.has("destination_ip", "destination_port"):
        group, unit = DESTINATION, "connections"
    if not group:
        return []
    gone, new = gone_and_new(ctx, group)
    if not gone and not new:
        return [
            Change(
                "targets",
                "targets_changed",
                "The same targets serve traffic before and after",
                Verdict.CLEAN,
                "No target with meaningful traffic before has disappeared, and no new target "
                "carries meaningful traffic after.",
                "A cutover that replaces instances shows up here as targets gone and targets "
                "new; the 5xx check says whether the new ones are healthy.",
                0,
                0,
                unit,
            )
        ]
    parts = []
    if gone:
        parts.append(
            f"{plural(len(gone), 'target')} that served {sum(int(r[1]) for r in gone):,} {unit} "
            f"before serve nothing after ({', '.join(str(r[0]) for r in gone[:3])})"
        )
    if new:
        parts.append(
            f"{plural(len(new), 'new target')} serve {sum(int(r[1]) for r in new):,} {unit} "
            f"after ({', '.join(str(r[0]) for r in new[:3])})"
        )
    tables = []
    if gone:
        tables.append(Table("Targets with no traffic after", ["target", f"{unit} before"], gone))
    if new:
        tables.append(Table("Targets new after", ["target", f"{unit} after"], new))
    before_where = f"({group}) IN ({sql_list([r[0] for r in gone])})" if gone else ""
    after_where = f"({group}) IN ({sql_list([r[0] for r in new])})" if new else ""
    evidence = "after" if new else "before"
    return [
        Change(
            "targets",
            "targets_changed",
            "Targets changed: " + "; ".join(parts),
            Verdict.REVIEW,
            "If the cutover replaced the instances this is expected; check that the new "
            "targets took over the whole load and that nothing still points at the old ones.",
            "Targets are matched by address and port, so a replaced instance is a target gone "
            "plus a target new.",
            sum(int(r[1]) for r in gone),
            sum(int(r[1]) for r in new),
            unit,
            tables,
            f"{before_where} AND {ctx.window('before')}" if before_where else "",
            f"{after_where} AND {ctx.window('after')}" if after_where else "",
            evidence=evidence,
            rows=ctx.count("after", after_where) if new else ctx.count("before", before_where),
        )
    ]


def check_latency(ctx: DiffContext) -> list[Change]:
    """p95 target processing time before against after."""
    if not ctx.has("target_processing_time"):
        return []
    (b_p95,) = ctx.one(
        "SELECT quantile_cont(target_processing_time, 0.95) FROM b "
        "WHERE target_processing_time >= 0"
    ) or (None,)
    (a_p95,) = ctx.one(
        "SELECT quantile_cont(target_processing_time, 0.95) FROM a "
        "WHERE target_processing_time >= 0"
    ) or (None,)
    if b_p95 is None or a_p95 is None:
        return []
    b_p95, a_p95 = float(b_p95), float(a_p95)
    slow = a_p95 >= SLOW_MIN_SECONDS and a_p95 >= SLOW_REVIEW * max(b_p95, 0.001)
    by_path = (
        ctx.sql(
            "SELECT path, count(*), round(quantile_cont(target_processing_time, 0.95), 3) FROM a "
            "WHERE target_processing_time >= 0 GROUP BY 1 HAVING count(*) >= 10 "
            "ORDER BY 3 DESC LIMIT 10"
        )
        if ctx.has("path")
        else []
    )
    where = f"target_processing_time >= {lit(round(a_p95, 3))}"
    return [
        Change(
            "latency",
            "latency",
            f"Target time p95: {a_p95:.2f} s after, {b_p95:.2f} s before "
            f"({describe_change(b_p95, a_p95)})",
            Verdict.REVIEW if slow else Verdict.CLEAN,
            (
                "The slowest five percent of requests take twice as long as before; the paths "
                "below carry most of it."
                if slow
                else "The slow tail of requests is about where it was."
            ),
            "Target processing time is what the target took to answer, excluding the load "
            "balancer's own work, so a change here is the application's.",
            round(b_p95, 3),
            round(a_p95, 3),
            "seconds",
            [Table("Slowest paths after (p95)", ["path", "requests", "p95 seconds"], by_path)]
            if by_path
            else [],
            "",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def check_handshakes(ctx: DiffContext) -> list[Change]:
    """NLB: failed TLS handshakes per destination."""
    if not ctx.has("handshake_ok", "destination_ip", "destination_port"):
        return []
    rows = share_changes(ctx, DESTINATION, "NOT handshake_ok")
    if not rows:
        return [
            Change(
                "handshakes",
                "handshake_failures",
                "No destination fails more handshakes than before",
                Verdict.CLEAN,
                "Every destination's share of failed TLS handshakes after is within a quarter "
                "of its share before, or below 20 failures.",
                "A certificate or policy change in the cutover shows up as handshakes that "
                "used to complete and no longer do.",
                0,
                0,
                "connections",
            )
        ]
    verdict = worst([share_verdict(int(r[1]), int(r[2]), int(r[3]), int(r[4])) for r in rows])
    key, b_n, b_bad, a_n, a_bad = rows[0]
    where = f"NOT handshake_ok AND ({DESTINATION}) IN ({sql_list([r[0] for r in rows])})"
    return [
        Change(
            "handshakes",
            "handshake_failures",
            f"Failed handshakes: {key} fails {share(a_bad, a_n)} after, {share(b_bad, b_n)} before",
            verdict,
            f"{plural(len(rows), 'destination')} fail{'s' if len(rows) == 1 else ''} more TLS "
            "handshakes after the cutover; "
            f"{key} failed {int(a_bad):,} of {int(a_n):,} after against {int(b_bad):,} of "
            f"{int(b_n):,} before.",
            "Clients that completed handshakes before and fail them after were broken by the "
            "change: a certificate they do not trust, a TLS version or cipher the new policy "
            "dropped, or a listener that no longer offers their protocol.",
            sum(int(r[2]) for r in rows),
            sum(int(r[4]) for r in rows),
            "connections",
            [
                Table(
                    "Destinations with more failed handshakes after",
                    ["destination", "before", "failed before", "after", "failed after"],
                    rows,
                )
            ],
            f"{where} AND {ctx.window('before')}",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def lb_cutover_checks(ctx: DiffContext) -> list[Change]:
    changes: list[Change] = []
    changes += check_target_errors(ctx)
    changes += check_path_errors(ctx)
    changes += check_handshakes(ctx)
    changes += check_targets_changed(ctx)
    changes += check_latency(ctx)
    return changes
