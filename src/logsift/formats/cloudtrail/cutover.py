"""Cutover checks for CloudTrail event exports."""

from __future__ import annotations

from logsift.cutover import Change, DiffContext, Health, Verdict, worst
from logsift.cutover_checks import gone_and_new, share, share_changes, share_verdict, sql_list
from logsift.insights.base import Table, plural
from logsift.sql import lit

DENIED_MIN = 5
DENIED_REGRESSION = 20
MAX_ROWS = 20


def trail_health(columns: set[str]) -> Health | None:
    if "error_code" not in columns:
        return None
    return Health("error_code IS NOT NULL", "succeeded", "failed", "calls")


def check_new_denials(ctx: DiffContext) -> list[Change]:
    """Principal and action pairs refused after that were not refused before."""
    if not ctx.has("access_denied", "principal", "event_name", "service"):
        return []
    rows = ctx.sql(
        f"""
        WITH after AS (
            SELECT principal, service || ':' || event_name AS action, count(*) AS n,
                   count(*) FILTER (WHERE NOT access_denied) AS allowed
            FROM a WHERE access_denied GROUP BY ALL
        ), before AS (
            SELECT principal, service || ':' || event_name AS action,
                   count(*) FILTER (WHERE access_denied) AS denied,
                   count(*) FILTER (WHERE NOT access_denied) AS allowed
            FROM b GROUP BY ALL
        )
        SELECT after.principal, after.action, after.n, coalesce(before.denied, 0),
               coalesce(before.allowed, 0)
        FROM after LEFT JOIN before USING (principal, action)
        WHERE after.n >= {DENIED_MIN} AND after.n >= 5 * coalesce(before.denied, 0) + {DENIED_MIN}
        ORDER BY after.n DESC LIMIT {MAX_ROWS}
        """
    )
    if not rows:
        return [
            Change(
                "new-denials",
                "new_denials",
                "No principal is newly refused an action",
                Verdict.CLEAN,
                "Every principal and action refused after was refused at a similar rate before.",
                "A policy or role change in the cutover shows up as a principal refused an "
                "action it used to be allowed.",
                0,
                0,
                "calls",
            )
        ]
    total = sum(int(r[2]) for r in rows)
    worked = [r for r in rows if int(r[4]) > 0]
    top = worked[0] if worked else rows[0]
    pairs = " OR ".join(
        f"(principal = {lit(p)} AND service || ':' || event_name = {lit(a)})" for p, a, *_ in rows
    )
    where = f"access_denied AND ({pairs})"
    regression = any(int(r[2]) >= DENIED_REGRESSION for r in worked)
    return [
        Change(
            "new-denials",
            "new_denials",
            f"New access denied: {total:,} refusals across "
            f"{plural(len(rows), 'principal and action pair')} not refused before",
            Verdict.REGRESSION if regression else Verdict.REVIEW,
            f"{top[0]} is refused {top[1]} {int(top[2]):,} times after"
            + (
                f", having been allowed it {int(top[4]):,} times before."
                if int(top[4])
                else ", an action it did not call before."
            ),
            "A principal refused an action it was allowed before the cutover points at a "
            "policy, role or permission boundary that changed with it: a managed policy "
            "replaced, a role recreated without an attachment, or a resource policy that "
            "names the old role.",
            sum(int(r[3]) for r in rows),
            total,
            "calls",
            [
                Table(
                    "Refused after",
                    ["principal", "action", "refused after", "refused before", "allowed before"],
                    rows,
                )
            ],
            f"{where} AND {ctx.window('before')}",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def check_service_errors(ctx: DiffContext) -> list[Change]:
    """Error share per service."""
    if not ctx.has("service", "error_code"):
        return []
    rows = share_changes(
        ctx, "service", "error_code IS NOT NULL", extra=[("mode(error_code)", "top_error")]
    )
    if not rows:
        return [
            Change(
                "service-errors",
                "service_errors",
                "No service returns more errors than before",
                Verdict.CLEAN,
                "Every service's share of failed calls after is within a quarter of its share "
                "before, or below 20 errors.",
                "Errors from one service after a cutover are usually the new code calling it "
                "differently, or a quota or permission the new hosts lack.",
                0,
                0,
                "calls",
            )
        ]
    verdict = worst([share_verdict(int(r[1]), int(r[2]), int(r[3]), int(r[4])) for r in rows])
    key, b_n, b_bad, a_n, a_bad, top_error = rows[0]
    where = f"error_code IS NOT NULL AND service IN ({sql_list([r[0] for r in rows])})"
    return [
        Change(
            "service-errors",
            "service_errors",
            f"Errors per service: {key} fails {share(a_bad, a_n)} of calls after, "
            f"{share(b_bad, b_n)} before",
            verdict,
            f"{plural(len(rows), 'service')} return{'s' if len(rows) == 1 else ''} more errors "
            f"after; {key} failed "
            f"{int(a_bad):,} of {int(a_n):,} calls after ({top_error} most often) against "
            f"{int(b_bad):,} of {int(b_n):,} before.",
            "The error code says which kind: AccessDenied is a permission, Throttling a "
            "quota, a validation error the new code's request shape.",
            sum(int(r[2]) for r in rows),
            sum(int(r[4]) for r in rows),
            "calls",
            [
                Table(
                    "Services with a higher error share after",
                    [
                        "service",
                        "calls before",
                        "errors before",
                        "calls after",
                        "errors after",
                        "top error",
                    ],
                    rows,
                )
            ],
            f"{where} AND {ctx.window('before')}",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def check_principals_changed(ctx: DiffContext) -> list[Change]:
    """Principals gone and principals new."""
    if not ctx.has("principal"):
        return []
    writes: list[tuple[str, str]] = (
        [("count(*) FILTER (WHERE NOT coalesce(read_only, true))", "writes")]
        if ctx.has("read_only")
        else []
    )
    gone, new = gone_and_new(ctx, "principal", min_rows=10, extra=writes)
    if not gone and not new:
        return [
            Change(
                "principals",
                "principals_changed",
                "The same principals are active before and after",
                Verdict.CLEAN,
                "No principal with meaningful activity before has gone quiet, and no new "
                "principal is active after.",
                "A cutover that swaps roles shows up as a principal gone and a principal new.",
                0,
                0,
                "calls",
            )
        ]
    parts = []
    if gone:
        parts.append(
            f"{plural(len(gone), 'principal')} gone ({', '.join(str(r[0]) for r in gone[:3])})"
        )
    if new:
        parts.append(
            f"{plural(len(new), 'principal')} new ({', '.join(str(r[0]) for r in new[:3])})"
        )
    cols = ["principal", "calls"] + (["writes"] if writes else [])
    tables = []
    if gone:
        tables.append(Table("Principals with no calls after", cols, gone))
    if new:
        tables.append(Table("Principals new after", cols, new))
    before_where = f"principal IN ({sql_list([r[0] for r in gone])})" if gone else ""
    after_where = f"principal IN ({sql_list([r[0] for r in new])})" if new else ""
    return [
        Change(
            "principals",
            "principals_changed",
            "Principals changed: " + "; ".join(parts),
            Verdict.REVIEW,
            "Expected when the cutover replaced a role or an instance profile; check that the "
            "new principals are the intended ones and that the old ones are not still needed "
            "somewhere.",
            "Principals are the user or role name behind each call, with role sessions grouped "
            "under their role.",
            sum(int(r[1]) for r in gone),
            sum(int(r[1]) for r in new),
            "calls",
            tables,
            f"{before_where} AND {ctx.window('before')}" if before_where else "",
            f"{after_where} AND {ctx.window('after')}" if after_where else "",
            evidence="after" if new else "before",
            rows=ctx.count("after", after_where) if new else ctx.count("before", before_where),
        )
    ]


def check_new_regions(ctx: DiffContext) -> list[Change]:
    """Regions active after that had no calls before."""
    if not ctx.has("aws_region", "global_service"):
        return []
    _, new = gone_and_new(
        ctx,
        "aws_region",
        ok="NOT global_service AND aws_region IS NOT NULL",
        min_rows=5,
        extra=[("count(DISTINCT principal)", "principals"), ("mode(event_name)", "top_event")],
    )
    if not new:
        return [
            Change(
                "regions",
                "new_regions",
                "No new regions",
                Verdict.CLEAN,
                "Every region with regional calls after already had calls before.",
                "Activity in a region that was quiet before a cutover is either the planned "
                "expansion or someone's mistake.",
                0,
                0,
                "calls",
            )
        ]
    where = f"NOT global_service AND aws_region IN ({sql_list([r[0] for r in new])})"
    total = sum(int(r[1]) for r in new)
    return [
        Change(
            "regions",
            "new_regions",
            f"New regions: {', '.join(str(r[0]) for r in new)} with {total:,} calls after and "
            "none before",
            Verdict.REVIEW,
            f"{new[0][0]} saw {int(new[0][1]):,} calls from {plural(int(new[0][2]), 'principal')}, "
            f"most often {new[0][3]}.",
            "If the cutover did not include this region, something is creating or reading "
            "resources where nobody is looking.",
            0,
            total,
            "calls",
            [Table("Regions new after", ["region", "calls", "principals", "top event"], new)],
            "",
            f"{where} AND {ctx.window('after')}",
            rows=ctx.count("after", where),
        )
    ]


def trail_cutover_checks(ctx: DiffContext) -> list[Change]:
    changes: list[Change] = []
    changes += check_new_denials(ctx)
    changes += check_service_errors(ctx)
    changes += check_principals_changed(ctx)
    changes += check_new_regions(ctx)
    return changes
