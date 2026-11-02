"""Building blocks the per-format cutover checks share: share changes and gone-or-new keys."""

from __future__ import annotations

from typing import Any

from logsift.cutover import DiffContext, Verdict

SHARE_REVIEW = 1.25  # the bad share grew by a quarter
SHARE_REGRESSION = 2.0  # ... or doubled
MIN_BAD = 20  # bad rows after, before a key is reported at all
MIN_ROWS = 20  # rows before (or after) for a key to count as present
MAX_ROWS = 20

# Extra columns for a key: (SQL expression, alias) pairs.
Extra = tuple[tuple[str, str], ...] | list[tuple[str, str]]


def extra_select(extra: Extra) -> str:
    return "".join(f", {expr} AS {alias}" for expr, alias in extra)


def share_changes(
    ctx: DiffContext,
    group: str,
    bad: str,
    *,
    ok: str = "TRUE",
    min_bad: int = MIN_BAD,
    extra: Extra = (),
) -> list[tuple[Any, ...]]:
    """Keys whose share of bad rows grew: (key, before rows, before bad, after rows, after bad).

    ``group`` is a SQL expression for the key, ``bad`` a boolean. Keys with fewer than
    ``min_bad`` bad rows after are left out, as are keys whose share did not grow by a
    quarter. ``extra`` adds (expression, alias) columns computed over the after rows.
    """
    extra_cols = "".join(f", after.{alias}" for _, alias in extra)
    rows = ctx.sql(
        f"""
        WITH before AS (
            SELECT {group} AS key, count(*) AS n, count(*) FILTER (WHERE {bad}) AS bad
            FROM b WHERE {ok} GROUP BY 1
        ), after AS (
            SELECT {group} AS key, count(*) AS n, count(*) FILTER (WHERE {bad}) AS bad
                   {extra_select(extra)}
            FROM a WHERE {ok} GROUP BY 1
        )
        SELECT after.key, coalesce(before.n, 0), coalesce(before.bad, 0), after.n, after.bad
               {extra_cols}
        FROM after LEFT JOIN before USING (key)
        WHERE after.bad >= {int(min_bad)}
          AND (coalesce(before.bad, 0) = 0
               OR after.bad / after.n >= {SHARE_REVIEW} * before.bad / before.n)
        ORDER BY after.bad DESC LIMIT {MAX_ROWS}
        """
    )
    return [tuple(r) for r in rows if r[0] is not None]


def share_verdict(before_n: int, before_bad: int, after_n: int, after_bad: int) -> Verdict:
    b_share = before_bad / before_n if before_n else 0.0
    a_share = after_bad / after_n if after_n else 0.0
    if after_bad < MIN_BAD:
        return Verdict.CLEAN
    if b_share == 0 or a_share >= SHARE_REGRESSION * b_share:
        return Verdict.REGRESSION
    if a_share >= SHARE_REVIEW * b_share:
        return Verdict.REVIEW
    return Verdict.CLEAN


def share(n_bad: int, n: int) -> str:
    return f"{100.0 * n_bad / n:.1f}%" if n else "0%"


def gone_and_new(
    ctx: DiffContext, group: str, *, ok: str = "TRUE", min_rows: int = MIN_ROWS, extra: Extra = ()
) -> tuple[list[tuple[Any, ...]], list[tuple[Any, ...]]]:
    """Keys with rows before and none after, and keys new after: (key, rows, ...extra)."""
    cols = "".join(f", {alias}" for _, alias in extra)
    sel = extra_select(extra)
    gone = ctx.sql(
        f"""
        WITH before AS (SELECT {group} AS key, count(*) AS n {sel} FROM b WHERE {ok} GROUP BY 1),
             after AS (SELECT DISTINCT {group} AS key FROM a WHERE {ok})
        SELECT key, n{cols} FROM before ANTI JOIN after USING (key)
        WHERE n >= {int(min_rows)} ORDER BY n DESC LIMIT {MAX_ROWS}
        """
    )
    new = ctx.sql(
        f"""
        WITH after AS (SELECT {group} AS key, count(*) AS n {sel} FROM a WHERE {ok} GROUP BY 1),
             before AS (SELECT DISTINCT {group} AS key FROM b WHERE {ok})
        SELECT key, n{cols} FROM after ANTI JOIN before USING (key)
        WHERE n >= {int(min_rows)} ORDER BY n DESC LIMIT {MAX_ROWS}
        """
    )
    return (
        [tuple(r) for r in gone if r[0] is not None],
        [tuple(r) for r in new if r[0] is not None],
    )


def sql_list(values: list[Any]) -> str:
    from logsift.sql import lit

    return ", ".join(lit(v) for v in values)
