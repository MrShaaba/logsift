"""Rule-based findings for CloudTrail event exports.

Every rule is plain SQL over the ``trail`` table built by ``logsift.trail``. One row is
one API call or console sign-in, so the rules talk about principals, actions, regions and
error codes. Thresholds are simple and written next to each rule.
"""

from __future__ import annotations

import re
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
    utc,
)
from logsift.sql import lit

if TYPE_CHECKING:
    from logsift.dataset import Dataset

ACTION = "service || ':' || event_name"
MUTATING = "NOT coalesce(read_only, true)"  # unknown read_only counts as not a change

DENIED_PER_MINUTE = 5  # refusals in one minute from one principal before the minute is hot
DENIED_BURST_MIN = 30  # refusals in a run of hot minutes before the run is reported
DENIED_GAP_MINUTES = 2  # hot minutes this close together are one run
ENUMERATION_MIN_ACTIONS = 8  # distinct refused actions in a run: looks like testing a key
NORMAL_REGION_SHARE = 0.05  # a region with at least this share of regional calls is usual
MAX_PER_RULE = 5


@dataclass
class Context:
    con: duckdb.DuckDBPyConnection
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
        return int(self.one(f"SELECT count(*) FROM trail WHERE {where}")[0])

    def share(self, n: int, of: int | None = None) -> str:
        of = self.total if of is None else of
        return f"{100.0 * n / of:.1f}%" if of else "0%"


def make_context(ds: Dataset) -> Context:
    con = ds.cursor()
    columns = {c for c, _ in ds.columns}
    if "event_time" in columns:
        row = con.execute("SELECT count(*), min(event_time), max(event_time) FROM trail").fetchone()
    else:
        row = con.execute("SELECT count(*), NULL, NULL FROM trail").fetchone()
    total, start, end = row or (0, None, None)
    return Context(con, columns, int(total), start, end)


def listing(items: list[str], limit: int = 4) -> str:
    items = [str(i) for i in items]
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"


def minutes_between(first: datetime | None, last: datetime | None) -> int:
    if not first or not last:
        return 1
    return max(1, int((last - first).total_seconds() // 60) + 1)


# ------------------------------------------------------------------ access denied


def rule_access_denied(ctx: Context) -> list[Finding]:
    if not ctx.has("access_denied", "principal"):
        return []
    where = "access_denied"
    n = ctx.count(where)
    if n == 0:
        return [
            Finding(
                "access-denied",
                "access_denied",
                "No access denied errors",
                Severity.INFO,
                f"None of the {ctx.total:,} calls in this file was refused by a policy.",
                "A refused call would carry an error code such as AccessDenied, "
                "AccessDeniedException or Client.UnauthorizedOperation.",
                "",
                0,
                where,
            )
        ]
    share = n / ctx.total
    sev = Severity.HIGH if share >= 0.10 else Severity.MEDIUM if share >= 0.02 else Severity.LOW
    first, last = ctx.one(f"SELECT min(event_time), max(event_time) FROM trail WHERE {where}")
    by_pair = ctx.sql(
        f"""
        SELECT principal, {ACTION}, count(*), count(DISTINCT source_ip), min(event_time),
               max(event_time)
        FROM trail WHERE {where} GROUP BY 1, 2 ORDER BY 3 DESC, 1, 2 LIMIT 15
        """
    )
    by_principal = ctx.sql(
        f"""
        SELECT principal, any_value(identity_type), count(*) FILTER (WHERE {where}) AS refused,
               count(DISTINCT event_name) FILTER (WHERE {where}),
               count(DISTINCT source_ip) FILTER (WHERE {where}),
               round(100.0 * count(*) FILTER (WHERE {where}) / count(*), 1)
        FROM trail GROUP BY 1 HAVING refused > 0 ORDER BY refused DESC LIMIT 10
        """
    )
    by_code = ctx.sql(
        f"SELECT error_code, count(*), count(DISTINCT principal) FROM trail WHERE {where} "
        "GROUP BY 1 ORDER BY 2 DESC"
    )
    by_ip = ctx.sql(
        f"SELECT source_ip, count(*), count(DISTINCT principal), any_value(user_agent) "
        f"FROM trail WHERE {where} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
    )
    top, _, top_n, top_actions, top_ips, _ = by_principal[0]
    top_action = next(a for p, a, *_ in by_pair if p == top)
    if top_actions >= ENUMERATION_MIN_ACTIONS:
        what = f"spread over {top_actions} different actions"
        shape = (
            f"{top} was refused {top_actions} different actions, which is not what a program "
            "doing its job looks like; the burst finding has the details."
        )
    else:
        what = f"mostly {top_action}"
        shape = (
            f"{top} was refused the same {plural(int(top_actions), 'action')} over and over, "
            "the shape of a missing permission being retried."
        )
    return [
        Finding(
            "access-denied",
            "access_denied",
            f"{n:,} calls were refused by a policy ({ctx.share(n)} of calls)",
            sev,
            f"{n:,} of {ctx.total:,} calls got an access denied error {span(first, last)}. "
            f"{top} accounts for {top_n:,} of them, {what}, from "
            f"{plural(int(top_ips), 'address')}.",
            "A refused call means the credentials were valid but no policy allowed the action: "
            "the request reached the service and was turned down. A scattering of refusals is "
            "normal in any account. A steady stream of one action from one principal is a "
            "missing permission; many different actions from one principal in a few minutes is "
            "someone finding out what a credential can do.",
            shape,
            n,
            where,
            [
                Table(
                    "By principal and action",
                    ["principal", "action", "refused", "addresses", "first", "last"],
                    by_pair,
                ),
                Table(
                    "By principal",
                    [
                        "principal",
                        "type",
                        "refused",
                        "actions",
                        "addresses",
                        "share of its calls (%)",
                    ],
                    by_principal,
                ),
                Table("By error code", ["error code", "refused", "principals"], by_code),
                Table(
                    "By source address",
                    ["address", "refused", "principals", "user agent"],
                    by_ip,
                ),
            ],
        )
    ]


def rule_denied_bursts(ctx: Context) -> list[Finding]:
    """Runs of minutes where one principal is refused far more than the background rate."""
    if not ctx.has("access_denied", "principal", "event_time"):
        return []
    hot = ctx.sql(
        f"""
        SELECT principal, date_trunc('minute', event_time) AS m, count(*)
        FROM trail WHERE access_denied GROUP BY 1, 2
        HAVING count(*) >= {DENIED_PER_MINUTE} ORDER BY 1, 2
        """
    )
    runs: list[list[Any]] = []  # [principal, start, end, refused]
    for principal, minute, count in hot:
        last = runs[-1] if runs else None
        if (
            last
            and last[0] == principal
            and (minute - last[2]).total_seconds() <= DENIED_GAP_MINUTES * 60
        ):
            last[2], last[3] = minute, last[3] + int(count)
        else:
            runs.append([principal, minute, minute, int(count)])
    runs = [r for r in runs if r[3] >= DENIED_BURST_MIN]
    runs.sort(key=lambda r: -r[3])
    findings: list[Finding] = []
    for i, (principal, start, end, _) in enumerate(runs[:MAX_PER_RULE], 1):
        stop = end + timedelta(minutes=1)
        window = f"event_time >= {ts(start)} AND event_time < {ts(stop)}"
        where = f"principal = {lit(principal)} AND access_denied AND {window}"
        n, actions, ips, first, last, kind, key = ctx.one(
            "SELECT count(*), count(DISTINCT event_name), count(DISTINCT source_ip), "
            "min(event_time), max(event_time), any_value(identity_type), any_value(access_key_id) "
            f"FROM trail WHERE {where}"
        )
        allowed = ctx.count(f"principal = {lit(principal)} AND NOT access_denied AND {window}")
        by_action = ctx.sql(
            f"SELECT {ACTION}, count(*), any_value(error_code), any_value(error_message) "
            f"FROM trail WHERE {where} GROUP BY 1 ORDER BY 2 DESC, 1"
        )
        by_source = ctx.sql(
            f"SELECT source_ip, any_value(user_agent), count(*) FROM trail WHERE {where} "
            "GROUP BY 1 ORDER BY 3 DESC"
        )
        by_minute = ctx.sql(
            f"SELECT date_trunc('minute', event_time), count(*), count(DISTINCT event_name) "
            f"FROM trail WHERE {where} GROUP BY 1 ORDER BY 1"
        )
        outside_total, outside_denied, outside_ips = ctx.one(
            "SELECT count(*), count(*) FILTER (WHERE access_denied), "
            f"list(DISTINCT source_ip) FROM trail WHERE principal = {lit(principal)} "
            f"AND NOT ({window})"
        )
        burst_ips = [r[0] for r in by_source]
        new_ips = [ip for ip in burst_ips if ip not in (outside_ips or [])]
        enumeration = int(actions) >= ENUMERATION_MIN_ACTIONS
        minutes = minutes_between(first, last)
        top_action, top_count, _, message = by_action[0]
        # "mostly X" only when X really dominates; a flat spread is the point of the finding.
        flat = int(actions) > 1 and int(top_count) * int(actions) <= int(n) * 1.5
        what = f"spread over {actions} actions" if flat else f"mostly {top_action}"
        if enumeration:
            shape = f" across {actions} different actions"
        elif int(actions) == 1:
            shape = f", all {top_action}"
        else:
            shape = f" over {plural(int(actions), 'action')}"
        if new_ips and int(outside_total) > 0:
            address_note = (
                f" The address {listing(new_ips)} never appears in this principal's other "
                f"{outside_total:,} calls, which came from {listing(outside_ips or [])}."
            )
        else:
            address_note = ""
        if enumeration:
            sev = Severity.HIGH
            cause = (
                "Many different actions, each tried a few times and nearly all refused, is what "
                "testing a stolen or found credential looks like, not a program doing its job. "
                "Check where the address belongs. If you do not recognise it, deactivate the "
                f"access key{f' {key}' if key else ''} now, rotate it, and look at the "
                "calls that were allowed in the same window."
            )
        else:
            sev = Severity.HIGH if new_ips and int(outside_total) > 0 else Severity.MEDIUM
            match = re.search(r"on resource: (\S+)", str(message or ""))
            resource = f" The error message names the resource: {match.group(1)}." if match else ""
            cause = (
                "The same action refused again and again on a schedule is a retry loop: a deploy "
                "started reading a resource the role's policy does not cover, or a policy change "
                "took a permission away and the caller never stopped asking. Add the permission "
                f"or fix the caller.{resource}"
            )
        findings.append(
            Finding(
                f"denied-burst-{i}",
                "denied_burst",
                f"{principal} was refused {n:,} calls in {plural(minutes, 'minute')}{shape}",
                sev,
                f"Between {fmt_ts(first)} and {fmt_ts(last)}, {principal} ({kind}) made "
                f"{int(n) + allowed:,} calls from {listing(burst_ips)}; {n:,} were refused, "
                f"{what}, and {allowed:,} were allowed. Outside this window the same "
                f"principal made {outside_total:,} calls with {outside_denied:,} refused."
                + address_note,
                "A burst of refusals from one principal stands out from the file's background "
                "rate. Whether it is a broken deployment or a stolen key shows in the shape: how "
                "many different actions were tried, from where, and whether that address is one "
                "the principal normally uses.",
                cause,
                int(n),
                where,
                [
                    Table(
                        "By action", ["action", "refused", "error code", "error message"], by_action
                    ),
                    Table("By source address", ["address", "user agent", "refused"], by_source),
                    Table("By minute", ["minute", "refused", "actions"], by_minute),
                ],
            )
        )
    return findings


# ---------------------------------------------------------------- console sign-ins


def rule_console_logins(ctx: Context) -> list[Finding]:
    if not ctx.has("event_name", "mfa_used", "principal"):
        return []
    logins = "event_name = 'ConsoleLogin'"
    total = ctx.count(logins)
    if total == 0:
        return []
    success = f"{logins} AND coalesce(login_result, 'Success') = 'Success'"
    failed = ctx.count(f"{logins} AND login_result = 'Failure'")
    by_user = ctx.sql(
        f"""
        SELECT principal, coalesce(login_result, 'Success'),
               CASE mfa_used WHEN true THEN 'yes' WHEN false THEN 'no' ELSE 'unknown' END,
               count(*), min(event_time), max(event_time)
        FROM trail WHERE {logins} GROUP BY ALL ORDER BY 4 DESC
        """
    )
    all_table = Table(
        "All sign-ins", ["user", "result", "MFA", "sign-ins", "first", "last"], by_user
    )
    tables = [all_table]
    if failed:
        tables.append(
            Table(
                "Failed sign-ins",
                ["user", "address", "attempts"],
                ctx.sql(
                    f"SELECT principal, source_ip, count(*) FROM trail WHERE {logins} AND "
                    "login_result = 'Failure' GROUP BY ALL ORDER BY 3 DESC"
                ),
            )
        )
    failed_note = f" {plural(failed, 'sign-in')} failed." if failed else ""
    if ctx.count(f"{logins} AND mfa_used IS NOT NULL") == 0:
        return [
            Finding(
                "console-mfa",
                "console_logins",
                f"Could not tell whether {plural(total, 'console sign-in')} used MFA",
                Severity.LOW,
                f"This file has {plural(total, 'console sign-in')} but no MFA information."
                + failed_note,
                "CloudTrail records MFAUsed inside the sign-in event's additionalEventData. The "
                "console's CSV download carries it in the full event record column; a CloudTrail "
                "Lake or Athena query needs additionalEventData (or "
                "userIdentity.sessionContext.attributes.mfaAuthenticated) in its SELECT.",
                "",
                total,
                logins,
                tables,
            )
        ]
    no_mfa = f"{success} AND mfa_used = false"
    n = ctx.count(no_mfa)
    users = int(ctx.one(f"SELECT count(DISTINCT principal) FROM trail WHERE {success}")[0])
    if n == 0:
        return [
            Finding(
                "console-mfa",
                "console_logins",
                "Every console sign-in used MFA",
                Severity.INFO,
                f"{plural(ctx.count(success), 'successful console sign-in')} by "
                f"{plural(users, 'user')}, all with a second factor.{failed_note}",
                "MFAUsed in the sign-in event says whether a second factor was checked.",
                "",
                0,
                no_mfa,
                tables,
            )
        ]
    rows = ctx.sql(
        f"SELECT principal, identity_type, source_ip, event_time, user_agent FROM trail "
        f"WHERE {no_mfa} ORDER BY event_time"
    )
    root_rows = [r for r in rows if r[1] == "Root" or r[0] == "root"]
    names = list(dict.fromkeys(r[0] for r in rows))
    cause = (
        "IAM users without an MFA device, or MFA set up but not enforced. Enforce it with a "
        "policy that denies everything unless aws:MultiFactorAuthPresent is true, or move "
        "console access to IAM Identity Center so the identity provider enforces it."
    )
    if root_rows:
        cause += (
            " The root account signed in without MFA, which is the most urgent item in this "
            "file: add a hardware or virtual MFA device to root today, and check whether "
            f"{listing(list({r[2] for r in root_rows}))} is an address you recognise."
        )
    title = f"{plural(n, 'console sign-in')} without MFA"
    if root_rows:
        title += f", {len(root_rows)} by the root account"
    return [
        Finding(
            "console-mfa",
            "console_logins",
            title,
            Severity.HIGH,
            f"{n} of {plural(ctx.count(success), 'successful console sign-in')} used a password "
            f"alone, by {listing(names)}.{failed_note}",
            "MFAUsed in the sign-in event says whether a second factor was checked. A "
            "password-only sign-in means anyone who phishes, guesses or reuses that password "
            "has the console, and with it whatever the user may do.",
            cause,
            n,
            no_mfa,
            [
                Table(
                    "Sign-ins without MFA",
                    ["user", "type", "address", "time", "user agent"],
                    rows,
                ),
                *tables,
            ],
        )
    ]


# ------------------------------------------------------------------ root account


def rule_root_activity(ctx: Context) -> list[Finding]:
    if not ctx.has("is_root"):
        return []
    where = "is_root"
    n = ctx.count(where)
    if n == 0:
        return [
            Finding(
                "root-activity",
                "root_activity",
                "No root account activity",
                Severity.INFO,
                f"None of the {ctx.total:,} events was made by the root user.",
                "Root events carry userIdentity.type = Root. Day-to-day work should never "
                "produce one.",
                "",
                0,
                where,
            )
        ]
    first, last = ctx.one(f"SELECT min(event_time), max(event_time) FROM trail WHERE {where}")
    by_action = ctx.sql(
        f"""
        SELECT {ACTION}, aws_region, count(*), bool_and(coalesce(read_only, true)),
               count(*) FILTER (WHERE error_code IS NOT NULL)
        FROM trail WHERE {where} GROUP BY 1, 2 ORDER BY 3 DESC
        """
    )
    events = ctx.sql(
        f"""
        SELECT event_time, {ACTION}, aws_region, source_ip, error_code,
               CASE mfa_used WHEN true THEN 'yes' WHEN false THEN 'no' ELSE 'unknown' END,
               resource_name
        FROM trail WHERE {where} ORDER BY event_time LIMIT 50
        """
    )
    changes = [
        r[0]
        for r in ctx.sql(
            f"SELECT DISTINCT {ACTION} FROM trail WHERE {where} AND {MUTATING} ORDER BY 1"
        )
    ]
    ips = [r[0] for r in ctx.sql(f"SELECT DISTINCT source_ip FROM trail WHERE {where} ORDER BY 1")]
    touched = [
        r[0]
        for r in ctx.sql(
            f"SELECT DISTINCT resource_name FROM trail WHERE {where} AND {MUTATING} "
            "AND resource_name IS NOT NULL ORDER BY 1"
        )
    ]
    no_mfa_login = ctx.count(f"{where} AND event_name = 'ConsoleLogin' AND mfa_used = false")
    title = f"The root account made {plural(n, 'call')}"
    title += f", {len(changes)} of them changes" if changes else ", all read-only"
    summary = (
        f"Root was active {span(first, last)} from {listing(ips)}: {n:,} calls"
        + (f", including {listing(changes, 5)}" if changes else ", all read-only")
        + "."
    )
    if no_mfa_login:
        summary += " The root sign-in did not use MFA."
    cause = (
        "Someone used the root credentials for day-to-day work, or the credentials are in "
        "someone else's hands. "
    )
    if changes:
        cause += (
            "The changes are the thing to check first: a new user with an administrator policy "
            "and an access key is how an attacker keeps access after the root password changes."
            + (f" Resources touched: {listing(touched)}." if touched else "")
            + " If you do not recognise this activity, rotate the root password, delete any root "
            "access keys, and undo what was created."
        )
    else:
        cause += (
            "Read-only root calls are usually someone signed in as root to look at billing or "
            "support. Move that to an IAM Identity Center user with the right permissions."
        )
    return [
        Finding(
            "root-activity",
            "root_activity",
            title,
            Severity.HIGH,
            summary,
            "The root user is not subject to IAM policies and cannot be restricted, so AWS's own "
            "guidance is to lock it away behind MFA and use it only for the handful of tasks that "
            "need it, such as changing the support plan or closing the account. Any other root "
            "activity deserves a question.",
            cause,
            n,
            where,
            [
                Table("By action", ["action", "region", "calls", "read-only", "errors"], by_action),
                Table(
                    "Every root event",
                    ["time", "action", "region", "address", "error", "MFA", "resource"],
                    events,
                ),
            ],
        )
    ]


# ---------------------------------------------------------------- unusual regions


def rule_unusual_regions(ctx: Context) -> list[Finding]:
    if not ctx.has("aws_region", "global_service", "principal"):
        return []
    regional = "NOT global_service AND aws_region IS NOT NULL"
    total = ctx.count(regional)
    if total == 0:
        return []
    by_region = ctx.sql(
        f"""
        SELECT aws_region, count(*), count(*) FILTER (WHERE {MUTATING}), count(DISTINCT principal),
               min(event_time), max(event_time)
        FROM trail WHERE {regional} GROUP BY 1 ORDER BY 2 DESC
        """
    )
    usual = [r for r in by_region if r[1] / total >= NORMAL_REGION_SHARE]
    rare = [r for r in by_region if r[1] / total < NORMAL_REGION_SHARE]
    usual_table = Table(
        "Usual regions",
        ["region", "calls", "share (%)", "principals"],
        [(r[0], r[1], round(100.0 * r[1] / total, 1), r[3]) for r in usual],
    )
    usual_names = listing([f"{r[0]} ({100.0 * r[1] / total:.0f}%)" for r in usual])
    if not rare:
        return [
            Finding(
                "unusual-regions",
                "unusual_regions",
                f"All activity was in {plural(len(usual), 'region')}: "
                + listing([r[0] for r in usual]),
                Severity.INFO,
                f"Every regional call landed in {usual_names}. Global services (IAM, the STS "
                "global endpoint, CloudFront, Route 53) always record us-east-1 and are left out.",
                "A call in a region nobody uses is worth a look, because that is where a "
                "compromised credential goes to work unnoticed. There is none here.",
                "",
                0,
                regional,
                [usual_table],
            )
        ]
    rare_names = [r[0] for r in rare]
    where = f"{regional} AND aws_region IN ({', '.join(lit(r) for r in rare_names)})"
    n = sum(int(r[1]) for r in rare)
    mutating = sum(int(r[2]) for r in rare)
    first = min(r[4] for r in rare)
    last = max(r[5] for r in rare)
    calls = ctx.sql(
        f"SELECT aws_region, {ACTION}, principal, source_ip, count(*) FROM trail WHERE {where} "
        "GROUP BY ALL ORDER BY 1, 5 DESC LIMIT 30"
    )
    who = ctx.sql(
        "SELECT principal, any_value(identity_type), count(*), "
        f"count(*) FILTER (WHERE {MUTATING}), "
        "string_agg(DISTINCT aws_region, ', ' ORDER BY aws_region), "
        f"string_agg(DISTINCT source_ip, ', ' ORDER BY source_ip) "
        f"FROM trail WHERE {where} GROUP BY 1 ORDER BY 3 DESC"
    )
    changes = [
        r[0]
        for r in ctx.sql(
            f"SELECT DISTINCT {ACTION} FROM trail WHERE {where} AND {MUTATING} ORDER BY 1"
        )
    ]
    principals = [r[0] for r in who]
    summary = (
        f"{usual_names} hold the account's regional activity. {plural(n, 'call')} landed in "
        f"{listing(rare_names)} {span(first, last)}, by {listing(principals)}"
    )
    if mutating:
        summary += f"; {mutating} of them created or changed something ({listing(changes, 5)})."
    else:
        summary += ", all read-only."
    if mutating:
        sev = Severity.HIGH
        cause = (
            "Resources appearing in a region nobody works in is the classic sign of a "
            "compromised credential: attackers pick regions where no one is looking, often to "
            "run instances at your expense. It can also be a CLI profile with the wrong default "
            "region. Check the principals here against the sign-in and root findings, then look "
            f"at what was created: {listing(changes, 5)}."
        )
    else:
        sev = Severity.LOW
        cause = (
            "Read-only calls in an unfamiliar region are usually a tool walking every region: a "
            "security scanner, AWS Config, or a CLI run with --all-regions. Worth a look, not "
            "an alarm."
        )
    return [
        Finding(
            "unusual-regions",
            "unusual_regions",
            f"{plural(n, 'call')} in {plural(len(rare), 'region')} this account rarely uses "
            f"({listing(rare_names)})",
            sev,
            summary,
            "Global services always record us-east-1 and are left out. A region is usual when it "
            f"holds at least {NORMAL_REGION_SHARE:.0%} of the remaining calls; anything below "
            "that is listed here.",
            cause,
            n,
            where,
            [
                Table(
                    "Rarely used regions",
                    ["region", "calls", "changes", "principals", "first", "last"],
                    rare,
                ),
                Table(
                    "Calls in those regions",
                    ["region", "action", "principal", "address", "calls"],
                    calls,
                ),
                Table(
                    "Who called from there",
                    ["principal", "type", "calls", "changes", "regions", "addresses"],
                    who,
                ),
                usual_table,
            ],
        )
    ]


# ----------------------------------------------------------------- overview


def rule_top_principals(ctx: Context) -> list[Finding]:
    if not ctx.has("principal"):
        return []
    by_principal = ctx.sql(
        """
        SELECT principal, any_value(identity_type), count(*),
               count(*) FILTER (WHERE error_code IS NOT NULL), count(DISTINCT service),
               count(DISTINCT source_ip)
        FROM trail GROUP BY 1 ORDER BY 3 DESC LIMIT 10
        """
    )
    if not by_principal:
        return []
    by_service = ctx.sql(
        """
        SELECT service, count(*), count(DISTINCT event_name),
               count(*) FILTER (WHERE error_code IS NOT NULL), count(DISTINCT principal)
        FROM trail WHERE service IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10
        """
    )
    by_ip = ctx.sql(
        """
        SELECT source_ip, count(*), count(DISTINCT principal),
               string_agg(DISTINCT principal, ', ' ORDER BY principal)
        FROM trail WHERE source_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10
        """
    )
    distinct, services, errors = ctx.one(
        "SELECT count(DISTINCT principal), count(DISTINCT service), "
        "count(*) FILTER (WHERE error_code IS NOT NULL) FROM trail"
    )
    top = by_principal[0]
    return [
        Finding(
            "top-principals",
            "top_principals",
            f"Top principal: {top[0]} made {int(top[2]):,} calls ({ctx.share(int(top[2]))})",
            Severity.INFO,
            f"{plural(int(distinct), 'principal')} called {plural(int(services), 'service')} "
            f"{span(ctx.start, ctx.end)}: {ctx.total:,} events, {errors:,} of them errors.",
            "Who does what in this account. Role sessions are grouped under their role, so an "
            "autoscaled fleet shows up as one line.",
            "",
            int(top[2]),
            f"principal = {lit(top[0])}",
            [
                Table(
                    "By principal",
                    ["principal", "type", "calls", "errors", "services", "addresses"],
                    by_principal,
                ),
                Table(
                    "By service",
                    ["service", "calls", "actions", "errors", "principals"],
                    by_service,
                ),
                Table("By source address", ["address", "calls", "principals", "who"], by_ip),
            ],
        )
    ]


# ------------------------------------------------------------------------ timeline


def timeline(ctx: Context) -> dict[str, Any] | None:
    if not ctx.has("event_time") or ctx.start is None or ctx.end is None:
        return None
    bad = "error_code IS NOT NULL" if ctx.has("error_code") else "false"
    span_s = (ctx.end - ctx.start).total_seconds()
    name, secs = pick_bucket(span_s)
    rows = ctx.sql(
        f"""
        SELECT (epoch(event_time)::BIGINT // {secs}) * {secs} AS b,
               count(*) FILTER (WHERE NOT ({bad})), count(*) FILTER (WHERE {bad})
        FROM trail WHERE event_time IS NOT NULL GROUP BY b ORDER BY b
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
        "title": "API calls against errors",
        "good": "ok",
        "bad": "error",
        "unit": "events",
    }


RULES = [
    rule_access_denied,
    rule_denied_bursts,
    rule_console_logins,
    rule_root_activity,
    rule_unusual_regions,
    rule_top_principals,
]


def run_rules(ds: Dataset) -> list[Finding]:
    ctx = make_context(ds)
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(ctx))
    return sort_findings(findings)


def build_timeline(ds: Dataset) -> dict[str, Any] | None:
    return timeline(make_context(ds))
