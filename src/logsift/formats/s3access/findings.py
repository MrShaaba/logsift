"""Rule-based findings for S3 server access logs.

Every rule is plain SQL over the ``s3`` table built by ``table.py`` next door. One row is
one request against the bucket, so the rules talk about keys and prefixes, status codes,
principals and client addresses. Thresholds are simple and written next to each rule.
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

PREFIX = "coalesce(prefix, '(bucket)')"  # bucket-level requests have no key

ERROR_HIGH_SHARE = 0.10  # failed requests as a share of all requests
ERROR_MEDIUM_SHARE = 0.02
SERVER_ERRORS_MIN = 10  # 5xx before the error finding is at least medium
MISSING_MIN = 20  # 404s under one prefix before it is reported
DENIED_MIN = 10  # 403s for one signed principal before it is reported
DENIED_MEDIUM = 30
PROBE_MIN = 30  # anonymous 403s from one address: someone guessing names
DELETE_PER_MINUTE = 1  # any minute with a delete joins a run
DELETE_GAP_MINUTES = 2  # delete minutes this close together are one run
DELETE_MIN = 50  # deletes in a run before it is reported
MAX_PER_RULE = 5


@dataclass
class Context:
    con: duckdb.DuckDBPyConnection
    columns: set[str]
    total: int
    start: datetime | None
    end: datetime | None
    total_bytes: int

    def has(self, *cols: str) -> bool:
        return all(c in self.columns for c in cols)

    def sql(self, query: str) -> list[tuple[Any, ...]]:
        return self.con.execute(query).fetchall()

    def one(self, query: str) -> tuple[Any, ...]:
        row = self.con.execute(query).fetchone()
        return row if row is not None else ()

    def count(self, where: str) -> int:
        return int(self.one(f"SELECT count(*) FROM s3 WHERE {where}")[0])

    def share(self, n: int, of: int | None = None) -> str:
        of = self.total if of is None else of
        return f"{100.0 * n / of:.1f}%" if of else "0%"


def make_context(ds: Dataset) -> Context:
    con = ds.cursor()
    columns = {c for c, _ in ds.columns}
    time = "min(time), max(time)" if "time" in columns else "NULL, NULL"
    size = "coalesce(sum(bytes_sent), 0)" if "bytes_sent" in columns else "0"
    row = con.execute(f"SELECT count(*), {time}, {size} FROM s3").fetchone()
    total, start, end, total_bytes = row or (0, None, None, 0)
    return Context(con, columns, int(total), start, end, int(total_bytes))


def listing(items: list[Any], limit: int = 4) -> str:
    items = [str(i) for i in items]
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" and {len(items) - limit} more"


def minutes_between(first: datetime | None, last: datetime | None) -> int:
    if not first or not last:
        return 1
    return max(1, int((last - first).total_seconds() // 60) + 1)


def s3_action(verb: str | None, target: str | None) -> str:
    """The IAM action a logged operation needs: GET OBJECT -> s3:GetObject."""
    if not verb or not target:
        return "the action"
    name = "".join(part.capitalize() for part in (verb + "_" + target).lower().split("_"))
    return f"s3:{name}" if target != "BUCKET" else "s3:ListBucket"


# ------------------------------------------------------------------ anonymous access


def rule_anonymous(ctx: Context) -> list[Finding]:
    """Requests that carried no credentials: the ones that succeeded are the finding."""
    if not ctx.has("anonymous", "is_error"):
        return []
    findings: list[Finding] = []
    ok = "anonymous AND NOT is_error"
    n_ok = ctx.count(ok)
    if n_ok:
        objects, total_bytes, listings, ips, first, last = ctx.one(
            "SELECT count(DISTINCT key) FILTER (WHERE key IS NOT NULL), "
            "coalesce(sum(bytes_sent), 0), count(*) FILTER (WHERE target = 'BUCKET'), "
            f"count(DISTINCT remote_ip), min(time), max(time) FROM s3 WHERE {ok}"
        )
        by_prefix = ctx.sql(
            f"SELECT {PREFIX}, count(*), count(DISTINCT key), coalesce(sum(bytes_sent), 0) "
            f"FROM s3 WHERE {ok} GROUP BY 1 ORDER BY 4 DESC, 2 DESC"
        )
        by_ip = ctx.sql(
            "SELECT remote_ip, count(*), coalesce(sum(bytes_sent), 0), any_value(user_agent), "
            f"min(time), max(time) FROM s3 WHERE {ok} GROUP BY 1 ORDER BY 3 DESC LIMIT 10"
        )
        largest = ctx.sql(
            f"SELECT key, bytes_sent, time, remote_ip FROM s3 WHERE {ok} AND key IS NOT NULL "
            "ORDER BY bytes_sent DESC NULLS LAST, time LIMIT 10"
        )
        by_op = ctx.sql(
            f"SELECT operation, count(*), coalesce(sum(bytes_sent), 0) FROM s3 WHERE {ok} "
            "GROUP BY 1 ORDER BY 2 DESC"
        )
        prefixes = [r[0] for r in by_prefix if r[0] != "(bucket)"]
        addresses = [r[0] for r in by_ip]
        biggest = (
            f" The largest was {largest[0][0]} ({fmt_bytes(largest[0][1])})." if largest else ""
        )
        listed = f"{plural(int(listings), 'bucket listing')} and " if listings else ""
        findings.append(
            Finding(
                "anonymous-reads",
                "anonymous",
                f"{n_ok:,} anonymous requests succeeded, reading "
                f"{plural(int(objects), 'object')} ({fmt_bytes(total_bytes)})",
                Severity.HIGH,
                f"Between {fmt_ts(first)} and {fmt_ts(last)}, {plural(int(ips), 'address')} "
                f"({listing(addresses)}) used the bucket without signing a request: {listed}"
                f"{objects:,} objects under {listing(prefixes) or 'the bucket root'}, "
                f"{fmt_bytes(total_bytes)} in all.{biggest}",
                "An anonymous request carries no credentials, so the only thing that can allow "
                'it is a bucket policy or object ACL that grants access to everyone ("Principal": '
                '"*"). Block Public Access refuses such grants when it is on. These requests were '
                "allowed, so for this bucket it is off, and the grant is in place.",
                "The bucket, or at least these prefixes, is public. Unless it hosts a public "
                "website that is the thing to fix first: turn on Block Public Access, remove the "
                "public statement from the bucket policy and any public-read ACLs, then treat "
                f"everything under {listing(prefixes) or 'the bucket'} as disclosed. Backups, "
                "exports and database dumps in a public prefix are a breach, not a setting.",
                n_ok,
                ok,
                [
                    Table("By key prefix", ["prefix", "requests", "objects", "bytes"], by_prefix),
                    Table(
                        "By client address",
                        ["address", "requests", "bytes", "user agent", "first", "last"],
                        by_ip,
                    ),
                    Table("Largest objects read", ["key", "bytes", "time", "address"], largest),
                    Table("By operation", ["operation", "requests", "bytes"], by_op),
                ],
            )
        )
    denied = "anonymous AND http_status = 403"
    n_denied = ctx.count(denied) if ctx.has("http_status") else 0
    if n_denied:
        by_ip = ctx.sql(
            "SELECT remote_ip, count(*), count(DISTINCT key), any_value(user_agent), "
            f"min(time), max(time) FROM s3 WHERE {denied} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        )
        keys = ctx.sql(
            f"SELECT coalesce(key, '(bucket)'), count(*), any_value(remote_ip) FROM s3 "
            f"WHERE {denied} GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 200"
        )
        by_minute = ctx.sql(
            f"SELECT date_trunc('minute', time), count(*), count(DISTINCT remote_ip) "
            f"FROM s3 WHERE {denied} GROUP BY 1 ORDER BY 1"
        )
        top_ip, top_n, top_keys, agent, first, last = by_ip[0]
        probing = int(top_n) >= PROBE_MIN
        bucket = ctx.one("SELECT any_value(bucket) FROM s3")[0] if ctx.has("bucket") else None
        if probing:
            how_many = "all" if int(top_n) == n_denied else f"{top_n:,}"
            shape = (
                f", {how_many} from {top_ip} trying {plural(int(top_keys), 'different key')} in "
                f"{plural(minutes_between(first, last), 'minute')}"
            )
            cause = (
                "Nothing is broken: the bucket said no every time. It is worth knowing that the "
                f"bucket name{f' {bucket}' if bucket else ''} is known outside and is being "
                f"probed with {agent or 'an unknown client'}. If the same address appears in "
                "the successful anonymous requests, that is the one to worry about."
            )
        else:
            shape = ""
            cause = "Background noise from the internet; nothing to do."
        findings.append(
            Finding(
                "anonymous-denied",
                "anonymous",
                f"{n_denied:,} anonymous requests were refused{shape}",
                Severity.MEDIUM if probing else Severity.LOW,
                f"{n_denied:,} unsigned requests from {plural(len(by_ip), 'address')} got 403 "
                f"AccessDenied {span(first, last)}. The busiest, {top_ip}, tried "
                f"{plural(int(top_keys), 'different key')}: {listing([k for k, *_ in keys], 6)}.",
                "A private bucket answers every anonymous request with 403, without saying "
                "whether the key exists. A handful is the normal background of the internet. One "
                "address trying many different, sensible-looking names (.env, backups, database "
                "dumps) is someone who knows the bucket name and is guessing what is in it.",
                cause,
                n_denied,
                denied,
                [
                    Table(
                        "By client address",
                        ["address", "refused", "keys tried", "user agent", "first", "last"],
                        by_ip,
                    ),
                    Table("Keys tried", ["key", "refused", "address"], keys[:25]),
                    Table("By minute", ["minute", "refused", "addresses"], by_minute),
                ],
            )
        )
    if not n_ok and not n_denied:
        findings.append(
            Finding(
                "anonymous",
                "anonymous",
                "No anonymous requests",
                Severity.INFO,
                f"Every one of the {ctx.total:,} requests in this file was signed.",
                "An anonymous request shows up with - in the requester field. None did, which is "
                "what a private bucket nobody is probing looks like.",
                "",
                0,
                "anonymous",
            )
        )
    return findings


# ------------------------------------------------------------------ failed requests


def rule_errors(ctx: Context) -> list[Finding]:
    if not ctx.has("is_error", "http_status"):
        return []
    where = "is_error"
    n = ctx.count(where)
    if n == 0:
        return [
            Finding(
                "errors",
                "errors",
                "Every request succeeded",
                Severity.INFO,
                f"None of the {ctx.total:,} requests in this file got a 4xx or 5xx status.",
                "A failed request would carry a status of 400 or more and usually an error code "
                "such as NoSuchKey, AccessDenied or SlowDown.",
                "",
                0,
                where,
            )
        ]
    share = n / ctx.total
    server = ctx.count("http_status >= 500")
    if share >= ERROR_HIGH_SHARE:
        sev = Severity.HIGH
    elif share >= ERROR_MEDIUM_SHARE or server >= SERVER_ERRORS_MIN:
        sev = Severity.MEDIUM
    else:
        sev = Severity.LOW
    first, last = ctx.one(f"SELECT min(time), max(time) FROM s3 WHERE {where}")
    by_code = ctx.sql(
        "SELECT http_status, coalesce(error_code, '(none)'), count(*), "
        f"count(DISTINCT principal), count(DISTINCT key) FROM s3 WHERE {where} "
        "GROUP BY 1, 2 ORDER BY 3 DESC, 1"
    )
    by_prefix = ctx.sql(
        f"""
        SELECT {PREFIX}, count(*) FILTER (WHERE {where}) AS failed, count(*),
               round(100.0 * count(*) FILTER (WHERE {where}) / count(*), 1),
               mode(error_code) FILTER (WHERE {where})
        FROM s3 GROUP BY 1 HAVING failed > 0 ORDER BY failed DESC LIMIT 10
        """
    )
    by_principal = ctx.sql(
        f"""
        SELECT principal, count(*) FILTER (WHERE {where}) AS failed, count(*),
               round(100.0 * count(*) FILTER (WHERE {where}) / count(*), 1),
               mode(error_code) FILTER (WHERE {where})
        FROM s3 GROUP BY 1 HAVING failed > 0 ORDER BY failed DESC LIMIT 10
        """
    )
    by_ip = ctx.sql(
        f"""
        SELECT remote_ip, count(*), count(DISTINCT key), mode(error_code), any_value(user_agent)
        FROM s3 WHERE {where} AND remote_ip IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10
        """
    )
    top_status, top_code, top_n, _, _ = by_code[0]
    top_prefix = by_prefix[0][0]
    causes = {
        "NoSuchKey": (
            f"Most of the failures are requests for keys that do not exist, concentrated under "
            f"{top_prefix}: something still links to objects that were deleted or never "
            "uploaded. The missing-keys finding lists them and who removed them."
        ),
        "AccessDenied": (
            "Most of the failures are requests no policy allows. The access denied and "
            "anonymous findings say which principals and addresses were refused."
        ),
        "SlowDown": (
            "Most of the failures are S3 throttling: the request rate on one prefix went above "
            "what it serves without ramping up. Spread keys across prefixes, or back off and "
            "retry with jitter."
        ),
    }
    server_note = f" {server:,} were 5xx, which is S3's side, not the caller's." if server else ""
    return [
        Finding(
            "errors",
            "errors",
            f"{n:,} requests failed ({ctx.share(n)} of requests)",
            sev,
            f"{n:,} of {ctx.total:,} requests got a 4xx or 5xx status {span(first, last)}. "
            f"The most common was {top_status} {top_code} ({top_n:,}), mostly under "
            f"{top_prefix}.{server_note}",
            "A 4xx means the request reached S3 and was turned down: 404 for a key that is not "
            "there, 403 for a request no policy allows, 400 for a malformed one. A 5xx means S3 "
            "could not serve it: 503 SlowDown is the per-prefix request rate limit, 500 "
            "InternalError is rare and safe to retry. Some 4xx is normal in any bucket; a cluster "
            "under one prefix or from one principal is a bug or a scanner.",
            causes.get(str(top_code), ""),
            n,
            where,
            [
                Table(
                    "By status and error code",
                    ["status", "error code", "requests", "principals", "keys"],
                    by_code,
                ),
                Table(
                    "By key prefix",
                    ["prefix", "failed", "requests", "failed (%)", "most common error"],
                    by_prefix,
                ),
                Table(
                    "By principal",
                    ["principal", "failed", "requests", "failed (%)", "most common error"],
                    by_principal,
                ),
                Table(
                    "By client address",
                    ["address", "failed", "keys", "most common error", "user agent"],
                    by_ip,
                ),
            ],
        )
    ]


# ------------------------------------------------------------------ missing keys


def rule_missing_keys(ctx: Context) -> list[Finding]:
    """404s piling up under one prefix, and whether this file shows who deleted the keys."""
    if not ctx.has("http_status", "prefix", "key", "time"):
        return []
    groups = ctx.sql(
        f"SELECT {PREFIX}, count(*), count(DISTINCT key), min(time), max(time) FROM s3 "
        f"WHERE http_status = 404 GROUP BY 1 HAVING count(*) >= {MISSING_MIN} "
        f"ORDER BY 2 DESC LIMIT {MAX_PER_RULE}"
    )
    findings: list[Finding] = []
    for i, (prefix, n, keys, first, last) in enumerate(groups, 1):
        where = f"http_status = 404 AND {PREFIX} = {lit(prefix)}"
        top_keys = ctx.sql(
            f"SELECT key, count(*), min(time), max(time) FROM s3 WHERE {where} "
            "GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 10"
        )
        by_referer = ctx.sql(
            "SELECT coalesce(nullif(regexp_extract(referer, '^[a-z]+://([^/]+)', 1), ''), "
            f"'(none)'), count(*), count(DISTINCT key) FROM s3 WHERE {where} "
            "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        )
        by_ip = ctx.sql(
            f"SELECT remote_ip, count(*), count(DISTINCT key), any_value(user_agent) FROM s3 "
            f"WHERE {where} GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
        )
        deleted_sql = f"""
            FROM s3 d
            JOIN (SELECT key, min(time) AS first_miss FROM s3 WHERE {where} GROUP BY 1) m
              ON d.key = m.key AND d.verb = 'DELETE' AND d.time <= m.first_miss
        """
        del_keys, del_first, del_last, del_who, del_people = ctx.one(
            "SELECT count(DISTINCT d.key), min(d.time), max(d.time), any_value(d.principal), "
            f"count(DISTINCT d.principal) {deleted_sql}"
        )
        deleted_rows = ctx.sql(
            f"SELECT d.key, d.time, d.principal, d.remote_ip {deleted_sql} ORDER BY d.time LIMIT 10"
        )
        after = (
            ctx.count(f"{where} AND key IN (SELECT d.key {deleted_sql}) AND time > {ts(del_first)}")
            if del_keys
            else 0
        )
        ref_host, ref_n, _ = by_referer[0]
        referred = (
            f" {ref_n:,} of them carried a referer from {ref_host}, so a page there still "
            "links to these keys."
            if ref_host != "(none)"
            else ""
        )
        if del_keys:
            who = del_who if int(del_people) == 1 else f"{del_people} principals"
            which = f"All {keys:,}" if del_keys == keys else f"{del_keys:,} of the {keys:,}"
            cause = (
                f"{which} missing keys were deleted earlier in this file by "
                f"{who} between {fmt_ts(del_first)} and {fmt_ts(del_last)}, and {after:,} of "
                "these requests came after that. Whatever generates the links still expects the "
                "objects: regenerate them, restore them, or stop linking to them."
            )
        else:
            cause = (
                "The objects were never uploaded, or were removed before this file starts. The "
                "referers show which pages still link to them."
            )
        tables = [
            Table("Most requested missing keys", ["key", "requests", "first", "last"], top_keys),
            Table("By referer", ["referer host", "requests", "keys"], by_referer),
            Table("By client address", ["address", "requests", "keys", "user agent"], by_ip),
        ]
        if deleted_rows:
            tables.append(
                Table(
                    "Deleted earlier in this file",
                    ["key", "deleted at", "by", "address"],
                    deleted_rows,
                )
            )
        findings.append(
            Finding(
                f"missing-keys-{i}",
                "missing_keys",
                f"{n:,} requests for objects that do not exist under {prefix}",
                Severity.MEDIUM if int(n) >= 50 else Severity.LOW,
                f"{n:,} requests for {plural(int(keys), 'different key')} under {prefix} came "
                f"back 404 {span(first, last)}.{referred}",
                "S3 answers 404 NoSuchKey when the key is not in the bucket and the caller is "
                "allowed to know that (without s3:ListBucket it would get 403 instead). One or "
                "two are typos. Hundreds under one prefix means something still links to objects "
                "that are gone.",
                cause,
                int(n),
                where,
                tables,
            )
        )
    return findings


# ------------------------------------------------------------------ refused principals


def rule_access_denied(ctx: Context) -> list[Finding]:
    """Signed requests refused with 403, grouped by the principal that made them."""
    if not ctx.has("http_status", "principal", "anonymous", "time"):
        return []
    groups = ctx.sql(
        f"""
        SELECT principal, count(*), count(DISTINCT {PREFIX}), count(DISTINCT key),
               min(time), max(time), any_value(user_agent)
        FROM s3 WHERE http_status = 403 AND NOT anonymous
        GROUP BY 1 HAVING count(*) >= {DENIED_MIN} ORDER BY 2 DESC LIMIT {MAX_PER_RULE}
        """
    )
    findings: list[Finding] = []
    for i, (principal, n, prefixes, keys, first, last, agent) in enumerate(groups, 1):
        where = f"http_status = 403 AND principal = {lit(principal)}"
        by_prefix = ctx.sql(
            f"SELECT {PREFIX}, count(*), count(DISTINCT key) FROM s3 WHERE {where} "
            "GROUP BY 1 ORDER BY 2 DESC"
        )
        by_op = ctx.sql(
            "SELECT operation, count(*), any_value(error_code), any_value(verb), "
            f"any_value(target) FROM s3 WHERE {where} GROUP BY 1 ORDER BY 2 DESC"
        )
        by_minute = ctx.sql(
            f"SELECT date_trunc('minute', time), count(*) FROM s3 WHERE {where} "
            "GROUP BY 1 ORDER BY 1"
        )
        allowed = ctx.count(f"principal = {lit(principal)} AND NOT is_error")
        denied_prefixes = ", ".join(lit(p) for p, *_ in by_prefix)
        same_prefix_ok = ctx.count(
            f"principal = {lit(principal)} AND NOT is_error AND {PREFIX} IN ({denied_prefixes})"
        )
        top_prefix = by_prefix[0][0]
        operation, _, _, verb, target = by_op[0]
        action = s3_action(verb, target)
        shape = f"under {top_prefix}" if int(prefixes) == 1 else f"across {prefixes} prefixes"
        minutes = len(by_minute)
        if minutes >= 3 and first and last:
            every = round((last - first).total_seconds() / 60 / (minutes - 1))
            cadence = f", about every {plural(every, 'minute')}" if every >= 1 else ""
        else:
            cadence = ""
        same_note = f", {same_prefix_ok:,} of them under the same prefix" if same_prefix_ok else ""
        findings.append(
            Finding(
                f"access-denied-{i}",
                "access_denied",
                f"{principal} was refused {n:,} requests {shape}",
                Severity.MEDIUM if int(n) >= DENIED_MEDIUM else Severity.LOW,
                f"Between {fmt_ts(first)} and {fmt_ts(last)}, {principal} got 403 AccessDenied "
                f"on {plural(int(keys), 'key')} under {top_prefix} ({operation}{cadence}), "
                f"using {agent or 'an unknown client'}. The same principal was allowed "
                f"{allowed:,} other requests{same_note}.",
                "A signed request refused with 403 means the credentials were valid but neither "
                "the principal's policy nor the bucket policy allows that action on that key. "
                "The same request refused on a schedule is a retry loop: a batch job or a deploy "
                "that started reading something its role was never given.",
                f"Add {action} on {top_prefix}* to {principal}'s policy, or to the bucket "
                "policy, or stop the caller asking. Check the key is spelled the way the writer "
                "spells it: a 403 is also what S3 returns for a missing key when the caller "
                "lacks s3:ListBucket.",
                int(n),
                where,
                [
                    Table("By key prefix", ["prefix", "refused", "keys"], by_prefix),
                    Table(
                        "By operation",
                        ["operation", "refused", "error code", "verb", "target"],
                        by_op,
                    ),
                    Table("By minute", ["minute", "refused"], by_minute),
                ],
            )
        )
    return findings


# ------------------------------------------------------------------ delete bursts


def rule_deletes(ctx: Context) -> list[Finding]:
    """Runs of minutes in which one principal deletes objects, and what broke afterwards."""
    if not ctx.has("verb", "principal", "time", "key"):
        return []
    hot = ctx.sql(
        "SELECT principal, date_trunc('minute', time) AS m, count(*) FROM s3 "
        f"WHERE verb = 'DELETE' GROUP BY 1, 2 HAVING count(*) >= {DELETE_PER_MINUTE} "
        "ORDER BY 1, 2"
    )
    runs: list[list[Any]] = []  # [principal, start, end, deletes]
    for principal, minute, count in hot:
        last = runs[-1] if runs else None
        if (
            last
            and last[0] == principal
            and (minute - last[2]).total_seconds() <= DELETE_GAP_MINUTES * 60
        ):
            last[2], last[3] = minute, last[3] + int(count)
        else:
            runs.append([principal, minute, minute, int(count)])
    runs = [r for r in runs if r[3] >= DELETE_MIN]
    runs.sort(key=lambda r: -r[3])
    findings: list[Finding] = []
    for i, (principal, start, end, _) in enumerate(runs[:MAX_PER_RULE], 1):
        stop = end + timedelta(minutes=1)
        where = (
            f"verb = 'DELETE' AND principal = {lit(principal)} AND time >= {ts(start)} "
            f"AND time < {ts(stop)}"
        )
        n, keys, first, last, agent, ips = ctx.one(
            "SELECT count(*), count(DISTINCT key), min(time), max(time), any_value(user_agent), "
            f"list(DISTINCT remote_ip) FROM s3 WHERE {where}"
        )
        by_prefix = ctx.sql(
            f"SELECT {PREFIX}, count(*) FROM s3 WHERE {where} GROUP BY 1 ORDER BY 2 DESC"
        )
        by_minute = ctx.sql(
            f"SELECT date_trunc('minute', time), count(*) FROM s3 WHERE {where} "
            "GROUP BY 1 ORDER BY 1"
        )
        sample = ctx.sql(
            f"SELECT key, time, http_status FROM s3 WHERE {where} ORDER BY time LIMIT 10"
        )
        after_n, after_keys = ctx.one(
            "SELECT count(*), count(DISTINCT key) FROM s3 WHERE http_status = 404 AND "
            f"time > {ts(last)} AND key IN (SELECT key FROM s3 WHERE {where})"
        )
        prefixes = [p for p, _ in by_prefix]
        if len(prefixes) == 1:
            shape = f" under {prefixes[0]}"
        else:
            shape = f" across {len(prefixes)} prefixes"
        minutes = minutes_between(first, last)
        if after_n:
            follow = (
                f" {after_n:,} requests for {after_keys:,} of those keys came back 404 afterwards."
            )
            cause = (
                "The keys were still in use when they were removed. Restore them from a backup "
                "or regenerate them (if versioning is on, remove the delete markers), and fix the "
                "cleanup so it spares keys that are still referenced."
            )
            sev = Severity.HIGH if int(after_n) >= MISSING_MIN else Severity.MEDIUM
        else:
            follow = " None of those keys was requested again in this file."
            cause = (
                "Probably intended. If it was not, and versioning is on, the objects sit behind "
                "delete markers and can be brought back; if it is off, they are gone."
            )
            sev = Severity.MEDIUM
        findings.append(
            Finding(
                f"delete-burst-{i}",
                "delete_burst",
                f"{principal} deleted {n:,} objects in {plural(minutes, 'minute')}{shape}",
                sev,
                f"Between {fmt_ts(first)} and {fmt_ts(last)}, {principal} sent {n:,} DELETE "
                f"requests from {listing(ips or [])} with {agent or 'an unknown client'}, "
                f"removing {plural(int(keys), 'key')} under {listing(prefixes)}.{follow}",
                "Hundreds of deletes in a few minutes from one principal is a script: aws s3 rm "
                "--recursive, a sync with --delete, or a cleanup job. It may well be intended. "
                "The question is whether anything still depended on those objects, and the 404s "
                "that follow answer it.",
                cause,
                int(n),
                where,
                [
                    Table("By key prefix", ["prefix", "deleted"], by_prefix),
                    Table("By minute", ["minute", "deleted"], by_minute),
                    Table("First keys deleted", ["key", "time", "status"], sample),
                ],
            )
        )
    return findings


# ------------------------------------------------------------------ overview


def rule_top_clients(ctx: Context) -> list[Finding]:
    if not ctx.has("principal", "is_error"):
        return []
    size = "coalesce(sum(bytes_sent), 0)" if ctx.has("bytes_sent") else "0"
    by_principal = ctx.sql(
        f"""
        SELECT principal, count(*), round(100.0 * count(*) / {ctx.total}, 1), {size},
               count(*) FILTER (WHERE is_error)
        FROM s3 GROUP BY 1 ORDER BY 2 DESC LIMIT 10
        """
    )
    by_ip = ctx.sql(
        f"""
        SELECT remote_ip, count(*), {size}, count(DISTINCT key), any_value(principal),
               any_value(user_agent)
        FROM s3 WHERE remote_ip IS NOT NULL GROUP BY 1 ORDER BY 3 DESC LIMIT 10
        """
    )
    by_op = ctx.sql(
        f"SELECT operation, count(*), count(*) FILTER (WHERE is_error), {size} FROM s3 "
        "GROUP BY 1 ORDER BY 2 DESC LIMIT 15"
    )
    by_agent = ctx.sql(
        "SELECT coalesce(user_agent, '(none)'), count(*), count(DISTINCT remote_ip) FROM s3 "
        "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
    )
    by_prefix = ctx.sql(
        f"SELECT {PREFIX}, count(*), {size}, count(DISTINCT key) FROM s3 "
        "GROUP BY 1 ORDER BY 2 DESC LIMIT 10"
    )
    principals, addresses = ctx.one(
        "SELECT count(DISTINCT principal), count(DISTINCT remote_ip) FROM s3"
    )
    top, top_n, top_share, _, _ = by_principal[0]
    if by_ip:
        heavy_ip, _, heavy_bytes, _, heavy_who, _ = by_ip[0]
        heavy = f" Most bytes went to {heavy_ip} ({fmt_bytes(heavy_bytes)}, as {heavy_who})."
    else:
        heavy = ""
    return [
        Finding(
            "top-clients",
            "top_clients",
            f"Top principal: {top} made {top_n:,} requests ({top_share}%)",
            Severity.INFO,
            f"{ctx.total:,} requests by {plural(int(principals), 'principal')} from "
            f"{plural(int(addresses), 'address')}, {fmt_bytes(ctx.total_bytes)} sent. "
            f"{top} made the most requests.{heavy}",
            "Who uses the bucket, from where, for what and how much. Anonymous counts as a "
            "principal of its own. Not a problem by itself; a quick way to spot a client that "
            "should not be there or a prefix carrying more traffic than expected.",
            "",
            int(top_n),
            f"principal = {lit(top)}",
            [
                Table(
                    "By principal",
                    ["principal", "requests", "share (%)", "bytes", "failed"],
                    by_principal,
                ),
                Table(
                    "By client address",
                    ["address", "requests", "bytes", "keys", "principal", "user agent"],
                    by_ip,
                ),
                Table("By operation", ["operation", "requests", "failed", "bytes"], by_op),
                Table("By user agent", ["user agent", "requests", "addresses"], by_agent),
                Table("By key prefix", ["prefix", "requests", "bytes", "keys"], by_prefix),
            ],
        )
    ]


# ------------------------------------------------------------------ timeline


def timeline(ctx: Context) -> dict[str, Any] | None:
    if not ctx.has("time", "is_error") or ctx.start is None or ctx.end is None:
        return None
    span_s = (ctx.end - ctx.start).total_seconds()
    name, secs = pick_bucket(span_s)
    rows = ctx.sql(
        f"""
        SELECT (epoch(time)::BIGINT // {secs}) * {secs} AS b,
               count(*) FILTER (WHERE NOT is_error), count(*) FILTER (WHERE is_error)
        FROM s3 WHERE time IS NOT NULL GROUP BY b ORDER BY b
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
        "title": "Requests against errors (4xx and 5xx)",
        "good": "ok",
        "bad": "error",
        "unit": "requests",
    }


RULES = [
    rule_anonymous,
    rule_errors,
    rule_missing_keys,
    rule_access_denied,
    rule_deletes,
    rule_top_clients,
]


def run_rules(ds: Dataset) -> list[Finding]:
    ctx = make_context(ds)
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(ctx))
    return sort_findings(findings)


def build_timeline(ds: Dataset) -> dict[str, Any] | None:
    return timeline(make_context(ds))
