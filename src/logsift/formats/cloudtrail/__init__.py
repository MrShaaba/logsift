"""CloudTrail event exports as CSV: the console download, a CloudTrail Lake or Athena
result, or a flattened export with columns like userIdentity.type."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import duckdb

from logsift.formats.base import Format, FormatInfo, FormatPlugin, mostly, squash
from logsift.formats.cloudtrail.findings import build_timeline, run_rules
from logsift.formats.cloudtrail.table import GLOBAL_SERVICES, build_trail_table
from logsift.insights.cwlogs import QuerySpec, boolean, mapped, regex_escape
from logsift.loader import Sniff

if TYPE_CHECKING:
    from logsift.dataset import Dataset
    from logsift.insights.base import Finding

# CloudTrail CSV columns keyed by their squashed spelling. The console's event history
# download uses "Event name", a CloudTrail Lake or Athena result uses eventName or
# eventname, and flattened Lake columns such as userIdentity.type squash the same way.
TRAIL_FIELDS: dict[str, str] = {
    "eventid": "event_id",
    "eventtime": "event_time",
    "eventname": "event_name",
    "eventsource": "event_source",
    "username": "user_name",
    "useridentityusername": "user_name",
    "awsregion": "aws_region",
    "region": "aws_region",
    "sourceipaddress": "source_ip",
    "sourceip": "source_ip",
    "errorcode": "error_code",
    "errormessage": "error_message",
    "readonly": "read_only",
    "accesskeyid": "access_key_id",
    "useridentityaccesskeyid": "access_key_id",
    "eventtype": "event_type",
    "requestid": "request_id",
    "eventcategory": "event_category",
    "recipientaccountid": "recipient_account_id",
    "resources": "resources",
    "resourcetype": "resource_type",
    "resourcename": "resource_name",
    "useragent": "user_agent",
    "useridentity": "user_identity",
    "useridentitytype": "identity_type",
    "usertype": "identity_type",
    "identitytype": "identity_type",
    "useridentityarn": "identity_arn",
    "userarn": "identity_arn",
    "identityarn": "identity_arn",
    "useridentityprincipalid": "principal_id",
    "principalid": "principal_id",
    "useridentityaccountid": "identity_account_id",
    "useridentitysessioncontextattributesmfaauthenticated": "mfa_authenticated",
    "mfaauthenticated": "mfa_authenticated",
    "mfaused": "mfa_used",
    "additionaleventdata": "additional_event_data",
    "requestparameters": "request_parameters",
    "responseelements": "response_elements",
    "cloudtrailevent": "event_json",
    "eventrecord": "event_json",
    "rawevent": "event_json",
    "eventjson": "event_json",
    "record": "event_json",
}
TRAIL_REQUIRED = {"event_time", "event_name", "event_source"}

# The event record's own JSON names, as CloudWatch Logs discovers them in a trail's group.
CW_TRAIL_FIELDS = {
    "event_time": "eventTime",
    "event_name": "eventName",
    "event_source": "eventSource",
    "aws_region": "awsRegion",
    "source_ip": "sourceIPAddress",
    "error_code": "errorCode",
    "error_message": "errorMessage",
    "user_agent": "userAgent",
    "read_only": "readOnly",
    "event_type": "eventType",
    "event_category": "eventCategory",
    "event_id": "eventID",
    "request_id": "requestID",
    "recipient_account_id": "recipientAccountId",
    "identity_type": "userIdentity.type",
    "identity_arn": "userIdentity.arn",
    "user_name": "userIdentity.userName",
    "access_key_id": "userIdentity.accessKeyId",
    "login_result": "responseElements.ConsoleLogin",
}
TRAIL_DISPLAY = [
    "eventTime",
    "eventSource",
    "eventName",
    "userIdentity.arn",
    "sourceIPAddress",
    "awsRegion",
    "errorCode",
]
GLOBAL_SOURCES = ", ".join(f'"{s}.amazonaws.com"' for s in GLOBAL_SERVICES if s != "sts")
TRAIL_STATS = {
    "access_denied": (
        "stats count(*) as calls by {identity_arn}, {event_name} | sort calls desc | limit 50"
    ),
    "denied_burst": (
        "stats count(*) as calls by {event_source}, {event_name}, {error_code} "
        "| sort calls desc | limit 50"
    ),
    "unusual_regions": (
        "stats count(*) as calls by {aws_region}, {event_name} | sort calls desc | limit 50"
    ),
    "top_principals": "stats count(*) as calls by {event_name} | sort calls desc | limit 50",
}


def service_field(op: str, value: object) -> str | None:
    if op not in ("=", "<>") or not isinstance(value, str):
        return None
    text = f'eventSource = "{value}.amazonaws.com"'
    return text if op == "=" else f"not ({text})"


def principal_field(op: str, value: object) -> str | None:
    """``principal`` is the user or role name cut out of the identity ARN."""
    if op not in ("=", "<>") or not isinstance(value, str):
        return None
    if value == "root":
        text = 'userIdentity.type = "Root"'
    else:
        text = f"userIdentity.arn like /[:/]{regex_escape(value)}(/|$)/"
    return text if op == "=" else f"not ({text})"


TRAIL_DERIVED = {
    "service": service_field,
    "principal": principal_field,
    "is_root": boolean('userIdentity.type = "Root"'),
    "access_denied": boolean(
        "errorCode like /AccessDenied|Unauthorized|Forbidden|AuthorizationError/"
    ),
    "global_service": boolean(
        f"(eventSource in [{GLOBAL_SOURCES}] "
        'or (eventSource = "sts.amazonaws.com" and awsRegion = "us-east-1"))'
    ),
    "mfa_used": mapped("additionalEventData.MFAUsed", {True: '"Yes"', False: '"No"'}),
}


def trail_mapping(cols: list[str]) -> dict[str, str]:
    """Map header names onto CloudTrail field names; unknown columns keep their own name."""
    out: dict[str, str] = {}
    taken: set[str] = set()
    for raw in cols:
        name = TRAIL_FIELDS.get(squash(raw), raw)
        if name in taken:
            name = raw
        taken.add(name)
        out[raw] = name
    return out


def looks_like_cloudtrail(sn: Sniff, mapping: dict[str, str]) -> bool:
    if not TRAIL_REQUIRED.issubset(mapping.values()):
        return False
    idx = [i for i, raw in enumerate(sn.columns) if mapping[raw] == "event_source"][0]
    sources = [r[idx] for r in sn.rows if idx < len(r) and r[idx]]
    return mostly([s.endswith(("amazonaws.com", "amazonaws.com.cn")) for s in sources])


class CloudTrailPlugin(FormatPlugin):
    name = "cloudtrail"
    table = "trail"

    def detect(self, sn: Sniff) -> FormatInfo | None:
        if not sn.has_header:
            return None
        mapping = trail_mapping(sn.columns)
        if not looks_like_cloudtrail(sn, mapping):
            return None
        known = sum(1 for raw, name in mapping.items() if name != raw)
        return self.found(
            Format.CLOUDTRAIL,
            "CloudTrail event export",
            f"header names {known} CloudTrail fields and every event source is an AWS service",
            columns=mapping,
        )

    def build_table(
        self, con: duckdb.DuckDBPyConnection, fmt: FormatInfo, source: str = "raw"
    ) -> list[str]:
        return build_trail_table(con, fmt, source, self.table)

    def findings(self, ds: Dataset) -> list[Finding]:
        return run_rules(ds)

    def timeline(self, ds: Dataset) -> dict[str, Any] | None:
        return build_timeline(ds)

    def query_spec(self, fmt: FormatInfo) -> QuerySpec | None:
        return QuerySpec(
            fields=dict(CW_TRAIL_FIELDS),
            time_columns=("event_time",),
            derived=TRAIL_DERIVED,
            display=TRAIL_DISPLAY,
            stats=TRAIL_STATS,
        )
