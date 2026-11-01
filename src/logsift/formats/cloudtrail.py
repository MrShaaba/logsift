"""CloudTrail event exports as CSV: the console download, a CloudTrail Lake or Athena
result, or a flattened export with columns like userIdentity.type."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import duckdb

from logsift.formats.base import Format, FormatInfo, FormatPlugin, mostly, squash
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
        from logsift.trail import build_trail_table

        return build_trail_table(con, fmt, source, self.table)

    def findings(self, ds: Dataset) -> list[Finding]:
        from logsift.insights.cloudtrail import run_rules

        return run_rules(ds)

    def timeline(self, ds: Dataset) -> dict[str, Any] | None:
        from logsift.insights.cloudtrail import build_timeline

        return build_timeline(ds)
