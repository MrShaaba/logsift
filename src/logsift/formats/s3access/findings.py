"""Rule-based findings for S3 server access logs. Filled in by the next step."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from logsift.dataset import Dataset
    from logsift.insights.base import Finding


def run_rules(ds: Dataset) -> list[Finding]:
    return []


def build_timeline(ds: Dataset) -> dict[str, Any] | None:
    return None
