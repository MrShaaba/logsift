"""Shared finding types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}


@dataclass
class Finding:
    id: str
    rule: str
    title: str
    severity: Severity
    summary: str
    explanation: str
    likely_cause: str
    row_count: int
    # SQL WHERE fragment over the flow table selecting the rows behind this finding.
    row_filter: str
    # Optional supporting table shown under the finding.
    table_columns: list[str] = field(default_factory=list)
    table_rows: list[tuple[Any, ...]] = field(default_factory=list)
    # Optional time series for a chart: list of (label, series dict).
    chart: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rule": self.rule,
            "title": self.title,
            "severity": str(self.severity),
            "summary": self.summary,
            "explanation": self.explanation,
            "likely_cause": self.likely_cause,
            "row_count": self.row_count,
            "details": [
                dict(zip(self.table_columns, row, strict=False)) for row in self.table_rows
            ],
        }
