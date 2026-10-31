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
class Table:
    title: str
    columns: list[str]
    rows: list[tuple[Any, ...]]

    def to_dicts(self) -> list[dict[str, Any]]:
        return [dict(zip(self.columns, row, strict=False)) for row in self.rows]


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
    tables: list[Table] = field(default_factory=list)
    # Optional series for a chart: {"labels": [...], "series": {"name": [...]}}
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
            "tables": [{"title": t.title, "rows": t.to_dicts()} for t in self.tables],
        }


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], -f.row_count, f.title))
