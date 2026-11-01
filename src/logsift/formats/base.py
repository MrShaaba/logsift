"""The format plug-in interface: what every file format must provide.

A format is a :class:`FormatPlugin`: a small class that knows how to recognise a sniffed
file, build a typed canonical table from the raw rows, and run its rules over that table.
Plug-ins are registered in ``logsift.formats.PLUGINS``; detection asks each in turn and
the first to answer owns the file.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any

import duckdb

from logsift.loader import Sniff

if TYPE_CHECKING:
    from logsift.dataset import Dataset
    from logsift.insights.base import Finding


class Format(StrEnum):
    GENERIC = "generic"
    VPC_V2 = "vpc_flow_v2"
    VPC_CUSTOM = "vpc_flow_custom"
    CW_INSIGHTS = "cloudwatch_insights"
    ALB = "alb_access"
    NLB = "nlb_access"
    CLOUDTRAIL = "cloudtrail_csv"
    S3_ACCESS = "s3_access"


@dataclass
class FormatInfo:
    """What detection found out about a file."""

    kind: Format
    label: str
    # Registry name of the plug-in that recognised the file and owns its rows.
    plugin: str = "generic"
    # Canonical table the plug-in builds from the raw rows. "" leaves the rows as loaded,
    # and means there are no findings for this file.
    table: str = ""
    # Raw column name -> canonical field name, for the columns the plug-in understands.
    columns: dict[str, str] = field(default_factory=dict)
    # Plug-in specific detection results, such as where the flow fields live.
    options: dict[str, str] = field(default_factory=dict)
    # AWS log formats write "-" for a field that has no value.
    dash_means_missing: bool = False
    reasons: list[str] = field(default_factory=list)

    @property
    def has_rules(self) -> bool:
        return bool(self.table)


class FormatPlugin(ABC):
    """One file format: how to recognise it, type its rows and judge them.

    Subclasses set ``name`` (the registry name), ``table`` (the canonical table they build,
    or "" for a format that only gets detected) and ``dash_means_missing``, then implement
    ``detect``. ``build_table`` must create ``self.table`` from the raw rows and return its
    column names; ``findings`` and ``timeline`` run over that table. Register an instance
    in ``logsift.formats.PLUGINS``.
    """

    name: str = ""
    table: str = ""
    dash_means_missing: bool = False

    @abstractmethod
    def detect(self, sn: Sniff) -> FormatInfo | None:
        """A FormatInfo when the sniffed file is in this format, otherwise None."""

    def build_table(
        self, con: duckdb.DuckDBPyConnection, fmt: FormatInfo, source: str = "raw"
    ) -> list[str]:
        """Create ``self.table`` from ``source`` and return its column names."""
        raise NotImplementedError(f"the {self.name} format does not build a table")

    def findings(self, ds: Dataset) -> list[Finding]:
        """Rule-based findings over the canonical table, most severe first."""
        return []

    def timeline(self, ds: Dataset) -> dict[str, Any] | None:
        """Good against bad rows per time bucket, or None when there is no time column."""
        return None

    def found(
        self,
        kind: Format,
        label: str,
        *reasons: str,
        columns: dict[str, str] | None = None,
        options: dict[str, str] | None = None,
        table: str | None = None,
    ) -> FormatInfo:
        """A FormatInfo for a file this plug-in recognised.

        ``table`` defaults to the plug-in's own; pass "" for a file that is recognised but
        cannot be given a canonical table (and so gets no findings). "-" only counts as a
        missing value once the plug-in owns the rows.
        """
        table = self.table if table is None else table
        return FormatInfo(
            kind=kind,
            label=label,
            plugin=self.name,
            table=table,
            columns=dict(columns or {}),
            options=dict(options or {}),
            dash_means_missing=self.dash_means_missing and bool(table),
            reasons=list(reasons),
        )


# ------------------------------------------------------------- detection helpers


def squash(name: str) -> str:
    """Lower-case a header name and drop everything but letters and digits."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def mostly(checks: list[bool]) -> bool:
    """True when at least 80% of the sampled lines pass."""
    return bool(checks) and sum(checks) / len(checks) >= 0.8


def positional(cols: list[str], names: list[str]) -> dict[str, str]:
    """Map raw column_N names onto known field names; anything past the end is extra_N."""
    out: dict[str, str] = {}
    for i, raw in enumerate(cols):
        out[raw] = names[i] if i < len(names) else f"extra_{i - len(names) + 1}"
    return out
