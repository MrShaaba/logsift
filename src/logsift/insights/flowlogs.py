"""Placeholder, rules land in the next step."""

from __future__ import annotations

from typing import TYPE_CHECKING

from logsift.insights.base import Finding

if TYPE_CHECKING:
    from logsift.dataset import Dataset


def run_rules(ds: Dataset) -> list[Finding]:
    return []
