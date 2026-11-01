"""Small SQL helpers shared by the table builders and the rules."""

from __future__ import annotations

from typing import Any


def q(ident: str) -> str:
    """Quote an identifier."""
    return '"' + ident.replace('"', '""') + '"'


def lit(value: Any) -> str:
    """Render a Python value as a SQL literal."""
    if value is None:
        return "NULL"
    if isinstance(value, int | float):
        return repr(value)
    return "'" + str(value).replace("'", "''") + "'"
