"""The fallback format: any delimited file we could sniff. No table, no rules."""

from __future__ import annotations

from logsift.formats.base import Format, FormatInfo, FormatPlugin
from logsift.loader import Sniff


class GenericPlugin(FormatPlugin):
    name = "generic"

    def detect(self, sn: Sniff) -> FormatInfo | None:
        return self.found(
            Format.GENERIC,
            "Generic delimited file",
            f"{sn.delimiter_name}-separated with {len(sn.columns)} columns",
        )
