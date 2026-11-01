"""Format detection through the plug-in registry.

Every format lives in its own module under this package with a detector, a canonical
table builder and a findings module behind the :class:`FormatPlugin` interface.
``detect_format`` asks each plug-in in ``PLUGINS`` order and the first match wins, so the
order matters where shapes overlap and is written down next to the list.
"""

from __future__ import annotations

from logsift.formats.base import Format, FormatInfo, FormatPlugin, mostly, positional, squash
from logsift.formats.cloudtrail import CloudTrailPlugin
from logsift.formats.generic import GenericPlugin
from logsift.formats.loadbalancer import LoadBalancerPlugin
from logsift.formats.vpcflow import CloudWatchInsightsPlugin, VpcFlowPlugin
from logsift.loader import Sniff

__all__ = [
    "PLUGINS",
    "Format",
    "FormatInfo",
    "FormatPlugin",
    "detect_format",
    "mostly",
    "plugin_for",
    "positional",
    "squash",
]

PLUGINS: list[FormatPlugin] = [
    # Space-delimited lines without a header, starting with the listener type.
    LoadBalancerPlugin(),
    # Any header with CloudWatch's @-prefixed fields, flow log or not. Checked before
    # CloudTrail so a Logs Insights export keeps its CloudWatch label.
    CloudWatchInsightsPlugin(),
    # A header naming CloudTrail fields, with AWS services as the event sources. Checked
    # before the flow-log header match so an export with a "region" column is not
    # mistaken for a flow log.
    CloudTrailPlugin(),
    # Version 2 flow-log lines, or a header naming flow-log fields.
    VpcFlowPlugin(),
    # Everything else. Must stay last: it claims any file.
    GenericPlugin(),
]


def plugin_for(name: str) -> FormatPlugin:
    """The registered plug-in with this name."""
    for plugin in PLUGINS:
        if plugin.name == name:
            return plugin
    raise KeyError(f"no format plug-in named {name!r}")


def detect_format(sn: Sniff) -> FormatInfo:
    """Work out which format the sniffed file is in."""
    for plugin in PLUGINS:
        info = plugin.detect(sn)
        if info is not None:
            return info
    raise RuntimeError("no plug-in claimed the file; GenericPlugin must be registered")
