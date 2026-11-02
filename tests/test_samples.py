from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import ROOT

ALLOWED_PREFIXES = ("10.", "192.0.2.", "198.51.100.", "203.0.113.")
IP_RE = r"(?<![/\w.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"  # skips Chrome/124.0.0.0


def test_generator_is_deterministic_and_matches_shipped_samples(tmp_path: Path) -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate_samples.py"), "--out", str(tmp_path)],
        check=True,
        capture_output=True,
    )
    shipped = sorted(p.name for p in (ROOT / "samples").iterdir() if p.is_file())
    fresh = sorted(p.name for p in tmp_path.iterdir())
    assert fresh == shipped
    for name in shipped:
        assert (tmp_path / name).read_bytes() == (ROOT / "samples" / name).read_bytes(), name


def test_samples_only_use_documentation_and_private_addresses() -> None:
    import re

    text = (ROOT / "samples" / "vpc_flow_logs_custom_v5.log").read_text()
    ips = set(re.findall(IP_RE, text))
    assert ips and all(ip.startswith(ALLOWED_PREFIXES) for ip in ips)
    assert "123456789012" in text


@pytest.mark.parametrize("name", ["alb_access_logs.log", "nlb_access_logs.log"])
def test_load_balancer_samples_are_fictional(name: str) -> None:
    import re

    text = (ROOT / "samples" / name).read_text()
    ips = set(re.findall(IP_RE, text))
    assert ips and all(ip.startswith(ALLOWED_PREFIXES) for ip in ips)
    hosts = set(re.findall(r"[a-z0-9.-]+\.(?:com|net|org|io)\b", text))
    assert hosts <= {"shop.example.com", "api.example.com"}
    assert "123456789012" in text
    assert "eu-west-1" in text


def test_cloudtrail_sample_is_fictional() -> None:
    import re

    text = (ROOT / "samples" / "cloudtrail_events.csv").read_text()
    ips = set(re.findall(IP_RE, text)) - {"0.0.0.0"}  # the open-to-the-world CIDR in a rule
    assert ips and all(ip.startswith(ALLOWED_PREFIXES) for ip in ips)
    hosts = set(re.findall(r"[a-z0-9.-]+\.(?:com|net|org|io)\b", text))
    assert hosts and all(h.endswith(("amazonaws.com", "aws.amazon.com")) for h in hosts)
    # Twelve digits not inside a hex id (a UUID segment can happen to be all digits).
    accounts = set(re.findall(r"(?<![0-9a-f-])\d{12}(?![0-9a-f])", text))
    assert accounts == {"123456789012"}
    keys = set(re.findall(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", text))
    assert keys and all("EXAMPLE" in k for k in keys)


def test_s3_sample_is_fictional() -> None:
    import re

    text = (ROOT / "samples" / "s3_access_logs.log").read_text()
    ips = set(re.findall(IP_RE, text))
    assert ips and all(ip.startswith(ALLOWED_PREFIXES) for ip in ips)
    hosts = set(re.findall(r"[a-z0-9.-]+\.(?:com|net|org|io)\b", text))
    assert hosts and all(h.endswith(("amazonaws.com", "example.com")) for h in hosts)
    # Random host ids and signatures can contain twelve digits in a row, so look at the
    # account field of every ARN instead of every twelve-digit run.
    accounts = set(re.findall(r"arn:aws:[a-z0-9-]+::(\d{12}):", text))
    assert accounts == {"123456789012"}
    keys = set(re.findall(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", text))
    assert keys and all("EXAMPLE" in k for k in keys)
    assert "shop-assets-example" in text


@pytest.mark.parametrize(
    "name", ["route53_resolver_query_logs.json", "route53_resolver_query_logs.csv"]
)
def test_resolver_samples_are_fictional(name: str) -> None:
    import re

    text = (ROOT / "samples" / name).read_text()
    # Reverse lookups spell addresses backwards (1.1.0.10.in-addr.arpa); skip those.
    ips = set(re.findall(IP_RE, re.sub(r"[0-9.]+\.in-addr\.arpa\.", "", text)))
    assert ips and all(ip.startswith(ALLOWED_PREFIXES) for ip in ips)
    names = set(re.findall(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+\.(?=[\s\",])", text))
    assert names
    allowed = (
        "example.com.",
        "example.net.",
        "example.org.",
        "example.internal.",
        "amazonaws.com.",
        "in-addr.arpa.",
        ".example.",
        ".test.",
        ".invalid.",
        "exmaple.com.",
    )
    odd = sorted(n for n in names if not n.endswith(allowed))
    assert not odd, odd[:5]
    if name.endswith(".json"):
        assert "123456789012" in text
