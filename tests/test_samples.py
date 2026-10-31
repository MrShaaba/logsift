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
