from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tests.conftest import ROOT


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
    ips = set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text))
    allowed = ("10.", "192.0.2.", "198.51.100.", "203.0.113.")
    assert ips and all(ip.startswith(allowed) for ip in ips)
    assert "123456789012" in text
