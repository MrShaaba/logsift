"""The on-demand large flow log generator, and the sample-then-full-pass path over its output."""

from __future__ import annotations

import gzip
import re
import subprocess
import sys
from pathlib import Path

from logsift.dataset import Dataset
from logsift.formats import Format
from logsift.loader import LoadProgress
from tests.conftest import ROOT
from tests.test_samples import ALLOWED_PREFIXES, IP_RE

SCRIPT = ROOT / "scripts" / "generate_big_flow_log.py"
CHUNK = 256 * 1024


def generate(out: Path, rows: int, *extra: str) -> Path:
    done = subprocess.run(
        [sys.executable, str(SCRIPT), "--rows", str(rows), "--out", str(out), *extra],
        check=True,
        capture_output=True,
        text=True,
    )
    assert done.stdout.startswith("wrote ")
    return Path(done.stdout.split()[1])


def test_generator_is_deterministic_and_fictional(tmp_path: Path) -> None:
    a = generate(tmp_path / "a.log", 30_000)
    b = generate(tmp_path / "b.log", 30_000)
    assert a.read_bytes() == b.read_bytes()
    assert a.read_bytes() != generate(tmp_path / "c.log", 30_000, "--seed", "7").read_bytes()
    text = a.read_text()
    lines = text.splitlines()
    assert len(lines) == 30_000 and all(len(ln.split(" ")) == 14 for ln in lines)
    ips = set(re.findall(IP_RE, text))
    assert ips and all(ip.startswith(ALLOWED_PREFIXES) for ip in ips)
    assert "123456789012" in text
    # Records are in time order and the day has its twenty minute gap.
    starts = [int(ln.split(" ")[10]) for ln in lines]
    assert starts == sorted(starts)
    minutes = {s // 60 for s in starts}
    day0 = min(minutes)
    assert len(minutes) == 24 * 60 - 20
    assert all(day0 + m not in minutes for m in range(13 * 60, 13 * 60 + 20))


def test_custom_format_and_gzip(tmp_path: Path) -> None:
    out = generate(tmp_path / "custom.log", 3000, "--format", "custom", "--gzip")
    assert out.name == "custom.log.gz"
    with gzip.open(out, "rt") as fh:
        lines = fh.read().splitlines()
    assert lines[0].startswith("version account-id interface-id") and len(lines) == 3001
    ds = Dataset.open(out)
    assert ds.format.kind == Format.VPC_CUSTOM and ds.rows == 3000 and ds.table == "flow"
    assert any(f.id == "syn-no-synack" for f in ds.findings)  # needs tcp-flags, custom only
    ds.close()


def test_sample_then_full_pass_over_a_generated_log(tmp_path: Path) -> None:
    path = generate(tmp_path / "big.log", 60_000)
    size = path.stat().st_size
    seen: list[tuple[int, int]] = []
    ds = Dataset.open(
        path,
        limit=20_000,
        chunk_bytes=CHUNK,
        progress=lambda p: seen.append((p.rows, p.bytes_read)),
    )
    assert ds.format.kind == Format.VPC_V2 and ds.table == "flow"
    assert ds.is_sample and ds.rows == 20_000
    assert len(seen) > 3 and seen == sorted(seen) and seen[-1][0] == 20_000
    assert 0.25 < ds.fraction_loaded < 0.45
    assert ds.timeline is not None and ds.findings
    sample_titles = {f.id: f.title for f in ds.findings}
    assert "asymmetric" in sample_titles

    phases: list[str] = []

    def watch(p: LoadProgress) -> None:
        phases.append(p.phase)
        assert p.total_bytes == size

    ds.run_full_pass(progress=watch)
    assert not ds.is_sample and ds.rows == 60_000 and ds.fraction_loaded == 1.0
    assert phases[0] == "reading" and phases[-1] == "ready"
    ids = {f.id: f for f in ds.findings}
    assert ids["asymmetric"].title != sample_titles["asymmetric"]  # recomputed over everything
    assert ids["asymmetric"].title == (
        "Return traffic blocked: 1,445 requests accepted but replies rejected"
    )
    assert ids["reject-cluster-1"].title == "TCP port 5432 to 10.0.3.20 rejected 721 times"
    assert ids["top-talkers"].title.startswith("Top talker: 10.0.1.12 sent 66.2 GB")
    assert ids["time-gaps"].title == "1 gap in the time range (21 minutes with no records)"
    assert any(i.startswith("port-sweep") for i in ids)
    assert ds.profile.rows == 60_000
    # Row order survived the chunked load and the resume.
    rows = ds.cursor().execute("SELECT start FROM flow ORDER BY row_no").fetchall()
    starts = [r[0] for r in rows]
    assert starts == sorted(starts)
    ds.close()
