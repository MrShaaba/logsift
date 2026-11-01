"""Generate a multi-million-row VPC Flow Log for trying logsift on a large file.

Run with ``uv run python scripts/generate_big_flow_log.py [--rows 5000000] [--out
data/big_vpc_flow_logs.log] [--format v2|custom] [--gzip]``. The file is written under
``data/`` (which git ignores) and is never committed: it is seeded, so the same arguments
always produce the same bytes, and anyone can regenerate it on demand.

The log covers one day for the same fictional VPC as ``samples/`` (documentation address
ranges and the example account only) and streams one minute at a time, so generating it
needs almost no memory. The planted problems are the sample's, scaled to the day:

* a network ACL blocking return traffic from app host 10.0.2.10 back to the web tier
* the database security group rejecting PostgreSQL (5432) from the app tier
* one web host pushing a very large volume to a single public address, all day
* one public source sweeping a thousand ports on a web host inside four minutes
* SYN-only flows to a host that never answers
* NODATA and SKIPDATA records and a twenty minute gap at 13:00
"""

from __future__ import annotations

import argparse
import gzip
import random
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import IO

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_samples import (  # noqa: E402
    ACK,
    ALL_HOSTS,
    APP,
    BASTION,
    CUSTOM_FIELDS,
    DB,
    ICMP,
    IDLE,
    PUBLIC_CLIENTS,
    PUBLIC_SERVICES,
    RESOLVER,
    SYN,
    T0,
    TCP,
    UDP,
    WEB,
    Flow,
    tcp_pair,
)

SEED = 20260311
MINUTES = 24 * 60
DAY_START = T0.replace(hour=0, minute=0)
GAP_MINUTES = range(13 * 60, 13 * 60 + 20)
SWEEP_MINUTES = range(10 * 60, 10 * 60 + 4)
SWEEP_SRC = "198.51.100.77"
SWEEP_PORTS = range(20, 1021)
TOP_TALKER_DST = "203.0.113.9"
SILENT_HOST, SILENT_PORT = "10.0.2.99", 9200
PROGRESS_EVERY = 500_000


def quotas(rows: int) -> list[int]:
    """How many lines each minute of the day gets; the gap minutes get none."""
    active = [m for m in range(MINUTES) if m not in GAP_MINUTES]
    base, extra = divmod(rows, len(active))
    out = [0] * MINUTES
    for i, m in enumerate(active):
        out[m] = base + (1 if i < extra else 0)
    return out


def minute_flows(rng: random.Random, m: int, quota: int) -> list[Flow]:
    """Every flow record with a start time in minute ``m`` of the day, exactly ``quota`` of them."""
    t = DAY_START + timedelta(minutes=m)
    flows: list[Flow] = []

    # Planted: the sweep happens once, the top talker runs all day, NODATA/SKIPDATA tick.
    if m in SWEEP_MINUTES:
        i = m - SWEEP_MINUTES.start
        step = (len(SWEEP_PORTS) + len(SWEEP_MINUTES) - 1) // len(SWEEP_MINUTES)
        for port in list(SWEEP_PORTS)[i * step : (i + 1) * step]:
            action = "ACCEPT" if port == 443 else "REJECT"
            flows.append(
                Flow(WEB[0], SWEEP_SRC, WEB[0].ip, rng.randrange(40000, 60000), port, TCP, 1, 44,
                     t, action, "ingress", SYN)
            )  # fmt: skip
    flows += tcp_pair(
        rng, WEB[2], TOP_TALKER_DST, 443, t,
        req_bytes=(40_000_000, 60_000_000), resp_bytes=(50_000, 120_000),
    )  # fmt: skip
    if m % 5 == 0:
        flows.append(Flow(IDLE, "-", "-", 0, 0, 0, 0, 0, t, "-", "-", log_status="NODATA"))
    if m % 97 == 13:
        flows.append(
            Flow(rng.choice(WEB), "-", "-", 0, 0, 0, 0, 0, t, "-", "-", log_status="SKIPDATA")
        )

    while len(flows) < quota:
        r = rng.random()
        if r < 0.42:  # public clients browsing the web tier
            flows += tcp_pair(rng, rng.choice(PUBLIC_CLIENTS), rng.choice(WEB), 443, t)
        elif r < 0.52:  # web tier calling the healthy app host
            flows += tcp_pair(rng, rng.choice(WEB), APP[1], 8080, t)
        elif r < 0.58:  # app tier talking to the database, which is allowed from 10.0.2.11 only
            flows += tcp_pair(rng, APP[1], DB, 5432, t)
        elif r < 0.66:  # hosts calling public services
            flows += tcp_pair(rng, rng.choice(ALL_HOSTS), rng.choice(PUBLIC_SERVICES[1:]), 443, t)
        elif r < 0.80:  # DNS
            h = rng.choice(ALL_HOSTS)
            sport = rng.randrange(32768, 61000)
            flows.append(Flow(h, h.ip, RESOLVER, sport, 53, UDP, 2, rng.randrange(120, 300), t,
                              "ACCEPT", "egress", 0, "1"))  # fmt: skip
            flows.append(Flow(h, RESOLVER, h.ip, 53, sport, UDP, 2, rng.randrange(150, 600), t,
                              "ACCEPT", "ingress"))  # fmt: skip
        elif r < 0.83:  # bastion SSH and pings
            h = rng.choice([*WEB, *APP, DB])
            if rng.random() < 0.7:
                flows += tcp_pair(rng, BASTION, h, 22, t, resp_bytes=(2000, 20000))
            else:
                flows.append(Flow(h, BASTION.ip, h.ip, 0, 0, ICMP, 4, 336, t, "ACCEPT", "ingress"))
                flows.append(
                    Flow(h, h.ip, BASTION.ip, 0, 0, ICMP, 4, 336, t, "ACCEPT", "egress", 0, "1")
                )
        elif r < 0.88:  # internet noise rejected at the web tier
            web = rng.choice(WEB)
            flows.append(Flow(web, rng.choice(PUBLIC_CLIENTS), web.ip, rng.randrange(1024, 65000),
                              rng.choice([23, 445, 3389, 8080, 8443, 1433, 25]), TCP, 1,
                              rng.randrange(40, 60), t, "REJECT", "ingress", SYN))  # fmt: skip
        elif r < 0.94:  # planted A: the NACL blocks the reply from 10.0.2.10
            web = rng.choice(WEB)
            sport = rng.randrange(32768, 61000)
            req, resp = rng.randrange(180, 260), rng.randrange(120, 200)
            flows.append(
                Flow(
                    web,
                    web.ip,
                    APP[0].ip,
                    sport,
                    8080,
                    TCP,
                    3,
                    req,
                    t,
                    "ACCEPT",
                    "egress",
                    SYN,
                    "1",
                )
            )
            flows.append(
                Flow(
                    web,
                    APP[0].ip,
                    web.ip,
                    8080,
                    sport,
                    TCP,
                    3,
                    resp,
                    t,
                    "REJECT",
                    "ingress",
                    SYN | ACK,
                )
            )
            flows.append(
                Flow(
                    APP[0], web.ip, APP[0].ip, sport, 8080, TCP, 3, req, t, "ACCEPT", "ingress", SYN
                )
            )
            flows.append(
                Flow(
                    APP[0],
                    APP[0].ip,
                    web.ip,
                    8080,
                    sport,
                    TCP,
                    3,
                    resp,
                    t,
                    "ACCEPT",
                    "egress",
                    SYN | ACK,
                    "1",
                )
            )
        elif r < 0.97:  # planted B: the database security group refuses 10.0.2.10
            sport = rng.randrange(32768, 61000)
            n = rng.randrange(100, 140)
            flows.append(
                Flow(DB, APP[0].ip, DB.ip, sport, 5432, TCP, 2, n, t, "REJECT", "ingress", SYN)
            )
            flows.append(
                Flow(
                    APP[0],
                    APP[0].ip,
                    DB.ip,
                    sport,
                    5432,
                    TCP,
                    2,
                    n,
                    t,
                    "ACCEPT",
                    "egress",
                    SYN,
                    "1",
                )
            )
        else:  # planted E: SYN to a host that never answers
            app = rng.choice(APP)
            flows.append(Flow(app, app.ip, SILENT_HOST, rng.randrange(32768, 61000), SILENT_PORT,
                              TCP, 3, 180, t, "ACCEPT", "egress", SYN, "1"))  # fmt: skip
    del flows[quota:]
    flows.sort(key=lambda f: (f.eni.eni, f.src, f.dst, f.srcport, f.dstport))
    return flows


def write_log(out: Path, rows: int, fmt: str, seed: int, use_gzip: bool, log: IO[str]) -> Path:
    if use_gzip and out.suffix != ".gz":
        out = out.with_name(out.name + ".gz")
    out.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    per_minute = quotas(rows)
    written = 0
    started = time.monotonic()
    next_report = PROGRESS_EVERY
    raw = out.open("wb")
    fh: IO[bytes] = gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) if use_gzip else raw
    try:
        if fmt == "custom":
            fh.write((" ".join(CUSTOM_FIELDS) + "\n").encode())
        for m, quota in enumerate(per_minute):
            if not quota:
                continue
            flows = minute_flows(rng, m, quota)
            lines = [" ".join(f.custom() if fmt == "custom" else f.v2()) for f in flows]
            fh.write(("\n".join(lines) + "\n").encode())
            written += len(lines)
            if written >= next_report:
                elapsed = time.monotonic() - started
                print(
                    f"{written:,} of {rows:,} rows ({written / rows:.0%}, {elapsed:.0f}s)", file=log
                )
                next_report += PROGRESS_EVERY
    finally:
        fh.close()
        if use_gzip:
            raw.close()
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--rows", type=int, default=5_000_000, help="rows to write")
    parser.add_argument("--out", default="data/big_vpc_flow_logs.log", help="output file")
    parser.add_argument("--format", choices=["v2", "custom"], default="v2")
    parser.add_argument("--gzip", action="store_true", help="gzip the output")
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()
    out = write_log(Path(args.out), args.rows, args.format, args.seed, args.gzip, sys.stderr)
    size = out.stat().st_size
    print(f"wrote {out} ({args.rows:,} rows, {size / 1e6:,.1f} MB)")


if __name__ == "__main__":
    main()
