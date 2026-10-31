"""Generate fictional sample files with known problems planted in them.

Run with ``uv run python scripts/generate_samples.py [--out samples]``.

Everything here is made up. Addresses come from the documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and private 10.x space, and the
account ID is the AWS example account ``123456789012``.

Planted problems in the flow logs (see ``PLANTED`` for the exact values):

* a network ACL blocking return traffic from the app tier back to the web tier
* a security group rejecting PostgreSQL (5432) from the app tier to the database
* one noisy host sending a very large volume to a single public address
* one public source sweeping a range of ports on a web host
* SYN-only flows to a host that never answers (custom format only, needs tcp-flags)
* NODATA and SKIPDATA records and a twenty minute gap in the time range
"""

from __future__ import annotations

import argparse
import csv
import gzip
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

SEED = 20260310
ACCOUNT = "123456789012"
REGION = "eu-west-1"
AZ = "euw1-az1"
VPC = "vpc-0a1b2c3d4e5f60789"

T0 = datetime(2026, 3, 10, 8, 0, tzinfo=UTC)
DURATION = timedelta(hours=2)
GAP = (T0 + timedelta(minutes=75), T0 + timedelta(minutes=95))

PLANTED = {
    "nacl_return_block": {"server": "10.0.2.10", "port": 8080, "clients": "10.0.1.0/24"},
    "sg_rejects_5432": {"db": "10.0.3.20", "port": 5432, "clients": ["10.0.2.10", "10.0.2.11"]},
    "top_talker": {"src": "10.0.1.12", "dst": "203.0.113.9", "port": 443},
    "port_sweep": {"src": "198.51.100.77", "dst": "10.0.1.10", "ports": (20, 220)},
    "syn_no_synack": {"dst": "10.0.2.99", "port": 9200, "clients": ["10.0.2.10", "10.0.2.11"]},
}


@dataclass(frozen=True)
class Host:
    ip: str
    eni: str
    subnet: str
    instance: str


WEB = [
    Host("10.0.1.10", "eni-0a1b2c3d4e5f60101", "subnet-0a1b2c3d4e5f60001", "i-0a1b2c3d4e5f60101"),
    Host("10.0.1.11", "eni-0a1b2c3d4e5f60102", "subnet-0a1b2c3d4e5f60001", "i-0a1b2c3d4e5f60102"),
    Host("10.0.1.12", "eni-0a1b2c3d4e5f60103", "subnet-0a1b2c3d4e5f60001", "i-0a1b2c3d4e5f60103"),
]
APP = [
    Host("10.0.2.10", "eni-0b2c3d4e5f6a70201", "subnet-0b2c3d4e5f6a70002", "i-0b2c3d4e5f6a70201"),
    Host("10.0.2.11", "eni-0b2c3d4e5f6a70202", "subnet-0b2c3d4e5f6a70002", "i-0b2c3d4e5f6a70202"),
]
DB = Host("10.0.3.20", "eni-0c3d4e5f6a7b80301", "subnet-0c3d4e5f6a7b80003", "i-0c3d4e5f6a7b80301")
BASTION = Host(
    "10.0.0.5", "eni-0d4e5f6a7b8c90005", "subnet-0d4e5f6a7b8c90000", "i-0d4e5f6a7b8c90005"
)
IDLE = Host("10.0.0.9", "eni-0e5f6a7b8c9d00009", "subnet-0d4e5f6a7b8c90000", "i-0e5f6a7b8c9d00009")
ALL_HOSTS = [*WEB, *APP, DB, BASTION]

RESOLVER = "10.0.0.2"
PUBLIC_CLIENTS = [f"198.51.100.{i}" for i in range(10, 60)] + [
    f"203.0.113.{i}" for i in range(10, 60)
]
PUBLIC_SERVICES = ["203.0.113.9", "192.0.2.44", "192.0.2.45", "198.51.100.200"]

V2_FIELDS = [
    "version",
    "account-id",
    "interface-id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log-status",
]
CUSTOM_FIELDS = [
    *V2_FIELDS,
    "vpc-id",
    "subnet-id",
    "instance-id",
    "tcp-flags",
    "type",
    "pkt-srcaddr",
    "pkt-dstaddr",
    "region",
    "az-id",
    "flow-direction",
    "traffic-path",
]

TCP, UDP, ICMP = 6, 17, 1
SYN, FIN, RST, ACK = 2, 1, 4, 16


@dataclass
class Flow:
    eni: Host
    src: str
    dst: str
    srcport: int
    dstport: int
    proto: int
    packets: int
    bytes: int
    start: datetime
    action: str
    direction: str
    tcp_flags: int = 0
    traffic_path: str = "-"
    log_status: str = "OK"
    extra: dict[str, str] = field(default_factory=dict)

    def v2(self) -> list[str]:
        if self.log_status != "OK":
            return [
                "2",
                ACCOUNT,
                self.eni.eni,
                *["-"] * 7,
                str(int(self.start.timestamp())),
                str(int(self.start.timestamp()) + 60),
                "-",
                self.log_status,
            ]
        return [
            "2",
            ACCOUNT,
            self.eni.eni,
            self.src,
            self.dst,
            str(self.srcport),
            str(self.dstport),
            str(self.proto),
            str(self.packets),
            str(self.bytes),
            str(int(self.start.timestamp())),
            str(int(self.start.timestamp()) + 59),
            self.action,
            self.log_status,
        ]

    def custom(self) -> list[str]:
        base = self.v2()
        base[0] = "5"
        if self.log_status != "OK":
            return [*base, VPC, self.eni.subnet, self.eni.instance, *["-"] * 8]
        return [
            *base,
            VPC,
            self.eni.subnet,
            self.eni.instance,
            str(self.tcp_flags) if self.proto == TCP else "0",
            "IPv4",
            self.src,
            self.dst,
            REGION,
            AZ,
            self.direction,
            self.traffic_path if self.direction == "egress" else "-",
        ]


def is_public(ip: str) -> bool:
    return not ip.startswith("10.")


def minute(rng: random.Random, lo: datetime | None = None, hi: datetime | None = None) -> datetime:
    """A random whole minute inside the range, never inside the planted gap."""
    lo = lo or T0
    hi = hi or (T0 + DURATION)
    span = int((hi - lo).total_seconds() // 60)
    while True:
        t = lo + timedelta(minutes=rng.randrange(span))
        if not (GAP[0] <= t < GAP[1]):
            return t


def tcp_pair(
    rng: random.Random,
    client: Host | str,
    server: Host | str,
    port: int,
    start: datetime,
    *,
    req_bytes: tuple[int, int] = (400, 4000),
    resp_bytes: tuple[int, int] = (1000, 60000),
    client_eni: Host | None = None,
    server_eni: Host | None = None,
) -> list[Flow]:
    """A completed TCP exchange as seen on whichever ENIs are in the VPC."""
    cip = client.ip if isinstance(client, Host) else client
    sip = server.ip if isinstance(server, Host) else server
    client_eni = client_eni or (client if isinstance(client, Host) else None)
    server_eni = server_eni or (server if isinstance(server, Host) else None)
    sport = rng.randrange(32768, 61000)
    pk_req = rng.randrange(5, 40)
    pk_resp = rng.randrange(5, 60)
    b_req = rng.randrange(*req_bytes)
    b_resp = rng.randrange(*resp_bytes)
    flows: list[Flow] = []
    path = "1" if not is_public(sip) else "2"
    if client_eni is not None:
        flows.append(
            Flow(
                client_eni,
                cip,
                sip,
                sport,
                port,
                TCP,
                pk_req,
                b_req,
                start,
                "ACCEPT",
                "egress",
                SYN | ACK | FIN,
                path,
            )
        )
        flows.append(
            Flow(
                client_eni,
                sip,
                cip,
                port,
                sport,
                TCP,
                pk_resp,
                b_resp,
                start,
                "ACCEPT",
                "ingress",
                SYN | ACK | FIN,
            )
        )
    if server_eni is not None:
        flows.append(
            Flow(
                server_eni,
                cip,
                sip,
                sport,
                port,
                TCP,
                pk_req,
                b_req,
                start,
                "ACCEPT",
                "ingress",
                SYN | ACK | FIN,
            )
        )
        flows.append(
            Flow(
                server_eni,
                sip,
                cip,
                port,
                sport,
                TCP,
                pk_resp,
                b_resp,
                start,
                "ACCEPT",
                "egress",
                SYN | ACK | FIN,
                path,
            )
        )
    return flows


def background(rng: random.Random) -> list[Flow]:
    flows: list[Flow] = []
    # Public clients browsing the web tier over HTTPS.
    for _ in range(1400):
        web = rng.choice(WEB)
        flows += tcp_pair(rng, rng.choice(PUBLIC_CLIENTS), web, 443, minute(rng))
    # Web tier calling the second app host, which works fine (only 10.0.2.10 is broken).
    for _ in range(300):
        flows += tcp_pair(rng, rng.choice(WEB), APP[1], 8080, minute(rng))
    # Hosts calling public services (package mirrors, APIs).
    for _ in range(250):
        h = rng.choice(ALL_HOSTS)
        flows += tcp_pair(rng, h, rng.choice(PUBLIC_SERVICES[1:]), 443, minute(rng))
    # DNS to the VPC resolver.
    for _ in range(600):
        h = rng.choice(ALL_HOSTS)
        t = minute(rng)
        sport = rng.randrange(32768, 61000)
        flows.append(
            Flow(
                h,
                h.ip,
                RESOLVER,
                sport,
                53,
                UDP,
                2,
                rng.randrange(120, 300),
                t,
                "ACCEPT",
                "egress",
                0,
                "1",
            )
        )
        flows.append(
            Flow(
                h,
                RESOLVER,
                h.ip,
                53,
                sport,
                UDP,
                2,
                rng.randrange(150, 600),
                t,
                "ACCEPT",
                "ingress",
            )
        )
    # Bastion SSH into hosts.
    for _ in range(120):
        h = rng.choice([*WEB, *APP, DB])
        flows += tcp_pair(rng, BASTION, h, 22, minute(rng), resp_bytes=(2000, 20000))
    # ICMP health pings from the bastion.
    for _ in range(80):
        h = rng.choice([*WEB, *APP])
        t = minute(rng)
        flows.append(Flow(h, BASTION.ip, h.ip, 0, 0, ICMP, 4, 336, t, "ACCEPT", "ingress"))
        flows.append(Flow(h, h.ip, BASTION.ip, 0, 0, ICMP, 4, 336, t, "ACCEPT", "egress", 0, "1"))
    # Ordinary internet noise rejected at the web tier (a handful of ports).
    for _ in range(180):
        web = rng.choice(WEB)
        port = rng.choice([23, 445, 3389, 8080, 8443, 1433, 25])
        src = rng.choice(PUBLIC_CLIENTS)
        flows.append(
            Flow(
                web,
                src,
                web.ip,
                rng.randrange(1024, 65000),
                port,
                TCP,
                1,
                rng.randrange(40, 60),
                minute(rng),
                "REJECT",
                "ingress",
                SYN,
            )
        )
    return flows


def planted(rng: random.Random) -> list[Flow]:
    flows: list[Flow] = []

    # A: NACL on the web subnet blocks the ephemeral-port return path from app host 10.0.2.10.
    #    Request is ACCEPTed leaving the web ENI, the reply is REJECTed coming back in.
    for _ in range(320):
        web = rng.choice(WEB)
        t = minute(rng)
        sport = rng.randrange(32768, 61000)
        flows.append(
            Flow(
                web,
                web.ip,
                APP[0].ip,
                sport,
                8080,
                TCP,
                3,
                rng.randrange(180, 260),
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
                rng.randrange(120, 200),
                t,
                "REJECT",
                "ingress",
                SYN | ACK,
            )
        )
        # The app ENI sees the request arrive and its own reply leave normally.
        flows.append(
            Flow(
                APP[0],
                web.ip,
                APP[0].ip,
                sport,
                8080,
                TCP,
                3,
                rng.randrange(180, 260),
                t,
                "ACCEPT",
                "ingress",
                SYN,
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
                rng.randrange(120, 200),
                t,
                "ACCEPT",
                "egress",
                SYN | ACK,
                "1",
            )
        )

    # B: The database security group does not allow 5432 from the app tier.
    for _ in range(160):
        app = rng.choice(APP)
        t = minute(rng)
        sport = rng.randrange(32768, 61000)
        flows.append(
            Flow(
                DB,
                app.ip,
                DB.ip,
                sport,
                5432,
                TCP,
                2,
                rng.randrange(100, 140),
                t,
                "REJECT",
                "ingress",
                SYN,
            )
        )
        flows.append(
            Flow(
                app,
                app.ip,
                DB.ip,
                sport,
                5432,
                TCP,
                2,
                rng.randrange(100, 140),
                t,
                "ACCEPT",
                "egress",
                SYN,
                "1",
            )
        )

    # C: One web host pushing a very large volume to a single public address.
    talk = PLANTED["top_talker"]
    web = WEB[2]
    for i in range(110):
        t = T0 + timedelta(minutes=i)
        if GAP[0] <= t < GAP[1]:
            continue
        flows += tcp_pair(
            rng,
            web,
            str(talk["dst"]),
            443,
            t,
            req_bytes=(40_000_000, 60_000_000),
            resp_bytes=(50_000, 120_000),
        )

    # D: One public source sweeps ports 20..220 on a web host inside three minutes.
    sweep = PLANTED["port_sweep"]
    lo, hi = sweep["ports"]  # type: ignore[misc]
    target = WEB[0]
    base = T0 + timedelta(minutes=40)
    for i, port in enumerate(range(int(lo), int(hi) + 1)):
        t = base + timedelta(minutes=i // 70)
        action = "ACCEPT" if port == 443 else "REJECT"
        flows.append(
            Flow(
                target,
                str(sweep["src"]),
                target.ip,
                rng.randrange(40000, 60000),
                port,
                TCP,
                1,
                44,
                t,
                action,
                "ingress",
                SYN,
            )
        )

    # E: SYN sent to a host that never answers (nothing listening, no reject either).
    syn = PLANTED["syn_no_synack"]
    for _ in range(130):
        app = rng.choice(APP)
        t = minute(rng)
        flows.append(
            Flow(
                app,
                app.ip,
                str(syn["dst"]),
                rng.randrange(32768, 61000),
                int(syn["port"]),
                TCP,
                3,
                180,
                t,
                "ACCEPT",
                "egress",
                SYN,
                "1",
            )
        )

    # F: NODATA from an idle interface, and a few SKIPDATA records.
    for i in range(0, 120, 5):
        t = T0 + timedelta(minutes=i)
        if GAP[0] <= t < GAP[1]:
            continue
        flows.append(Flow(IDLE, "-", "-", 0, 0, 0, 0, 0, t, "-", "-", log_status="NODATA"))
    for _ in range(6):
        flows.append(
            Flow(
                rng.choice(WEB),
                "-",
                "-",
                0,
                0,
                0,
                0,
                0,
                minute(rng),
                "-",
                "-",
                log_status="SKIPDATA",
            )
        )
    return flows


def write_flow_files(out: Path, flows: list[Flow]) -> None:
    flows.sort(key=lambda f: (f.start, f.eni.eni, f.src, f.dst))

    v2_lines = [" ".join(f.v2()) for f in flows]
    (out / "vpc_flow_logs_v2.log").write_text("\n".join(v2_lines) + "\n")
    with (
        (out / "vpc_flow_logs_v2.log.gz").open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz,
    ):
        gz.write(("\n".join(v2_lines) + "\n").encode())

    custom_lines = [" ".join(CUSTOM_FIELDS)] + [" ".join(f.custom()) for f in flows]
    (out / "vpc_flow_logs_custom_v5.log").write_text("\n".join(custom_lines) + "\n")

    # A CloudWatch Logs Insights export of the same log group, first 40 minutes only.
    cutoff = T0 + timedelta(minutes=40)
    with (out / "cloudwatch_insights_export.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["@timestamp", "@message", "srcAddr", "dstAddr", "dstPort", "action"])
        for f in flows:
            if f.start >= cutoff:
                break
            msg = " ".join(f.v2())
            ts = f.start.strftime("%Y-%m-%d %H:%M:%S.000")
            if f.log_status != "OK":
                w.writerow([ts, msg, "", "", "", ""])
            else:
                w.writerow([ts, msg, f.src, f.dst, f.dstport, f.action])


def write_sales(out: Path, rng: random.Random) -> None:
    stores = ["Harbour Street", "Mill Lane", "Online"]
    products = {
        "Coffee": [
            ("Espresso beans 250g", 7.5),
            ("Filter blend 1kg", 18.0),
            ("Cold brew pack", 9.0),
        ],
        "Tea": [("Breakfast tea 80", 4.2), ("Green tea 40", 5.6)],
        "Equipment": [("Hand grinder", 39.0), ("Pour-over kit", 27.5), ("Travel mug", 16.0)],
    }
    methods = ["card", "cash", "voucher"]
    day0 = datetime(2025, 1, 1, tzinfo=UTC)
    with (out / "daily_sales.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "date",
                "store",
                "category",
                "product",
                "units",
                "unit_price",
                "discount_pct",
                "revenue",
                "payment_method",
                "customer_rating",
                "notes",
            ]
        )
        for d in range(365):
            day = day0 + timedelta(days=d)
            weekend = day.weekday() >= 5
            for store in stores:
                for category, items in products.items():
                    name, price = rng.choice(items)
                    units = max(0, int(rng.gauss(14 if weekend else 9, 4)))
                    if store == "Online":
                        units = int(units * 1.6)
                    disc = rng.choice([0, 0, 0, 5, 10, 15])
                    revenue = round(units * price * (1 - disc / 100), 2)
                    rating = rng.choice(["", "", 3, 4, 4, 5, 5, 5, 2])
                    note = ""
                    if units == 0:
                        note = "no sales recorded"
                    elif rng.random() < 0.03:
                        note = rng.choice(
                            ["promo day", "stock-out mid afternoon", "staff training"]
                        )
                    w.writerow(
                        [
                            day.date().isoformat(),
                            store,
                            category,
                            name,
                            units,
                            f"{price:.2f}",
                            disc,
                            f"{revenue:.2f}",
                            rng.choice(methods),
                            rating,
                            note,
                        ]
                    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default="samples", help="output directory")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    rng = random.Random(SEED)
    flows = background(rng) + planted(rng)
    write_flow_files(out, flows)
    write_sales(out, random.Random(SEED + 1))
    for p in sorted(out.iterdir()):
        print(f"{p.name:40s} {p.stat().st_size / 1024:8.0f} KB")


if __name__ == "__main__":
    main()
