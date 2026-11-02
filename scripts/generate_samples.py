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

Planted problems in the load balancer logs (see ``LB_PLANTED``):

* ALB: one API target returning 502 for twenty minutes while its health check passes
* ALB: one report endpoint taking seconds per request and sometimes timing out (504)
* ALB: one public address probing dozens of well-known paths, plus malformed requests
* ALB: an old integration still negotiating TLS 1.1
* NLB: TLS handshakes aborted by clients (unknown CA, bad certificate, no client hello)
* NLB: one client opening hundreds of very short connections in four minutes

Planted problems in the CloudTrail export (see ``TRAIL_PLANTED``):

* one IAM user's access key used from an unknown address to try two dozen actions,
  nearly all denied, which is what testing a stolen key looks like
* the web tier's role denied one SSM parameter every thirty seconds, a steady retry loop
* console sign-ins without MFA, one of them by the root account
* root creating an administrator user and an access key for it
* that new user launching GPU instances in two regions the account never uses

Planted problems in the S3 server access log (see ``S3_PLANTED``):

* a bucket policy that lets anyone list the bucket and read ``backups/``, and a stranger
  who does exactly that, pulling gigabytes of database dumps without signing a request
* another stranger guessing sixty file names worth stealing, refused every time
* a cleanup script deleting three hundred thumbnails, and the shop's 404s from then on
* a batch role missing permission on one prefix and retrying every five minutes
* a short burst of 503 SlowDown during an upload spike

Planted problems in the Route 53 Resolver query log (see ``RESOLVER_PLANTED``):

* an app host walking through 1,500 algorithmically generated names in twelve minutes,
  nearly all NXDOMAIN, which is what malware looking for its controller looks like
* the bastion looking up every host name in the internal zone and the reverse records
  for a whole subnet in ten minutes: someone mapping the network
* a web host asking for names on a DNS Firewall block list every twenty seconds, all day
* an app host moving data over DNS: hundreds of TXT queries with long random labels under
  one domain, and long answers back
* six minutes of SERVFAIL for the internal zone while the forwarding endpoint was down

The cutover pair (``cutover_before_flow_logs.log`` and ``cutover_after_flow_logs.log``) is
the same hour of flow logs the day before and the day after a change, for ``logsift diff``
(see ``CUTOVER_PLANTED``):

* the database security group was replaced and no longer allows the app tier on 5432
* the web subnet's network ACL lost its ephemeral-port allow, so replies from the second
  app host on 8080 are rejected while requests still leave
* the cache moved from 10.0.2.30 to 10.0.2.40, so one destination disappears and a new
  host appears, and a third app host joined the tier
"""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import json
import math
import random
import uuid
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


# ------------------------------------------------------------ load balancer access logs

ALB_NAME = "app/shop-web/50dc6c495c0c9188"
NLB_NAME = "net/shop-api-tls/c6e77e28c25b2234"
NLB_LISTENER = "a1b2c3d4e5f60789"
NLB_ADDRESS = "192.0.2.80:443"
DOMAIN = "shop.example.com"
API_DOMAIN = "api.example.com"
CERT_ARN = f"arn:aws:acm:{REGION}:{ACCOUNT}:certificate/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
CERT_SERIAL = "03:0a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8"
TG_WEB = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/shop-web/73e2d6bc24d8a067"
TG_API = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/shop-api/8f2a1b3c4d5e6f70"
WEB_TARGETS = [f"{h.ip}:80" for h in WEB]
API_TARGETS = [f"{h.ip}:8080" for h in APP]

LB_PLANTED = {
    "failing_target": {"target": "10.0.2.11:8080", "window": ("09:05", "09:25"), "status": 502},
    "slow_path": {"path": "/api/reports/export", "timeouts": 8},
    "path_probing": {"client": "198.51.100.77", "window": ("08:40", "08:43")},
    "legacy_tls": {"client": "203.0.113.61", "protocol": "TLSv1.1"},
    "nlb_unknown_ca": {"client": "203.0.113.61", "alert": 48},
    "nlb_bad_certificate": {"client": "198.51.100.88", "alert": 42},
    "nlb_no_client_hello": {"client": "198.51.100.33"},
    "nlb_connection_churn": {"client": "198.51.100.23", "window": ("08:30", "08:34")},
}

BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Mobile Safari/537.36",
    "shop-mobile-app/3.2.1 (Android 14)",
    "shop-mobile-app/3.2.0 (iOS 17.4)",
]
SCANNER_AGENT = "python-requests/2.31.0"
LEGACY_AGENT = "Java/1.7.0_80"

TLS13 = ("TLS_AES_128_GCM_SHA256", "TLSv1.3")
TLS12 = ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2")
TLS11 = ("ECDHE-RSA-AES128-SHA", "TLSv1.1")

WORDS = ["kettle", "grinder", "filter", "mug", "beans", "espresso", "decaf", "gift"]
WEB_PATHS = [
    ("GET", "/", 30),
    ("GET", "/products", 20),
    ("GET", "/products/{id}", 60),
    ("GET", "/products/{id}/reviews", 10),
    ("GET", "/search?q={word}", 15),
    ("GET", "/cart", 15),
    ("POST", "/cart", 10),
    ("GET", "/checkout", 6),
    ("POST", "/checkout", 4),
    ("GET", "/account/orders", 6),
    ("GET", "/static/app.css", 25),
    ("GET", "/static/app.js", 25),
    ("GET", "/static/img/{n}.png", 40),
]
API_PATHS = [
    ("GET", "/api/products", 30),
    ("GET", "/api/products/{id}", 40),
    ("GET", "/api/cart", 15),
    ("POST", "/api/cart/items", 10),
    ("POST", "/api/orders", 6),
    ("GET", "/api/orders/{id}", 8),
    ("GET", "/api/health", 12),
]
PROBE_PATHS = [
    "/wp-login.php",
    "/wp-admin/",
    "/xmlrpc.php",
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/phpmyadmin/",
    "/phpmyadmin/index.php",
    "/pma/index.php",
    "/admin/",
    "/admin/login",
    "/administrator/",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/config.php",
    "/config.json",
    "/wp-config.php.bak",
    "/.aws/credentials",
    "/.DS_Store",
    "/server-status",
    "/actuator/health",
    "/actuator/env",
    "/console/",
    "/manager/html",
    "/solr/admin/",
    "/jenkins/login",
    "/cgi-bin/test.cgi",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/owa/auth/logon.aspx",
    "/boaform/admin/formLogin",
    "/HNAP1/",
    "/shell",
    "/cmd",
    "/debug/pprof/",
    "/swagger-ui.html",
    "/api/v1/users",
    "/api/swagger.json",
    "/graphql",
    "/login.php",
    "/user/login",
    "/sitemap.xml.bak",
    "/robots.txt.old",
    "/.svn/entries",
    "/.hg/requires",
    "/id_rsa",
    "/.ssh/id_rsa",
    "/etc/passwd",
    "/../../etc/passwd",
    "/webdav/",
    "/elmah.axd",
    "/trace.axd",
    "/telescope/requests",
    "/_profiler/phpinfo",
    "/info.php",
    "/phpinfo.php",
    "/test.php",
    "/old/",
    "/dev/",
    "/staging/",
]


def stamp(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def nstamp(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S")


def quote(value: str) -> str:
    return f'"{value}"'


def at(hhmm: str) -> datetime:
    hours, minutes = hhmm.split(":")
    return T0.replace(hour=int(hours), minute=int(minutes))


def moment(rng: random.Random, lo: datetime | None = None, hi: datetime | None = None) -> datetime:
    """A random instant inside the range, with microseconds."""
    lo = lo or T0
    hi = hi or (T0 + DURATION)
    return lo + timedelta(seconds=rng.random() * (hi - lo).total_seconds())


def fill(template: str, rng: random.Random) -> str:
    return (
        template.replace("{id}", str(rng.randrange(100, 1000)))
        .replace("{n}", str(rng.randrange(1, 40)))
        .replace("{word}", rng.choice(WORDS))
    )


def pick(rng: random.Random, options: list[tuple[str, str, int]]) -> tuple[str, str]:
    method, template, _ = rng.choices(options, weights=[w for _, _, w in options])[0]
    return method, fill(template, rng)


@dataclass
class Req:
    """One Application Load Balancer access log entry."""

    time: datetime
    kind: str  # listener type: http, https or h2
    client: str
    target: str | None
    times: tuple[float, float, float]  # request, target, response; -1 means not applicable
    elb_code: int
    target_code: int | None
    received: int
    sent: int
    method: str | None
    url: str | None
    http_version: str
    agent: str
    tls: tuple[str, str] | None
    target_group: str | None
    priority: int | None
    actions: str = "forward"
    redirect: str = "-"

    def line(self, rng: random.Random) -> str:
        def secs(x: float) -> str:
            return "-1" if x < 0 else f"{x:.3f}"

        total = sum(self.times) if min(self.times) >= 0 else 0.0
        created = self.time - timedelta(seconds=total)
        request = f"{self.method} {self.url} {self.http_version}" if self.method else "- - - "
        trace = f"Root=1-{int(self.time.timestamp()):08x}-{rng.getrandbits(96):024x}"
        target = self.target or "-"
        target_code = str(self.target_code) if self.target_code is not None else "-"
        cipher, proto = self.tls or ("-", "-")
        fields = [
            self.kind,
            stamp(self.time),
            ALB_NAME,
            f"{self.client}:{rng.randrange(1024, 65535)}",
            target,
            secs(self.times[0]),
            secs(self.times[1]),
            secs(self.times[2]),
            str(self.elb_code),
            target_code,
            str(self.received),
            str(self.sent),
            quote(request),
            quote(self.agent),
            cipher,
            proto,
            self.target_group or "-",
            quote(trace),
            quote(DOMAIN if self.tls else "-"),
            quote(CERT_ARN if self.tls else "-"),
            str(self.priority) if self.priority is not None else "-",
            stamp(created),
            quote(self.actions),
            quote(self.redirect),
            quote("-"),
            quote(target),
            quote(target_code),
            quote("-"),
            quote("-"),
            f"TID_{rng.getrandbits(64):016x}",
        ]
        return " ".join(fields)


def listener(rng: random.Random) -> tuple[str, str, tuple[str, str]]:
    kind, version = rng.choice([("https", "HTTP/1.1"), ("h2", "HTTP/2.0")])
    return kind, version, TLS13 if rng.random() < 0.7 else TLS12


def web_request(rng: random.Random, t: datetime) -> Req:
    method, path = pick(rng, WEB_PATHS)
    kind, version, tls = listener(rng)
    code = 200
    if path.startswith("/static/") and rng.random() < 0.3:
        code = 304
    elif method == "POST" and path == "/cart":
        code = 302
    elif rng.random() < 0.02:
        code = 404
    sent = {200: rng.randrange(2000, 60000), 304: 0, 302: 0, 404: rng.randrange(900, 1400)}[code]
    target_time = max(0.002, rng.lognormvariate(math.log(0.04), 0.5))
    return Req(
        t,
        kind,
        rng.choice(PUBLIC_CLIENTS),
        rng.choice(WEB_TARGETS),
        (round(rng.random() * 0.002, 3), round(target_time, 3), 0.0),
        code,
        code,
        rng.randrange(200, 1500),
        sent,
        method,
        f"https://{DOMAIN}:443{path}",
        version,
        rng.choice(BROWSERS),
        tls,
        TG_WEB,
        0,
    )


def api_request(rng: random.Random, t: datetime) -> Req:
    method, path = pick(rng, API_PATHS)
    kind, version, tls = listener(rng)
    code = 201 if (method, path) == ("POST", "/api/orders") else 200
    if rng.random() < 0.003:
        code = 500
    target_time = max(0.005, rng.lognormvariate(math.log(0.12), 0.6))
    return Req(
        t,
        kind,
        rng.choice(PUBLIC_CLIENTS),
        rng.choice(API_TARGETS),
        (round(rng.random() * 0.002, 3), round(target_time, 3), 0.0),
        code,
        code,
        rng.randrange(150, 900),
        rng.randrange(300, 12000) if code != 500 else 120,
        method,
        f"https://{DOMAIN}:443{path}",
        version,
        rng.choice(BROWSERS[-2:]) if rng.random() < 0.6 else rng.choice(BROWSERS),
        tls,
        TG_API,
        10,
    )


def redirect_request(rng: random.Random, t: datetime) -> Req:
    _, path = pick(rng, WEB_PATHS[:5])
    return Req(
        t,
        "http",
        rng.choice(PUBLIC_CLIENTS),
        None,
        (0.0, 0.001, 0.0),
        301,
        None,
        rng.randrange(100, 400),
        rng.randrange(300, 400),
        "GET",
        f"http://{DOMAIN}:80{path}",
        "HTTP/1.1",
        rng.choice(BROWSERS),
        None,
        TG_WEB,
        0,
        actions="redirect",
        redirect=f"https://{DOMAIN}:443{path}",
    )


def fail_at_target(req: Req) -> Req:
    """The target closed the connection without answering: the ALB returns 502."""
    req.elb_code = 502
    req.target_code = None
    req.times = (0.001, -1.0, -1.0)
    req.sent = 272
    return req


def alb_requests(rng: random.Random) -> list[Req]:
    reqs: list[Req] = []
    bad = LB_PLANTED["failing_target"]
    bad_target = str(bad["target"])
    bad_from, bad_to = (at(h) for h in bad["window"])  # type: ignore[arg-type]

    # Background: web pages, API calls from the mobile app, and plain-HTTP redirects.
    for _ in range(3600):
        t = moment(rng)
        roll = rng.random()
        if roll < 0.70:
            reqs.append(web_request(rng, t))
        elif roll < 0.97:
            req = api_request(rng, t)
            # A: one API target fails every real request for twenty minutes while its
            #    health check keeps passing, so the ALB keeps sending it traffic.
            if req.target == bad_target and bad_from <= t < bad_to:
                fail_at_target(req)
            reqs.append(req)
        else:
            reqs.append(redirect_request(rng, t))

    # A (continued): the mobile app retries failed calls, so the broken target sees more.
    for _ in range(300):
        req = api_request(rng, moment(rng, bad_from, bad_to))
        req.target = bad_target
        reqs.append(fail_at_target(req))

    # B: one report endpoint is very slow and sometimes hits the 60 second idle timeout.
    slow = LB_PLANTED["slow_path"]
    for i in range(60):
        req = api_request(rng, moment(rng))
        req.method, req.url = "GET", f"https://{DOMAIN}:443{slow['path']}"
        req.agent = BROWSERS[1]
        if i < int(slow["timeouts"]):  # type: ignore[call-overload]
            req.elb_code, req.target_code = 504, None
            req.times, req.sent = (0.001, 60.0, 0.0), 288
        else:
            req.times = (0.001, round(rng.uniform(3.0, 9.0), 3), 0.0)
            req.sent = rng.randrange(400000, 2500000)
        reqs.append(req)

    # C: one public address probes dozens of well-known paths inside three minutes.
    probe = LB_PLANTED["path_probing"]
    p_from, p_to = (at(h) for h in probe["window"])  # type: ignore[arg-type]
    for i in range(150):
        path = PROBE_PATHS[i % len(PROBE_PATHS)]
        reqs.append(
            Req(
                moment(rng, p_from, p_to),
                "https",
                str(probe["client"]),
                rng.choice(WEB_TARGETS),
                (0.001, round(rng.uniform(0.002, 0.01), 3), 0.0),
                404,
                404,
                rng.randrange(80, 200),
                rng.randrange(900, 1400),
                "GET",
                f"https://{DOMAIN}:443{path}",
                "HTTP/1.1",
                SCANNER_AGENT,
                TLS12,
                TG_WEB,
                0,
            )
        )
    for _ in range(6):  # malformed requests the ALB itself refuses
        reqs.append(
            Req(
                moment(rng, p_from, p_to),
                "https",
                str(probe["client"]),
                None,
                (-1.0, -1.0, -1.0),
                400,
                None,
                0,
                272,
                None,
                None,
                "HTTP/1.1",
                SCANNER_AGENT,
                TLS12,
                None,
                None,
            )
        )

    # D: an old integration still negotiating TLS 1.1.
    legacy = LB_PLANTED["legacy_tls"]
    for _ in range(40):
        req = api_request(rng, moment(rng))
        req.client, req.agent = str(legacy["client"]), LEGACY_AGENT
        req.kind, req.http_version, req.tls = "https", "HTTP/1.1", TLS11
        req.method, req.url = "GET", f"https://{DOMAIN}:443/api/products"
        req.elb_code = req.target_code = 200
        reqs.append(req)

    reqs.sort(key=lambda r: (r.time, r.client))
    return reqs


def write_alb(out: Path, rng: random.Random) -> None:
    lines = [r.line(rng) for r in alb_requests(rng)]
    (out / "alb_access_logs.log").write_text("\n".join(lines) + "\n")


@dataclass
class Conn:
    """One Network Load Balancer TLS access log entry."""

    end: datetime
    client: str
    connection_ms: int
    handshake_ms: int | None
    received: int
    sent: int
    alert: int | None = None
    tls: tuple[str, str, str] | None = ("TLS_AES_128_GCM_SHA256", "tlsv13", "x25519")
    domain: str = API_DOMAIN
    alpn: tuple[str, str, str] = ("h2", "h2", "h2,http/1.1")

    def line(self, rng: random.Random) -> str:
        cipher, proto, group = self.tls or ("-", "-", "-")
        has_hello = self.tls is not None
        fields = [
            "tls",
            "2.0",
            nstamp(self.end),
            NLB_NAME,
            NLB_LISTENER,
            f"{self.client}:{rng.randrange(1024, 65535)}",
            NLB_ADDRESS,
            str(self.connection_ms),
            str(self.handshake_ms) if self.handshake_ms is not None else "-",
            str(self.received),
            str(self.sent),
            str(self.alert) if self.alert is not None else "-",
            CERT_ARN if has_hello else "-",
            CERT_SERIAL if has_hello else "-",
            cipher,
            proto,
            group,
            self.domain,
            *self.alpn,
            nstamp(self.end - timedelta(milliseconds=self.connection_ms)),
        ]
        return " ".join(fields)


NLB_TLS13 = ("TLS_AES_128_GCM_SHA256", "tlsv13", "x25519")
NLB_TLS12 = ("ECDHE-RSA-AES128-GCM-SHA256", "tlsv12", "secp256r1")
NLB_TLS11 = ("ECDHE-RSA-AES128-SHA", "tlsv11", "secp256r1")
NO_ALPN = ("-", "-", "-")


def nlb_connections(rng: random.Random) -> list[Conn]:
    conns: list[Conn] = []
    # Background: long-lived HTTP/2 connections from the mobile app and partners.
    for _ in range(2200):
        http2 = rng.random() < 0.7
        conns.append(
            Conn(
                moment(rng),
                rng.choice(PUBLIC_CLIENTS),
                int(rng.lognormvariate(math.log(8000), 1.2)) + 100,
                rng.randrange(5, 60),
                int(rng.lognormvariate(math.log(4000), 1.0)) + 200,
                int(rng.lognormvariate(math.log(30000), 1.2)) + 500,
                tls=NLB_TLS13 if rng.random() < 0.8 else NLB_TLS12,
                alpn=("h2", "h2", "h2,http/1.1") if http2 else ("http/1.1", "http/1.1", "http/1.1"),
            )
        )
    # A1: a client that does not trust the certificate chain aborts with alert 48.
    ca = LB_PLANTED["nlb_unknown_ca"]
    for _ in range(120):
        conns.append(
            Conn(
                moment(rng),
                str(ca["client"]),
                rng.randrange(20, 90),
                None,
                rng.randrange(300, 600),
                rng.randrange(1500, 3000),
                alert=int(ca["alert"]),  # type: ignore[call-overload]
                tls=NLB_TLS12,
                alpn=NO_ALPN,
            )
        )
    # A2: a client connecting by the load balancer's own DNS name rejects the certificate.
    bad = LB_PLANTED["nlb_bad_certificate"]
    for _ in range(40):
        conns.append(
            Conn(
                moment(rng),
                str(bad["client"]),
                rng.randrange(20, 90),
                None,
                rng.randrange(300, 600),
                rng.randrange(1500, 3000),
                alert=int(bad["alert"]),  # type: ignore[call-overload]
                tls=NLB_TLS13,
                domain="-",
                alpn=NO_ALPN,
            )
        )
    # A3: plain TCP connections to the TLS listener, no client hello at all.
    plain = LB_PLANTED["nlb_no_client_hello"]
    for _ in range(30):
        conns.append(
            Conn(
                moment(rng),
                str(plain["client"]),
                rng.randrange(1, 4),
                None,
                rng.randrange(60, 120),
                0,
                tls=None,
                domain="-",
                alpn=NO_ALPN,
            )
        )
    # B: one client opens hundreds of very short connections in four minutes.
    churn = LB_PLANTED["nlb_connection_churn"]
    c_from, c_to = (at(h) for h in churn["window"])  # type: ignore[arg-type]
    for _ in range(600):
        conns.append(
            Conn(
                moment(rng, c_from, c_to),
                str(churn["client"]),
                rng.randrange(5, 20),
                rng.randrange(3, 8),
                rng.randrange(100, 300),
                rng.randrange(200, 500),
                tls=NLB_TLS13,
                alpn=("http/1.1", "http/1.1", "http/1.1"),
            )
        )
    # C: a few connections still negotiating TLS 1.1.
    for _ in range(25):
        conns.append(
            Conn(
                moment(rng),
                "203.0.113.62",
                rng.randrange(500, 5000),
                rng.randrange(20, 80),
                rng.randrange(500, 3000),
                rng.randrange(2000, 20000),
                tls=NLB_TLS11,
                alpn=NO_ALPN,
            )
        )
    conns.sort(key=lambda c: (c.end, c.client))
    return conns


def write_nlb(out: Path, rng: random.Random) -> None:
    lines = [c.line(rng) for c in nlb_connections(rng)]
    (out / "nlb_access_logs.log").write_text("\n".join(lines) + "\n")


# ------------------------------------------------------------ CloudTrail events

TRAIL_PLANTED = {
    "denied_enumeration": {"user": "bob", "ip": "203.0.113.77", "window": ("08:52", "08:58")},
    "denied_retry_loop": {
        "role": "shop-web-role",
        "action": "ssm:GetParameter",
        "parameter": "/shop/web/feature-flags",
        "window": ("09:30", "10:00"),
    },
    "console_no_mfa": {"users": ["carol", "root"]},
    "root_activity": {"ip": "203.0.113.61", "window": ("09:12", "09:21")},
    "unusual_regions": {"user": "backup-admin", "regions": ["ap-southeast-1", "us-east-2"]},
}

TRAIL_HEADER = [
    "Event ID",
    "Event time",
    "User name",
    "Event name",
    "Event source",
    "Resource type",
    "Resource name",
    "AWS region",
    "Source IP address",
    "Error code",
    "Read-only",
    "Access key ID",
    "Event type",
    "Request ID",
    "Event category",
    "Recipient account ID",
    "Resources",
    "CloudTrail event",
]

HOME_REGION = REGION  # eu-west-1
DR_REGION = "eu-central-1"
GLOBAL_REGION = "us-east-1"  # IAM, STS global endpoint and console sign-in events land here

CLI_AGENT = "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0-1016-aws exe/x86_64.ubuntu.22 prompt/off"
SDK_AGENT = (
    "aws-sdk-java/2.25.16 Linux/6.1.79-99.167.amzn2023.x86_64 "
    "OpenJDK_64-Bit_Server_VM/17.0.10+7-LTS Java/17.0.10 vendor/Amazon.com_Inc."
)
BOTO_AGENT = (
    "Boto3/1.34.84 md/Botocore#1.34.84 ua/2.0 os/linux#6.5.0 md/arch#x86_64 "
    "lang/python#3.11.8 md/pyimpl#CPython cfg/retry-mode#legacy Botocore/1.34.84"
)
MAC_BROWSER = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
WIN_BROWSER = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
GITHUB_AGENT = "aws-cli/2.15.30 Python/3.11.8 Linux/6.5.0-1016-azure exe/x86_64.ubuntu.22"

OFFICE_IPS = {"alice": "198.51.100.20", "bob": "198.51.100.21", "carol": "198.51.100.22"}
CI_IP = "192.0.2.10"
MONITOR_IP = IDLE.ip
INTRUDER_IP = "203.0.113.61"
LEAKED_KEY_IP = "203.0.113.77"

ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
AMI = "ami-0a1b2c3d4e5f60789"


@dataclass(frozen=True)
class Identity:
    """Who made the call, as CloudTrail's userIdentity block describes it."""

    kind: str  # IAMUser, AssumedRole, Root or AWSService
    name: str  # user name, role name, "root", or the calling service's host name
    session: str = ""  # assumed-role session name
    key: str = ""  # access key id (documentation examples only)
    console: bool = False  # credentials came from a console sign-in
    mfa: bool = False  # the session was authenticated with MFA

    @property
    def arn(self) -> str:
        if self.kind == "Root":
            return f"arn:aws:iam::{ACCOUNT}:root"
        if self.kind == "IAMUser":
            return f"arn:aws:iam::{ACCOUNT}:user/{self.name}"
        if self.kind == "AssumedRole":
            return f"arn:aws:sts::{ACCOUNT}:assumed-role/{self.name}/{self.session}"
        return ""

    @property
    def user_name(self) -> str:
        """What the console's CSV export shows in its User name column."""
        return self.session if self.kind == "AssumedRole" else self.name

    def principal_id(self) -> str:
        digest = hashlib.sha1(f"{self.kind}:{self.name}".encode()).hexdigest().upper()
        return {"IAMUser": "AIDA", "AssumedRole": "AROA"}.get(self.kind, "") + "EX" + digest[:15]

    def json(self, t: datetime) -> dict[str, object]:
        if self.kind == "AWSService":
            return {"type": "AWSService", "invokedBy": self.name}
        attributes = {
            "creationDate": tstamp(t - timedelta(minutes=5)),
            "mfaAuthenticated": "true" if self.mfa else "false",
        }
        if self.kind == "Root":
            out: dict[str, object] = {
                "type": "Root",
                "principalId": ACCOUNT,
                "arn": self.arn,
                "accountId": ACCOUNT,
                "accessKeyId": self.key,
            }
            if self.console:
                out["sessionContext"] = {"attributes": attributes}
                out["sessionCredentialFromConsole"] = "true"
            return out
        if self.kind == "IAMUser":
            out = {
                "type": "IAMUser",
                "principalId": self.principal_id(),
                "arn": self.arn,
                "accountId": ACCOUNT,
                "accessKeyId": self.key,
                "userName": self.name,
            }
            if self.console:
                out["sessionContext"] = {"attributes": attributes}
                out["sessionCredentialFromConsole"] = "true"
            return out
        role_id = self.principal_id()
        return {
            "type": "AssumedRole",
            "principalId": f"{role_id}:{self.session}",
            "arn": self.arn,
            "accountId": ACCOUNT,
            "accessKeyId": self.key,
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": role_id,
                    "arn": f"arn:aws:iam::{ACCOUNT}:role/{self.name}",
                    "accountId": ACCOUNT,
                    "userName": self.name,
                },
                "attributes": attributes,
            },
        }


ALICE = Identity("IAMUser", "alice", key="AKIAIOSFODNN7EXAMPLE")
BOB = Identity("IAMUser", "bob", key="AKIAI44QH8DHBEXAMPLE")
CAROL = Identity("IAMUser", "carol")
ROOT = Identity("Root", "root")
BACKUP_ADMIN = Identity("IAMUser", "backup-admin", key="AKIAEXAMPLEBACKUP001")
DEPLOY = Identity("AssumedRole", "shop-deploy-role", "GitHubActions", "ASIAEXAMPLEDEPLOY001")
MONITOR = Identity("AssumedRole", "shop-monitoring-role", "grafana", "ASIAEXAMPLEMONITOR01")
WEB_ROLE = [
    Identity("AssumedRole", "shop-web-role", h.instance, f"ASIAEXAMPLEWEB00010{i}")
    for i, h in enumerate(WEB, 1)
]
AUTOSCALING = Identity("AWSService", "autoscaling.amazonaws.com")
CONFIG = Identity("AWSService", "config.amazonaws.com")


def tstamp(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def every(
    rng: random.Random, start: datetime, end: datetime, seconds: float, jitter: float = 0.3
) -> list[datetime]:
    """Instants spaced about ``seconds`` apart between start and end."""
    out: list[datetime] = []
    t = start + timedelta(seconds=rng.random() * seconds)
    while t < end:
        out.append(t)
        t += timedelta(seconds=seconds * (1 + jitter * (rng.random() * 2 - 1)))
    return out


def denied_message(identity: Identity, action: str, resource: str) -> str:
    return (
        f"User: {identity.arn} is not authorized to perform: {action} on resource: {resource} "
        f"because no identity-based policy allows the {action} action"
    )


@dataclass
class Event:
    """One CloudTrail management event."""

    time: datetime
    identity: Identity
    service: str  # short service name, e.g. "ec2"
    name: str
    region: str
    ip: str
    agent: str
    read_only: bool = True
    error: tuple[str, str] | None = None  # (errorCode, errorMessage)
    params: dict[str, object] | None = None
    response: dict[str, object] | None = None
    additional: dict[str, object] | None = None
    resources: list[dict[str, str]] = field(default_factory=list)
    event_type: str = "AwsApiCall"

    @property
    def source(self) -> str:
        return f"{self.service}.amazonaws.com"

    def row(self, rng: random.Random) -> list[str]:
        event_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        request_id = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        record: dict[str, object] = {
            "eventVersion": "1.10",
            "userIdentity": self.identity.json(self.time),
            "eventTime": tstamp(self.time),
            "eventSource": self.source,
            "eventName": self.name,
            "awsRegion": self.region,
            "sourceIPAddress": self.ip,
            "userAgent": self.agent,
        }
        if self.error:
            record["errorCode"], record["errorMessage"] = self.error
        record.update(
            {
                "requestParameters": self.params,
                "responseElements": self.response,
            }
        )
        if self.additional:
            record["additionalEventData"] = self.additional
        record.update(
            {
                "requestID": request_id,
                "eventID": event_id,
                "readOnly": self.read_only,
            }
        )
        if self.resources:
            record["resources"] = self.resources
        record.update(
            {
                "eventType": self.event_type,
                "managementEvent": True,
                "recipientAccountId": ACCOUNT,
                "eventCategory": "Management",
            }
        )
        first = self.resources[0] if self.resources else {}
        return [
            event_id,
            tstamp(self.time),
            self.identity.user_name,
            self.name,
            self.source,
            first.get("resourceType", ""),
            first.get("ARN", ""),
            self.region,
            self.ip,
            self.error[0] if self.error else "",
            "true" if self.read_only else "false",
            self.identity.key,
            self.event_type,
            request_id,
            "Management",
            ACCOUNT,
            json.dumps(self.resources, separators=(",", ":")) if self.resources else "",
            json.dumps(record, separators=(",", ":")),
        ]


def call(
    rng: random.Random,
    t: datetime,
    who: Identity,
    action: str,
    ip: str,
    agent: str,
    *,
    region: str = HOME_REGION,
    read_only: bool = True,
    denied: bool = False,
    **extra: object,
) -> Event:
    """Build an event from ``service:Action``. Denied calls get the service's usual error."""
    service, name = action.split(":")
    if service in ("iam", "organizations", "route53", "signin"):
        region = GLOBAL_REGION
    error = None
    if denied:
        resource = extra.pop("resource", "*")
        code = {
            "ec2": "Client.UnauthorizedOperation",
            "secretsmanager": "AccessDeniedException",
            "kms": "AccessDeniedException",
            "ssm": "AccessDeniedException",
            "eks": "AccessDeniedException",
            "lambda": "AccessDeniedException",
            "cloudtrail": "AccessDeniedException",
            "organizations": "AccessDeniedException",
            "dynamodb": "AccessDeniedException",
        }.get(service, "AccessDenied")
        error = (code, denied_message(who, action, str(resource)))
    else:
        extra.pop("resource", None)
    return Event(
        t, who, service, name, region, ip, agent, read_only=read_only, error=error, **extra
    )


def web_role_events(rng: random.Random) -> list[Event]:
    """Three web instances reading parameters and secrets, then a parameter they may not."""
    out: list[Event] = []
    names = ["/shop/web/db-host", "/shop/web/cache-host", "/shop/web/session-key-id"]
    for host, who in zip(WEB, WEB_ROLE, strict=True):
        for t in every(rng, T0, T0 + DURATION, 30):
            out.append(
                call(
                    rng,
                    t,
                    who,
                    "ssm:GetParameters",
                    host.ip,
                    SDK_AGENT,
                    params={"names": names, "withDecryption": True},
                    resources=[
                        {
                            "resourceType": "AWS::SSM::Parameter",
                            "ARN": f"arn:aws:ssm:{HOME_REGION}:{ACCOUNT}:parameter{names[0]}",
                        }
                    ],
                )
            )
        for t in every(rng, T0, T0 + DURATION, 1800):
            secret = f"arn:aws:secretsmanager:{HOME_REGION}:{ACCOUNT}:secret:shop/web/db-Ab12Cd"
            out.append(
                call(
                    rng,
                    t,
                    who,
                    "secretsmanager:GetSecretValue",
                    host.ip,
                    SDK_AGENT,
                    params={"secretId": "shop/web/db"},
                    resources=[{"resourceType": "AWS::SecretsManager::Secret", "ARN": secret}],
                )
            )
            out.append(
                call(
                    rng,
                    t + timedelta(milliseconds=120),
                    who,
                    "kms:Decrypt",
                    host.ip,
                    SDK_AGENT,
                    params={"encryptionAlgorithm": "SYMMETRIC_DEFAULT"},
                )
            )
        # Planted: a feature-flag parameter the role's policy does not cover, retried every
        # 30 seconds by each instance from 09:30 onwards.
        parameter = TRAIL_PLANTED["denied_retry_loop"]["parameter"]
        window = TRAIL_PLANTED["denied_retry_loop"]["window"]
        for t in every(rng, at(window[0]), at(window[1]), 30, jitter=0.1):
            out.append(
                call(
                    rng,
                    t,
                    who,
                    "ssm:GetParameter",
                    host.ip,
                    SDK_AGENT,
                    denied=True,
                    resource=f"arn:aws:ssm:{HOME_REGION}:{ACCOUNT}:parameter{parameter}",
                    params={"name": parameter, "withDecryption": False},
                )
            )
    return out


def service_events(rng: random.Random) -> list[Event]:
    out: list[Event] = []
    for t in every(rng, T0, T0 + DURATION, 60, jitter=0.05):
        out.append(
            call(
                rng,
                t,
                AUTOSCALING,
                "ec2:DescribeInstanceStatus",
                AUTOSCALING.name,
                AUTOSCALING.name,
            )
        )
    config_calls = [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "s3:GetBucketPolicy",
        "iam:ListPolicies",
        "rds:DescribeDBInstances",
    ]
    for t in every(rng, T0, T0 + DURATION, 180):
        out.append(call(rng, t, CONFIG, rng.choice(config_calls), CONFIG.name, CONFIG.name))
    return out


def monitoring_events(rng: random.Random) -> list[Event]:
    """Grafana polling CloudWatch and RDS in the home region and the DR region."""
    out: list[Event] = []
    for t in every(rng, T0, T0 + DURATION, 60, jitter=0.05):
        for region in (HOME_REGION, DR_REGION):
            out.append(
                call(
                    rng,
                    t + timedelta(milliseconds=rng.randrange(50, 400)),
                    MONITOR,
                    "cloudwatch:GetMetricData",
                    MONITOR_IP,
                    BOTO_AGENT,
                    region=region,
                )
            )
    for t in every(rng, T0, T0 + DURATION, 120):
        for region in (HOME_REGION, DR_REGION):
            out.append(
                call(
                    rng,
                    t,
                    MONITOR,
                    "rds:DescribeDBInstances",
                    MONITOR_IP,
                    BOTO_AGENT,
                    region=region,
                )
            )
    for t in every(rng, T0, T0 + DURATION, 2400):
        out.append(
            call(
                rng,
                t,
                MONITOR,
                "rds:DescribeDBLogFiles",
                MONITOR_IP,
                BOTO_AGENT,
                denied=True,
                resource=f"arn:aws:rds:{HOME_REGION}:{ACCOUNT}:db:shop-db",
            )
        )
    return out


ALICE_CALLS: list[tuple[str, int]] = [
    ("ec2:DescribeInstances", 10),
    ("ec2:DescribeSecurityGroups", 4),
    ("ecs:DescribeServices", 6),
    ("ecs:ListTasks", 4),
    ("ecs:DescribeTasks", 3),
    ("logs:DescribeLogGroups", 3),
    ("logs:FilterLogEvents", 5),
    ("cloudwatch:GetMetricData", 4),
    ("elasticloadbalancing:DescribeTargetHealth", 5),
    ("s3:ListBuckets", 2),
    ("sts:GetCallerIdentity", 3),
    ("lambda:ListFunctions", 2),
    ("iam:GetRole", 2),
    ("iam:ListRoles", 1),
]
BOB_CALLS: list[tuple[str, int]] = [
    ("ec2:DescribeInstances", 6),
    ("dynamodb:ListTables", 3),
    ("dynamodb:DescribeTable", 4),
    ("lambda:ListFunctions", 3),
    ("lambda:GetFunction", 4),
    ("logs:FilterLogEvents", 4),
    ("cloudformation:DescribeStacks", 4),
    ("cloudformation:ListStackResources", 2),
    ("s3:ListBuckets", 2),
    ("sts:GetCallerIdentity", 2),
]


def weighted(rng: random.Random, options: list[tuple[str, int]]) -> str:
    return rng.choices([a for a, _ in options], weights=[w for _, w in options])[0]


def developer_events(rng: random.Random) -> list[Event]:
    out: list[Event] = []
    for t in every(rng, T0, T0 + DURATION, 24, jitter=0.9):
        action = weighted(rng, ALICE_CALLS)
        region = DR_REGION if action.startswith("rds") or rng.random() < 0.08 else HOME_REGION
        out.append(call(rng, t, ALICE, action, OFFICE_IPS["alice"], CLI_AGENT, region=region))
    for t in every(rng, T0, T0 + DURATION, 48, jitter=0.9):
        out.append(call(rng, t, BOB, weighted(rng, BOB_CALLS), OFFICE_IPS["bob"], CLI_AGENT))
    # A few one-off mutations and the odd sporadic denial that every account has.
    out.append(
        call(
            rng,
            at("08:37"),
            ALICE,
            "ec2:CreateTags",
            OFFICE_IPS["alice"],
            CLI_AGENT,
            read_only=False,
            params={"resourcesSet": {"items": [{"resourceId": WEB[0].instance}]}},
        )
    )
    out.append(
        call(
            rng,
            at("08:41"),
            ALICE,
            "ec2:StartInstances",
            OFFICE_IPS["alice"],
            CLI_AGENT,
            read_only=False,
            denied=True,
            resource=f"arn:aws:ec2:{HOME_REGION}:{ACCOUNT}:instance/{IDLE.instance}",
        )
    )
    for hhmm in ("08:23", "09:48"):
        out.append(
            call(
                rng,
                at(hhmm),
                BOB,
                "iam:CreateAccessKey",
                OFFICE_IPS["bob"],
                CLI_AGENT,
                read_only=False,
                denied=True,
                resource=BOB.arn,
            )
        )
    return out


def deploy_events(rng: random.Random, start: datetime) -> list[Event]:
    """One GitHub Actions deploy of the web service: push an image, roll the ECS service."""
    out: list[Event] = []
    t = start
    service_arn = f"arn:aws:ecs:{HOME_REGION}:{ACCOUNT}:service/shop/shop-web"
    steps: list[tuple[str, bool, dict[str, object]]] = [
        ("sts:GetCallerIdentity", True, {}),
        ("ecr:GetAuthorizationToken", True, {}),
        ("ecr:DescribeImages", True, {"params": {"repositoryName": "shop-web"}}),
        (
            "ecs:RegisterTaskDefinition",
            False,
            {"params": {"family": "shop-web", "cpu": "512", "memory": "1024"}},
        ),
        (
            "ecs:UpdateService",
            False,
            {
                "params": {"cluster": "shop", "service": "shop-web", "taskDefinition": "shop-web"},
                "resources": [{"resourceType": "AWS::ECS::Service", "ARN": service_arn}],
            },
        ),
    ]
    for action, read_only, extra in steps:
        t += timedelta(seconds=rng.uniform(2, 15))
        out.append(call(rng, t, DEPLOY, action, CI_IP, GITHUB_AGENT, read_only=read_only, **extra))
    for _ in range(18):
        t += timedelta(seconds=rng.uniform(15, 25))
        out.append(call(rng, t, DEPLOY, "ecs:DescribeServices", CI_IP, GITHUB_AGENT))
        if rng.random() < 0.5:
            out.append(
                call(
                    rng,
                    t + timedelta(seconds=1),
                    DEPLOY,
                    "elasticloadbalancing:DescribeTargetHealth",
                    CI_IP,
                    GITHUB_AGENT,
                )
            )
    return out


def console_login(
    t: datetime, who: Identity, ip: str, agent: str, *, mfa: bool, success: bool = True
) -> Event:
    additional: dict[str, object] = {
        "LoginTo": "https://console.aws.amazon.com/console/home?region=eu-west-1",
        "MobileVersion": "No",
        "MFAUsed": "Yes" if mfa else "No",
    }
    return Event(
        t,
        who,
        "signin",
        "ConsoleLogin",
        GLOBAL_REGION,
        ip,
        agent,
        read_only=False,
        error=None if success else ("", "Failed authentication"),
        response={"ConsoleLogin": "Success" if success else "Failure"},
        additional=additional,
        event_type="AwsConsoleSignIn",
    )


def console_session(
    rng: random.Random, who: Identity, start: datetime, ip: str, calls: int, *, mfa: bool
) -> list[Event]:
    """The read-only calls the console makes while someone clicks around."""
    session = Identity(
        who.kind, who.name, key=f"ASIAEXAMPLECONSOLE{rng.randrange(10, 99)}", console=True, mfa=mfa
    )
    pages = [
        ("ec2:DescribeInstances", "console.ec2.amazonaws.com"),
        ("ec2:DescribeSecurityGroups", "console.ec2.amazonaws.com"),
        ("ec2:DescribeVolumes", "console.ec2.amazonaws.com"),
        ("s3:ListBuckets", "AWS Internal"),
        ("cloudwatch:DescribeAlarms", "console.amazonaws.com"),
        ("ecs:ListClusters", "console.amazonaws.com"),
        ("iam:ListUsers", "console.amazonaws.com"),
        ("iam:GetAccountSummary", "console.amazonaws.com"),
    ]
    out: list[Event] = []
    t = start
    for _ in range(calls):
        t += timedelta(seconds=rng.uniform(5, 90))
        action, agent = rng.choice(pages)
        out.append(call(rng, t, session, action, ip, agent))
    return out


def sign_in_events(rng: random.Random) -> list[Event]:
    out: list[Event] = []
    out.append(console_login(at("08:05"), ALICE, OFFICE_IPS["alice"], MAC_BROWSER, mfa=True))
    out += console_session(rng, ALICE, at("08:05"), OFFICE_IPS["alice"], 14, mfa=True)
    out.append(console_login(at("09:00"), BOB, OFFICE_IPS["bob"], MAC_BROWSER, mfa=True))
    out += console_session(rng, BOB, at("09:00"), OFFICE_IPS["bob"], 10, mfa=True)
    # Planted: carol has no MFA device. One typo, then two successful password-only sign-ins.
    carol_ip = OFFICE_IPS["carol"]
    out.append(console_login(at("08:14"), CAROL, carol_ip, MAC_BROWSER, mfa=False, success=False))
    out.append(console_login(at("08:15"), CAROL, carol_ip, MAC_BROWSER, mfa=False))
    out += console_session(rng, CAROL, at("08:15"), carol_ip, 12, mfa=False)
    out.append(console_login(at("09:40"), CAROL, carol_ip, MAC_BROWSER, mfa=False))
    out += console_session(rng, CAROL, at("09:40"), carol_ip, 8, mfa=False)
    return out


ENUMERATED: list[str] = [
    "iam:ListUsers",
    "iam:ListRoles",
    "iam:ListAccessKeys",
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:GetAccountAuthorizationDetails",
    "secretsmanager:ListSecrets",
    "secretsmanager:GetSecretValue",
    "kms:ListKeys",
    "ssm:DescribeParameters",
    "ssm:GetParametersByPath",
    "rds:DescribeDBInstances",
    "ec2:RunInstances",
    "ec2:CreateKeyPair",
    "ec2:CreateSecurityGroup",
    "s3:GetBucketPolicy",
    "s3:PutBucketPolicy",
    "cloudtrail:DescribeTrails",
    "cloudtrail:StopLogging",
    "organizations:ListAccounts",
    "eks:ListClusters",
]
ALLOWED_FOR_BOB = [
    "sts:GetCallerIdentity",
    "s3:ListBuckets",
    "ec2:DescribeRegions",
    "ec2:DescribeInstances",
    "lambda:ListFunctions",
]
MUTATING = {
    "CreateUser",
    "CreateAccessKey",
    "AttachUserPolicy",
    "RunInstances",
    "CreateKeyPair",
    "CreateSecurityGroup",
    "AuthorizeSecurityGroupIngress",
    "PutBucketPolicy",
    "StopLogging",
}


def leaked_key_events(rng: random.Random) -> list[Event]:
    """Planted: bob's access key used from an unknown address to test what it can do."""
    plan = TRAIL_PLANTED["denied_enumeration"]
    start, end = at(plan["window"][0]), at(plan["window"][1])
    actions = [a for a in ENUMERATED for _ in range(10)] + [
        a for a in ALLOWED_FOR_BOB for _ in range(2)
    ]
    rng.shuffle(actions)
    step = (end - start).total_seconds() / len(actions)
    out: list[Event] = []
    for i, action in enumerate(actions):
        t = start + timedelta(seconds=i * step + rng.uniform(0, step * 0.8))
        service, name = action.split(":")
        out.append(
            call(
                rng,
                t,
                BOB,
                action,
                plan["ip"],
                BOTO_AGENT,
                read_only=name not in MUTATING,
                denied=action in ENUMERATED,
                resource=f"arn:aws:{service}:{HOME_REGION}:{ACCOUNT}:*",
            )
        )
    return out


def root_events(rng: random.Random) -> list[Event]:
    """Planted: root signs in without MFA and creates an administrator user."""
    plan = TRAIL_PLANTED["root_activity"]
    ip = plan["ip"]
    root = Identity("Root", "root", key="ASIAEXAMPLEROOT00001", console=True, mfa=False)
    user_arn = BACKUP_ADMIN.arn
    out = [console_login(at(plan["window"][0]), ROOT, ip, WIN_BROWSER, mfa=False)]
    t = at(plan["window"][0]) + timedelta(seconds=40)
    steps: list[tuple[str, bool, dict[str, object]]] = [
        ("iam:GetAccountSummary", True, {}),
        ("iam:ListUsers", True, {}),
        ("iam:ListAccessKeys", True, {}),
        (
            "iam:CreateUser",
            False,
            {
                "params": {"userName": BACKUP_ADMIN.name},
                "response": {"user": {"userName": BACKUP_ADMIN.name, "arn": user_arn}},
                "resources": [{"resourceType": "AWS::IAM::User", "ARN": user_arn}],
            },
        ),
        (
            "iam:AttachUserPolicy",
            False,
            {
                "params": {"userName": BACKUP_ADMIN.name, "policyArn": ADMIN_POLICY},
                "resources": [{"resourceType": "AWS::IAM::User", "ARN": user_arn}],
            },
        ),
        (
            "iam:CreateAccessKey",
            False,
            {
                "params": {"userName": BACKUP_ADMIN.name},
                "response": {
                    "accessKey": {
                        "accessKeyId": BACKUP_ADMIN.key,
                        "status": "Active",
                        "userName": BACKUP_ADMIN.name,
                    }
                },
                "resources": [{"resourceType": "AWS::IAM::User", "ARN": user_arn}],
            },
        ),
        ("ec2:DescribeInstances", True, {}),
        ("s3:ListBuckets", True, {}),
        ("cloudtrail:DescribeTrails", True, {}),
        ("iam:ListUsers", True, {}),
    ]
    for action, read_only, extra in steps:
        t += timedelta(seconds=rng.uniform(20, 70))
        out.append(
            call(rng, t, root, action, ip, "console.amazonaws.com", read_only=read_only, **extra)
        )
    return out


def unusual_region_events(rng: random.Random) -> list[Event]:
    """Planted: the new user launches GPU instances in regions this account never uses."""
    plan = TRAIL_PLANTED["unusual_regions"]
    ip = TRAIL_PLANTED["root_activity"]["ip"]
    out: list[Event] = []
    t = at("09:24")
    for action in ("sts:GetCallerIdentity", "ec2:DescribeInstances", "ec2:DescribeRegions"):
        t += timedelta(seconds=rng.uniform(10, 40))
        out.append(call(rng, t, BACKUP_ADMIN, action, ip, BOTO_AGENT))
    launches = {plan["regions"][0]: 4, plan["regions"][1]: 2}
    for region, count in launches.items():
        sg = f"sg-0{rng.getrandbits(64):016x}"
        steps: list[tuple[str, bool, dict[str, object]]] = [
            ("ec2:DescribeVpcs", True, {}),
            ("ec2:DescribeImages", True, {"params": {"imagesSet": {"items": [{"imageId": AMI}]}}}),
            (
                "ec2:CreateKeyPair",
                False,
                {"params": {"keyName": "backup", "keyType": "rsa"}},
            ),
            (
                "ec2:CreateSecurityGroup",
                False,
                {
                    "params": {"groupName": "backup-ssh", "groupDescription": "backup"},
                    "response": {"groupId": sg},
                },
            ),
            (
                "ec2:AuthorizeSecurityGroupIngress",
                False,
                {
                    "params": {
                        "groupId": sg,
                        "ipPermissions": {
                            "items": [
                                {
                                    "ipProtocol": "tcp",
                                    "fromPort": 22,
                                    "toPort": 22,
                                    "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                                }
                            ]
                        },
                    }
                },
            ),
        ]
        for _ in range(count):
            instance = f"i-0{rng.getrandbits(64):016x}"
            steps.append(
                (
                    "ec2:RunInstances",
                    False,
                    {
                        "params": {
                            "instancesSet": {
                                "items": [{"imageId": AMI, "minCount": 1, "maxCount": 1}]
                            },
                            "instanceType": "g4dn.12xlarge",
                            "keyName": "backup",
                            "groupSet": {"items": [{"groupId": sg}]},
                        },
                        "response": {"instancesSet": {"items": [{"instanceId": instance}]}},
                        "resources": [
                            {
                                "resourceType": "AWS::EC2::Instance",
                                "ARN": f"arn:aws:ec2:{region}:{ACCOUNT}:instance/{instance}",
                            }
                        ],
                    },
                )
            )
        steps += [("ec2:DescribeInstances", True, {})] * 3
        for action, read_only, extra in steps:
            t += timedelta(seconds=rng.uniform(15, 75))
            out.append(
                call(
                    rng,
                    t,
                    BACKUP_ADMIN,
                    action,
                    ip,
                    BOTO_AGENT,
                    region=region,
                    read_only=read_only,
                    **extra,
                )
            )
    return out


def cloudtrail_events(rng: random.Random) -> list[Event]:
    events = web_role_events(rng)
    events += service_events(rng)
    events += monitoring_events(rng)
    events += developer_events(rng)
    events += deploy_events(rng, at("08:20"))
    events += deploy_events(rng, at("09:35"))
    events += sign_in_events(rng)
    events += leaked_key_events(rng)
    events += root_events(rng)
    events += unusual_region_events(rng)
    events = [e for e in events if T0 <= e.time < T0 + DURATION]
    events.sort(key=lambda e: (e.time, e.identity.user_name, e.name))
    return events


def write_cloudtrail(out: Path, rng: random.Random) -> None:
    with (out / "cloudtrail_events.csv").open("w", newline="") as fh:
        writer = csv.writer(fh, lineterminator="\n")
        writer.writerow(TRAIL_HEADER)
        for event in cloudtrail_events(rng):
            writer.writerow(event.row(rng))


# ------------------------------------------------------------ S3 server access logs

S3_PLANTED = {
    "public_backups": {"ip": "203.0.113.61", "prefix": "backups/", "window": ("09:15", "09:27")},
    "anonymous_probing": {"ip": "198.51.100.77", "window": ("09:50", "09:58")},
    "deleted_thumbnails": {"user": "bob", "prefix": "images/thumbs/", "window": ("09:05", "09:08")},
    "missing_thumbnails": {"prefix": "images/thumbs/", "from": "09:08"},
    "denied_exports": {"role": "shop-reports-role", "prefix": "exports/finance/"},
    "throttled_uploads": {"role": "shop-web-role", "window": ("08:40", "08:42")},
}

BUCKET = "shop-assets-example"
BUCKET_OWNER = hashlib.sha256(f"{BUCKET} owner".encode()).hexdigest()  # a canonical user id
S3_HOST = f"{BUCKET}.s3.{REGION}.amazonaws.com"
SHOP_URL = "https://shop.example.com"
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

REPORTS_ROLE = Identity("AssumedRole", "shop-reports-role", "reports-batch", "ASIAEXAMPLEREPORTS01")
BACKUP_ROLE = Identity("AssumedRole", "shop-backup-role", "backup-20260310", "ASIAEXAMPLEBACKUP001")
LIFECYCLE = "svc:s3.amazonaws.com"
CONSOLE_AGENT = "S3Console/0.4"
CURL_AGENT = "curl/8.4.0"
JAVA_SDK_AGENT = "aws-sdk-java/2.25.16 Linux/6.5.0-1016-aws OpenJDK_64-Bit_Server_VM/17.0.10"

DELETED_THUMBS = range(100, 400)  # product ids whose thumbnails bob removes at 09:05
PROBE_KEYS = [
    ".env",
    ".env.bak",
    ".git/config",
    ".git/HEAD",
    ".aws/credentials",
    ".htpasswd",
    ".DS_Store",
    "config.json",
    "config.yml",
    "config/database.yml",
    "settings.py",
    "appsettings.json",
    "web.config",
    "wp-config.php",
    "backup.zip",
    "backup.sql",
    "backup.tar.gz",
    "db.sql",
    "dump.sql",
    "database.sql",
    "site.zip",
    "www.zip",
    "credentials.json",
    "secrets.yaml",
    "secrets.json",
    "id_rsa",
    "id_rsa.pub",
    "server.key",
    "server.pem",
    "users.csv",
    "users.json",
    "customers.csv",
    "customers.xlsx",
    "orders.csv",
    "payments.csv",
    "invoices/2026/01.pdf",
    "admin/",
    "admin/config.php",
    "private/",
    "internal/",
    "uploads/",
    "logs/access.log",
    "logs/error.log",
    "debug.log",
    "error.log",
    "phpinfo.php",
    "info.php",
    "test.php",
    "robots.txt",
    "sitemap.xml",
    "index.html",
    "index.php",
    "api/keys.json",
    "api/config.json",
    "keys/",
    "export/",
    "exports/all.csv",
    "data/",
    "db/",
    "sql/",
]


def s3_time(t: datetime) -> str:
    return f"[{t.day:02d}/{MONTHS[t.month - 1]}/{t.year}:{t:%H:%M:%S} +0000]"


def presign(key_id: str, t: datetime, rng: random.Random) -> str:
    """The query string of a presigned URL (documentation example key ids only)."""
    return (
        "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-Credential={key_id}%2F{t:%Y%m%d}%2F{REGION}%2Fs3%2Faws4_request"
        f"&X-Amz-Date={t:%Y%m%dT%H%M%S}Z&X-Amz-Expires=300&X-Amz-SignedHeaders=host"
        f"&X-Amz-Signature={rng.getrandbits(256):064x}"
    )


@dataclass
class S3Req:
    """One line of an S3 server access log."""

    time: datetime
    ip: str  # "" when S3 itself made the request (lifecycle)
    requester: str  # ARN, canonical id, svc:..., or "" for anonymous
    operation: str  # REST.GET.OBJECT, REST.PUT.OBJECT, REST.GET.BUCKET, ...
    key: str  # "" for a bucket-level request
    method: str
    status: int
    error: str = ""
    bytes_sent: int | None = None
    object_size: int | None = None
    total_ms: int = 20
    turnaround_ms: int | None = 10
    referer: str = ""
    agent: str = "-"
    auth: str = "AuthHeader"  # AuthHeader, QueryString, or "" for anonymous
    tls: tuple[str, str] = TLS12
    query: str = ""

    def line(self, rng: random.Random) -> str:
        request_id = "".join(rng.choice("0123456789ABCDEF") for _ in range(16))
        host_id = base64.b64encode(rng.randbytes(56)).decode()
        uri = f"{self.method} /{self.key}{self.query} HTTP/1.1" if self.ip else "-"
        anonymous = not self.requester
        fields = [
            BUCKET_OWNER,
            BUCKET,
            s3_time(self.time),
            self.ip or "-",
            self.requester or "-",
            request_id,
            self.operation,
            self.key or "-",
            quote(uri),
            str(self.status),
            self.error or "-",
            "-" if self.bytes_sent is None else str(self.bytes_sent),
            "-" if self.object_size is None else str(self.object_size),
            str(self.total_ms),
            "-" if self.turnaround_ms is None else str(self.turnaround_ms),
            quote(self.referer or "-"),
            quote(self.agent),
            "-",  # version id: the bucket is not versioned
            host_id,
            "-" if anonymous or not self.ip else "SigV4",
            self.tls[0] if self.ip else "-",
            self.auth or "-",
            S3_HOST if self.ip else "-",
            self.tls[1] if self.ip else "-",
            "-",  # access point ARN
            "-",  # ACL required
        ]
        return " ".join(fields)


def error_bytes(status: int) -> int:
    return {403: 243, 404: 293, 503: 304}.get(status, 310)


def thumb_requests(rng: random.Random) -> list[S3Req]:
    """Shoppers fetching product images through presigned URLs the web tier hands out.

    Thumbnails for products 100-399 stop existing at 09:08 (bob's delete below), so from
    then on those requests come back 404 NoSuchKey: the planted 4xx-by-prefix problem.
    """
    out: list[S3Req] = []
    gone_from = at(S3_PLANTED["missing_thumbnails"]["from"])
    for _ in range(3400):
        t = moment(rng)
        signer = rng.choice(WEB_ROLE)
        product = rng.randrange(100, 1000) if rng.random() < 0.45 else rng.randrange(100, 400)
        thumb = rng.random() < 0.5
        key = f"images/{'thumbs' if thumb else 'products'}/{product}.jpg"
        size = rng.randrange(4_000, 30_000) if thumb else rng.randrange(40_000, 400_000)
        req = S3Req(
            t,
            rng.choice(PUBLIC_CLIENTS),
            signer.arn,
            "REST.GET.OBJECT",
            key,
            "GET",
            200,
            bytes_sent=size,
            object_size=size,
            total_ms=rng.randrange(12, 180),
            turnaround_ms=rng.randrange(8, 40),
            referer=f"{SHOP_URL}/products/{product}",
            agent=rng.choice(BROWSERS),
            auth="QueryString",
            tls=TLS13 if rng.random() < 0.7 else TLS12,
            query=presign(signer.key, t - timedelta(seconds=rng.randrange(1, 240)), rng),
        )
        if thumb and product in DELETED_THUMBS and t >= gone_from:
            req.status, req.error = 404, "NoSuchKey"
            req.bytes_sent, req.object_size = error_bytes(404), None
            req.turnaround_ms = None
        out.append(req)
    return out


def web_tier_requests(rng: random.Random) -> list[S3Req]:
    """The web instances: uploads, metadata checks and a feature-flag file polled each
    minute. A short 503 SlowDown burst is planted during an upload spike at 08:40."""
    out: list[S3Req] = []
    slow_lo, slow_hi = (at(x) for x in S3_PLANTED["throttled_uploads"]["window"])
    for host, who in zip(WEB, WEB_ROLE, strict=True):
        for t in every(rng, T0, T0 + DURATION, 60, jitter=0.05):
            out.append(
                S3Req(
                    t,
                    host.ip,
                    who.arn,
                    "REST.GET.OBJECT",
                    "config/feature-flags.json",
                    "GET",
                    200,
                    bytes_sent=1_842,
                    object_size=1_842,
                    total_ms=rng.randrange(8, 30),
                    turnaround_ms=rng.randrange(5, 15),
                    agent=BOTO_AGENT,
                    tls=TLS13,
                )
            )
        for t in every(rng, T0, T0 + DURATION, 120):
            product = rng.randrange(100, 1000)
            size = rng.randrange(40_000, 400_000)
            out.append(
                S3Req(
                    t,
                    host.ip,
                    who.arn,
                    "REST.PUT.OBJECT",
                    f"images/products/{product}.jpg",
                    "PUT",
                    200,
                    bytes_sent=None,
                    object_size=size,
                    total_ms=rng.randrange(30, 250),
                    turnaround_ms=rng.randrange(10, 60),
                    agent=BOTO_AGENT,
                    tls=TLS13,
                )
            )
        for t in every(rng, T0, T0 + DURATION, 75):
            product = rng.randrange(100, 1000)
            out.append(
                S3Req(
                    t,
                    host.ip,
                    who.arn,
                    "REST.HEAD.OBJECT",
                    f"images/products/{product}.jpg",
                    "HEAD",
                    200,
                    bytes_sent=None,
                    object_size=rng.randrange(40_000, 400_000),
                    total_ms=rng.randrange(6, 25),
                    turnaround_ms=rng.randrange(4, 12),
                    agent=BOTO_AGENT,
                    tls=TLS13,
                )
            )
    # A bulk import pushes 60 uploads through in two minutes; S3 throttles 14 of them.
    for i, t in enumerate(every(rng, slow_lo, slow_hi, 2, jitter=0.2)):
        host, who = WEB[i % 3], WEB_ROLE[i % 3]
        throttled = i % 4 == 1
        out.append(
            S3Req(
                t,
                host.ip,
                who.arn,
                "REST.PUT.OBJECT",
                f"images/products/{rng.randrange(1000, 1400)}.jpg",
                "PUT",
                503 if throttled else 200,
                error="SlowDown" if throttled else "",
                bytes_sent=error_bytes(503) if throttled else None,
                object_size=None if throttled else rng.randrange(40_000, 400_000),
                total_ms=rng.randrange(20, 90),
                turnaround_ms=None if throttled else rng.randrange(10, 60),
                agent=BOTO_AGENT,
                tls=TLS13,
            )
        )
    return out


def batch_requests(rng: random.Random) -> list[S3Req]:
    """Reports, backups, monitoring and lifecycle. The reports role lacks permission on
    exports/finance/ and retries three times every five minutes: the planted 403s."""
    out: list[S3Req] = []
    app_ip = APP[0].ip
    for t in every(rng, T0, T0 + DURATION, 600, jitter=0.02):
        out.append(
            S3Req(
                t,
                app_ip,
                REPORTS_ROLE.arn,
                "REST.PUT.OBJECT",
                f"exports/reports/sales-{t:%Y%m%d-%H%M}.csv",
                "PUT",
                200,
                object_size=rng.randrange(20_000, 90_000),
                total_ms=rng.randrange(30, 120),
                turnaround_ms=rng.randrange(10, 40),
                agent=JAVA_SDK_AGENT,
            )
        )
    denied_key = f"{S3_PLANTED['denied_exports']['prefix']}daily-2026-03-09.csv"
    for t in every(rng, T0, T0 + DURATION, 300, jitter=0.02):
        for attempt in range(3):
            out.append(
                S3Req(
                    t + timedelta(seconds=attempt * 2),
                    app_ip,
                    REPORTS_ROLE.arn,
                    "REST.GET.OBJECT",
                    denied_key,
                    "GET",
                    403,
                    error="AccessDenied",
                    bytes_sent=error_bytes(403),
                    total_ms=rng.randrange(6, 20),
                    turnaround_ms=None,
                    agent=JAVA_SDK_AGENT,
                )
            )
    # Nightly-style backups landing at 08:05, big objects uploaded in one go.
    backup_time = at("08:05")
    for i, (key, size) in enumerate(
        [
            ("backups/db/2026-03-10-0800.sql.gz", 648_204_311),
            ("backups/config/2026-03-10.tar.gz", 2_118_440),
            ("backups/README.txt", 412),
        ]
    ):
        out.append(
            S3Req(
                backup_time + timedelta(seconds=i * 90),
                DB.ip,
                BACKUP_ROLE.arn,
                "REST.PUT.OBJECT",
                key,
                "PUT",
                200,
                object_size=size,
                total_ms=max(40, size // 12_000),
                turnaround_ms=rng.randrange(20, 80),
                agent=CLI_AGENT,
            )
        )
    for t in every(rng, T0, T0 + DURATION, 300, jitter=0.02):
        out.append(
            S3Req(
                t,
                MONITOR_IP,
                MONITOR.arn,
                "REST.HEAD.BUCKET",
                "",
                "HEAD",
                200,
                total_ms=rng.randrange(5, 15),
                turnaround_ms=rng.randrange(3, 10),
                agent=BOTO_AGENT,
                tls=TLS13,
            )
        )
    for t in every(rng, T0, T0 + DURATION, 600):
        out.append(
            S3Req(
                t,
                "",
                LIFECYCLE,
                "S3.EXPIRE.OBJECT",
                f"tmp/upload-{rng.getrandbits(40):010x}.part",
                "-",
                200,
                object_size=rng.randrange(1_000, 5_000_000),
                total_ms=rng.randrange(10, 60),
                turnaround_ms=None,
                auth="",
            )
        )
    return out


def people_requests(rng: random.Random) -> list[S3Req]:
    """Alice and carol poking around with the CLI and the console; bob's cleanup script
    deleting every thumbnail for products 100-399 at 09:05 is the planted delete burst."""
    out: list[S3Req] = []
    alice_ip, bob_ip, carol_ip = (OFFICE_IPS[n] for n in ("alice", "bob", "carol"))
    for t in every(rng, at("08:10"), at("09:50"), 420, jitter=0.5):
        prefix = rng.choice(["exports/reports/", "images/products/", "static/", "backups/"])
        out.append(
            S3Req(
                t,
                alice_ip,
                ALICE.arn,
                "REST.GET.BUCKET",
                "",
                "GET",
                200,
                bytes_sent=rng.randrange(2_000, 40_000),
                total_ms=rng.randrange(20, 80),
                turnaround_ms=rng.randrange(10, 40),
                agent=CLI_AGENT,
                query=f"?list-type=2&prefix={prefix.replace('/', '%2F')}&encoding-type=url",
            )
        )
        if rng.random() < 0.6:
            size = rng.randrange(20_000, 90_000)
            out.append(
                S3Req(
                    t + timedelta(seconds=rng.randrange(3, 30)),
                    alice_ip,
                    ALICE.arn,
                    "REST.GET.OBJECT",
                    f"exports/reports/sales-20260309-{rng.randrange(8, 20):02d}00.csv",
                    "GET",
                    200,
                    bytes_sent=size,
                    object_size=size,
                    total_ms=rng.randrange(30, 120),
                    turnaround_ms=rng.randrange(10, 40),
                    agent=CLI_AGENT,
                )
            )
    for t in every(rng, at("08:30"), at("09:00"), 240, jitter=0.4):
        key = f"static/css/shop.{rng.getrandbits(32):08x}.css"
        size = rng.randrange(30_000, 120_000)
        out.append(
            S3Req(
                t,
                alice_ip,
                ALICE.arn,
                "REST.PUT.OBJECT",
                key,
                "PUT",
                200,
                object_size=size,
                total_ms=rng.randrange(40, 160),
                turnaround_ms=rng.randrange(10, 50),
                agent=CLI_AGENT,
            )
        )
    console_ops = [
        ("REST.GET.BUCKET", "", "GET", "?list-type=2&prefix=exports%2F&delimiter=%2F"),
        ("REST.GET.BUCKET", "", "GET", "?list-type=2&prefix=images%2F&delimiter=%2F"),
        ("REST.GET.VERSIONING", "", "GET", "?versioning"),
        ("REST.GET.LOCATION", "", "GET", "?location"),
        ("REST.GET.BUCKETPOLICY", "", "GET", "?policy"),
        ("REST.GET.PUBLIC_ACCESS_BLOCK", "", "GET", "?publicAccessBlock"),
        ("REST.GET.ENCRYPTION", "", "GET", "?encryption"),
        ("REST.GET.OBJECT", "exports/reports/sales-20260310-0900.csv", "GET", ""),
    ]
    for t in every(rng, at("09:20"), at("09:45"), 150, jitter=0.5):
        op, key, method, query = rng.choice(console_ops)
        size = rng.randrange(200, 40_000)
        out.append(
            S3Req(
                t,
                carol_ip,
                CAROL.arn,
                op,
                key,
                method,
                200,
                bytes_sent=size,
                object_size=size if key else None,
                total_ms=rng.randrange(15, 90),
                turnaround_ms=rng.randrange(8, 40),
                agent=CONSOLE_AGENT,
                tls=TLS13,
                query=query,
            )
        )
    # bob: a couple of listings, then "aws s3 rm --recursive" over the thumbnails.
    lo, hi = (at(x) for x in S3_PLANTED["deleted_thumbnails"]["window"])
    for i in range(3):
        out.append(
            S3Req(
                lo - timedelta(seconds=20 - i * 6),
                bob_ip,
                BOB.arn,
                "REST.GET.BUCKET",
                "",
                "GET",
                200,
                bytes_sent=rng.randrange(60_000, 90_000),
                total_ms=rng.randrange(60, 200),
                turnaround_ms=rng.randrange(30, 90),
                agent=CLI_AGENT,
                query="?list-type=2&prefix=images%2Fthumbs%2F&encoding-type=url"
                + ("&continuation-token=1%2Fexample" if i else ""),
            )
        )
    step = (hi - lo) / len(DELETED_THUMBS)
    for i, product in enumerate(DELETED_THUMBS):
        out.append(
            S3Req(
                lo + step * i,
                bob_ip,
                BOB.arn,
                "REST.DELETE.OBJECT",
                f"images/thumbs/{product}.jpg",
                "DELETE",
                204,
                total_ms=rng.randrange(8, 30),
                turnaround_ms=rng.randrange(5, 15),
                agent=CLI_AGENT,
            )
        )
    return out


def anonymous_requests(rng: random.Random) -> list[S3Req]:
    """Two strangers. One lists the bucket and downloads every backup without signing a
    thing, because a bucket policy grants read to everyone. The other guesses sixty
    file names that would be worth stealing and gets 403 for each."""
    out: list[S3Req] = []
    planted = S3_PLANTED["public_backups"]
    t = at(planted["window"][0])
    for query in ("?list-type=2", "?list-type=2&prefix=backups%2F"):
        out.append(
            S3Req(
                t,
                planted["ip"],
                "",
                "REST.GET.BUCKET",
                "",
                "GET",
                200,
                bytes_sent=rng.randrange(8_000, 60_000),
                total_ms=rng.randrange(40, 150),
                turnaround_ms=rng.randrange(20, 80),
                agent=CURL_AGENT,
                auth="",
                query=query,
            )
        )
        t += timedelta(seconds=rng.randrange(20, 40))
    backups = [(f"backups/db/2026-03-{day:02d}-0800.sql.gz", 640_000_000) for day in range(4, 11)]
    backups += [(f"backups/config/2026-03-{day:02d}.tar.gz", 2_100_000) for day in range(6, 11)]
    backups.append(("backups/README.txt", 412))
    for key, about in backups:
        size = about + rng.randrange(-about // 20, about // 20 + 1)
        out.append(
            S3Req(
                t,
                planted["ip"],
                "",
                "REST.GET.OBJECT",
                key,
                "GET",
                200,
                bytes_sent=size,
                object_size=size,
                total_ms=max(30, size // 9_000),
                turnaround_ms=rng.randrange(20, 80),
                agent=CURL_AGENT,
                auth="",
            )
        )
        t += timedelta(milliseconds=max(30, size // 9_000) + rng.randrange(500, 3000))
    probing = S3_PLANTED["anonymous_probing"]
    lo, hi = (at(x) for x in probing["window"])
    for i, key in enumerate(PROBE_KEYS):
        out.append(
            S3Req(
                lo + (hi - lo) * i / len(PROBE_KEYS) + timedelta(seconds=rng.random() * 4),
                probing["ip"],
                "",
                "REST.GET.OBJECT",
                key,
                "GET",
                403,
                error="AccessDenied",
                bytes_sent=error_bytes(403),
                total_ms=rng.randrange(5, 20),
                turnaround_ms=None,
                agent=SCANNER_AGENT,
                auth="",
            )
        )
    return out


def s3_requests(rng: random.Random) -> list[S3Req]:
    reqs = thumb_requests(rng)
    reqs += web_tier_requests(rng)
    reqs += batch_requests(rng)
    reqs += people_requests(rng)
    reqs += anonymous_requests(rng)
    reqs = [r for r in reqs if T0 <= r.time < T0 + DURATION]
    reqs.sort(key=lambda r: (r.time, r.operation, r.key))
    return reqs


def write_s3(out: Path, rng: random.Random) -> None:
    with (out / "s3_access_logs.log").open("w") as fh:
        for req in s3_requests(rng):
            fh.write(req.line(rng) + "\n")


# ----------------------------------------------------------------------------
# Route 53 Resolver query logs
# ----------------------------------------------------------------------------

RESOLVER_PLANTED = {
    "dga_burst": {"src": "10.0.2.11", "window": ("08:40", "08:52"), "names": 1500},
    "name_sweep": {"src": "10.0.0.5", "window": ("09:10", "09:20"), "hosts": 600},
    "firewall_blocks": {"src": "10.0.1.11", "domains": ["bad.example"]},
    "tunnelling": {"src": "10.0.2.10", "window": ("09:30", "09:50"), "domain": "dns.example.net"},
    "servfail": {"zone": "corp.example.internal", "window": ("09:00", "09:06")},
}
FIREWALL_GROUP = "rslvr-frg-0123456789abcdef0"
FIREWALL_LIST = "rslvr-fdl-0123456789abcdef0"
RESOLVER_VERSION = "1.100000"

# What the fleet looks up in a normal hour: (name, type, weight, answers)
PUBLIC_NAMES: list[tuple[str, str, int, list[str]]] = [
    ("api.example.com.", "A", 30, ["203.0.113.9"]),
    ("shop.example.com.", "A", 20, ["203.0.113.10", "203.0.113.11"]),
    ("cdn.example.com.", "A", 25, ["192.0.2.44", "192.0.2.45"]),
    ("cdn.example.com.", "AAAA", 8, []),
    ("auth.example.com.", "A", 10, ["203.0.113.12"]),
    ("www.example.org.", "A", 6, ["192.0.2.80"]),
    ("ntp.example.org.", "A", 4, ["192.0.2.123"]),
    ("s3.eu-west-1.amazonaws.com.", "A", 40, ["198.51.100.200", "198.51.100.201"]),
    ("dynamodb.eu-west-1.amazonaws.com.", "A", 25, ["198.51.100.202"]),
    ("ssm.eu-west-1.amazonaws.com.", "A", 15, ["198.51.100.203"]),
    ("logs.eu-west-1.amazonaws.com.", "A", 15, ["198.51.100.204"]),
    ("sts.amazonaws.com.", "A", 8, ["198.51.100.205"]),
    ("ec2.eu-west-1.amazonaws.com.", "A", 6, ["198.51.100.206"]),
    ("sqs.eu-west-1.amazonaws.com.", "A", 10, ["198.51.100.207"]),
]
INTERNAL_NAMES: list[tuple[str, str, int, list[str]]] = [
    ("db.corp.example.internal.", "A", 30, ["10.0.3.20"]),
    ("cache.corp.example.internal.", "A", 25, ["10.0.2.30"]),
    ("queue.corp.example.internal.", "A", 12, ["10.0.2.31"]),
    ("app.corp.example.internal.", "A", 18, ["10.0.2.10", "10.0.2.11"]),
    ("metrics.corp.example.internal.", "A", 8, ["10.0.0.40"]),
    ("vault.corp.example.internal.", "A", 6, ["10.0.0.41"]),
]
# Typos and stale names that get NXDOMAIN in any fleet.
STALE_NAMES = ["api.exmaple.com.", "old-cache.corp.example.internal.", "legacy.example.com."]


@dataclass
class Query:
    """One Route 53 Resolver query log record."""

    time: datetime
    src: Host
    name: str
    qtype: str
    rcode: str
    answers: list[str]
    transport: str = "UDP"
    firewall_action: str = ""

    def record(self, rng: random.Random) -> dict[str, object]:
        answer_type = "TXT" if self.qtype == "TXT" else ("PTR" if self.qtype == "PTR" else "A")
        rec: dict[str, object] = {
            "version": RESOLVER_VERSION,
            "account_id": ACCOUNT,
            "region": REGION,
            "vpc_id": VPC,
            "query_timestamp": self.time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "query_name": self.name,
            "query_type": self.qtype,
            "query_class": "IN",
            "rcode": self.rcode,
            "answers": [{"Rdata": a, "Type": answer_type, "Class": "IN"} for a in self.answers],
            "srcaddr": self.src.ip,
            "srcport": str(rng.randrange(32768, 61000)),
            "transport": self.transport,
            "srcids": {"instance": self.src.instance},
        }
        if self.firewall_action:
            rec["firewall_rule_action"] = self.firewall_action
            rec["firewall_rule_group_id"] = FIREWALL_GROUP
            rec["firewall_domain_list_id"] = FIREWALL_LIST
        return rec


def ptr_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa."


def background_queries(rng: random.Random) -> list[Query]:
    out: list[Query] = []
    servfail = RESOLVER_PLANTED["servfail"]
    sf_lo, sf_hi = (at(t) for t in servfail["window"])
    names = PUBLIC_NAMES + INTERNAL_NAMES
    weights = [w for _, _, w, _ in names]
    for host in ALL_HOSTS:
        # Web and app hosts are busy; the database and bastion barely resolve anything.
        rate = {"10.0.3.20": 60, "10.0.0.5": 40}.get(host.ip, 900)
        for _ in range(rate):
            t = moment(rng)
            name, qtype, _, answers = rng.choices(names, weights=weights)[0]
            rcode = "NOERROR"
            got = list(answers)
            if name.endswith("corp.example.internal.") and sf_lo <= t < sf_hi:
                rcode, got = "SERVFAIL", []
            transport = "TCP" if rng.random() < 0.03 else "UDP"
            out.append(Query(t, host, name, qtype, rcode, got, transport))
        for _ in range(rate // 60):
            out.append(Query(moment(rng), host, rng.choice(STALE_NAMES), "A", "NXDOMAIN", []))
        for _ in range(rate // 150):
            target = rng.choice(ALL_HOSTS).ip
            reverse = [f"host-{target.split('.')[-1]}.corp.example.internal."]
            out.append(Query(moment(rng), host, ptr_name(target), "PTR", "NOERROR", reverse))
    return out


def dga_name(rng: random.Random) -> str:
    length = rng.randrange(10, 17)
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(length))


def planted_queries(rng: random.Random) -> list[Query]:
    out: list[Query] = []
    by_ip = {h.ip: h for h in ALL_HOSTS}

    # A: something on an app host walks through algorithmically generated names, nearly
    # all of which do not exist: what malware looking for its controller looks like.
    p = RESOLVER_PLANTED["dga_burst"]
    lo, hi = (at(t) for t in p["window"])
    host = by_ip[p["src"]]
    for i in range(p["names"]):
        tld = rng.choice([".example.", ".test.", ".invalid."])
        t = lo + (hi - lo) * (i / p["names"]) + timedelta(seconds=rng.random() * 0.4)
        if rng.random() < 0.01:
            out.append(Query(t, host, dga_name(rng) + tld, "A", "NOERROR", ["198.51.100.66"]))
        else:
            out.append(Query(t, host, dga_name(rng) + tld, "A", "NXDOMAIN", []))

    # B: the bastion looks up every host name in the internal zone, and the reverse
    # records for a whole subnet, in ten minutes: someone mapping the network.
    p = RESOLVER_PLANTED["name_sweep"]
    lo, hi = (at(t) for t in p["window"])
    host = by_ip[p["src"]]
    for i in range(p["hosts"]):
        t = lo + (hi - lo) * (i / p["hosts"]) + timedelta(seconds=rng.random() * 0.5)
        name = f"host-{i + 1}.corp.example.internal."
        if i % 3 == 0:
            out.append(Query(t, host, name, "A", "NOERROR", [f"10.0.{1 + i % 3}.{10 + i % 200}"]))
        else:
            out.append(Query(t, host, name, "A", "NXDOMAIN", []))
        if i < 254:
            known = i % 4 == 0
            answers = [f"host-{i + 1}.corp.example.internal."] if known else []
            rcode = "NOERROR" if known else "NXDOMAIN"
            reverse = ptr_name(f"10.0.1.{i + 1}")
            out.append(Query(t + timedelta(seconds=0.2), host, reverse, "PTR", rcode, answers))

    # C: a web host keeps asking for names on a DNS Firewall block list, every twenty
    # seconds, all day: a browser extension or an agent phoning home.
    p = RESOLVER_PLANTED["firewall_blocks"]
    host = by_ip[p["src"]]
    bad = ["cdn.tracker.bad.example.", "update.bad.example.", "c2.bad.example."]
    t = T0 + timedelta(seconds=7)
    while t < T0 + DURATION:
        out.append(Query(t, host, rng.choice(bad), "A", "NXDOMAIN", [], firewall_action="BLOCK"))
        t += timedelta(seconds=18 + rng.random() * 6)

    # D: an app host sends hundreds of TXT queries whose left-most labels are long
    # random strings under one domain, and gets long answers back: data moving over DNS.
    p = RESOLVER_PLANTED["tunnelling"]
    lo, hi = (at(t) for t in p["window"])
    host = by_ip[p["src"]]
    for i in range(700):
        t = lo + (hi - lo) * (i / 700) + timedelta(seconds=rng.random() * 0.3)
        chunk = f"{rng.getrandbits(192):048x}"
        name = f"{chunk}.{rng.getrandbits(32):08x}.{p['domain']}."
        answer = base64.b64encode(rng.randbytes(45)).decode()
        out.append(Query(t, host, name, "TXT", "NOERROR", [f'"{answer}"']))
    return out


def resolver_queries(rng: random.Random) -> list[Query]:
    queries = background_queries(rng) + planted_queries(rng)
    queries = [qq for qq in queries if T0 <= qq.time < T0 + DURATION]
    queries.sort(key=lambda qq: (qq.time, qq.src.ip, qq.name))
    return queries


def write_resolver(out: Path, rng: random.Random) -> None:
    queries = resolver_queries(rng)
    with (out / "route53_resolver_query_logs.json").open("w") as fh:
        for qq in queries:
            fh.write(json.dumps(qq.record(rng), separators=(",", ":")) + "\n")
    # The same hour as a CSV export, the shape an Athena query over the log gives you.
    with (out / "route53_resolver_query_logs.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(
            [
                "query_timestamp",
                "query_name",
                "query_type",
                "rcode",
                "answers",
                "srcaddr",
                "srcport",
                "transport",
                "instance_id",
                "vpc_id",
                "firewall_rule_action",
            ]
        )
        for qq in queries:
            if qq.time >= T0 + timedelta(hours=1):
                break
            rec = qq.record(rng)
            w.writerow(
                [
                    rec["query_timestamp"],
                    qq.name,
                    qq.qtype,
                    qq.rcode,
                    " ".join(qq.answers),
                    qq.src.ip,
                    rec["srcport"],
                    qq.transport,
                    qq.src.instance,
                    VPC,
                    qq.firewall_action,
                ]
            )


# ----------------------------------------------------------------------------
# A cutover: the same hour of flow logs the day before and the day after a change
# ----------------------------------------------------------------------------

CUTOVER_BEFORE = datetime(2026, 3, 9, 8, 0, tzinfo=UTC)
CUTOVER_AFTER = datetime(2026, 3, 11, 8, 0, tzinfo=UTC)
CUTOVER_HOUR = timedelta(hours=1)
CACHE_OLD = Host(
    "10.0.2.30", "eni-0f6a7b8c9d0e10230", "subnet-0b2c3d4e5f6a70002", "i-0f6a7b8c9d0e10230"
)
CACHE_NEW = Host(
    "10.0.2.40", "eni-0f6a7b8c9d0e10240", "subnet-0b2c3d4e5f6a70002", "i-0f6a7b8c9d0e10240"
)
APP_NEW = Host(
    "10.0.2.12", "eni-0b2c3d4e5f6a70203", "subnet-0b2c3d4e5f6a70002", "i-0b2c3d4e5f6a70203"
)
CUTOVER_PLANTED = {
    "sg_now_rejects_5432": {"db": DB.ip, "port": 5432, "clients": [h.ip for h in APP]},
    "nacl_breaks_8080_replies": {"server": APP[1].ip, "port": 8080, "clients": "10.0.1.0/24"},
    "cache_moved": {"old": CACHE_OLD.ip, "new": CACHE_NEW.ip, "port": 6379},
    "new_app_host": {"ip": APP_NEW.ip},
}


def cutover_flows(rng: random.Random, start: datetime, after: bool) -> list[Flow]:
    """One hour of the fleet's traffic; ``after`` adds the regressions the change caused."""
    end = start + CUTOVER_HOUR

    def when() -> datetime:
        return start + timedelta(minutes=rng.randrange(60))

    flows: list[Flow] = []
    apps = [*APP, APP_NEW] if after else list(APP)
    cache = CACHE_NEW if after else CACHE_OLD
    # Public clients browsing the web tier: the same either day.
    for _ in range(700):
        flows += tcp_pair(rng, rng.choice(PUBLIC_CLIENTS), rng.choice(WEB), 443, when())
    # Hosts calling public services and the resolver.
    for _ in range(120):
        flows += tcp_pair(rng, rng.choice(ALL_HOSTS), rng.choice(PUBLIC_SERVICES[1:]), 443, when())
    for _ in range(300):
        h = rng.choice(ALL_HOSTS)
        sport = rng.randrange(32768, 61000)
        t = when()
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
                rng.randrange(150, 500),
                t,
                "ACCEPT",
                "ingress",
            )
        )
    # The internet knocking on closed ports, the same either day: not new, not interesting.
    for _ in range(80):
        web = rng.choice(WEB)
        flows.append(
            Flow(
                web,
                rng.choice(PUBLIC_CLIENTS),
                web.ip,
                rng.randrange(1024, 65000),
                rng.choice([22, 3389, 23]),
                TCP,
                1,
                44,
                when(),
                "REJECT",
                "ingress",
                SYN,
            )
        )
    # Web tier to the app tier on 8080.
    for _ in range(260):
        web, app = rng.choice(WEB), rng.choice(apps)
        t = when()
        if after and app is APP[1]:
            # The web subnet's NACL lost its ephemeral-port allow: request out, reply refused.
            sport = rng.randrange(32768, 61000)
            flows.append(
                Flow(
                    web,
                    web.ip,
                    app.ip,
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
                    app.ip,
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
            flows.append(
                Flow(
                    app,
                    web.ip,
                    app.ip,
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
                    app,
                    app.ip,
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
        else:
            flows += tcp_pair(rng, web, app, 8080, t)
    # App tier to the database on 5432.
    for _ in range(180):
        app = rng.choice(apps)
        t = when()
        if after:
            # The database security group was replaced and no longer allows the app tier.
            flows.append(
                Flow(
                    DB,
                    app.ip,
                    DB.ip,
                    rng.randrange(32768, 61000),
                    5432,
                    TCP,
                    1,
                    rng.randrange(40, 60),
                    t,
                    "REJECT",
                    "ingress",
                    SYN,
                )
            )
        else:
            flows += tcp_pair(rng, app, DB, 5432, t, resp_bytes=(2000, 200000))
    # App tier to the cache, which moved to a new host in the cutover.
    for _ in range(220):
        flows += tcp_pair(rng, rng.choice(apps), cache, 6379, when(), resp_bytes=(200, 8000))
    return [f for f in flows if start <= f.start < end]


def write_cutover(out: Path, rng: random.Random) -> None:
    for name, start, after in (
        ("cutover_before_flow_logs.log", CUTOVER_BEFORE, False),
        ("cutover_after_flow_logs.log", CUTOVER_AFTER, True),
    ):
        flows = cutover_flows(rng, start, after)
        flows.sort(key=lambda f: (f.start, f.eni.eni, f.src, f.dst))
        lines = [" ".join(CUSTOM_FIELDS)] + [" ".join(f.custom()) for f in flows]
        (out / name).write_text("\n".join(lines) + "\n")


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
    write_alb(out, random.Random(SEED + 2))
    write_nlb(out, random.Random(SEED + 3))
    write_cloudtrail(out, random.Random(SEED + 4))
    write_s3(out, random.Random(SEED + 5))
    write_resolver(out, random.Random(SEED + 6))
    write_cutover(out, random.Random(SEED + 7))
    for p in sorted(out.iterdir()):
        print(f"{p.name:40s} {p.stat().st_size / 1024:8.0f} KB")


if __name__ == "__main__":
    main()
