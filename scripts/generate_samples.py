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
"""

from __future__ import annotations

import argparse
import csv
import gzip
import math
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
    for p in sorted(out.iterdir()):
        print(f"{p.name:40s} {p.stat().st_size / 1024:8.0f} KB")


if __name__ == "__main__":
    main()
