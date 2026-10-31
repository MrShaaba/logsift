# logsift

Drop in a CSV or log file and understand it right away.

logsift is a small local tool for the moment you open an unfamiliar CSV or log export and
lose time working out what the columns mean and where the interesting rows are. You drop a
file in and get a plain-English read of it: what the file is, what each column holds, and,
for AWS VPC Flow Logs, load balancer access logs and CloudTrail exports, where traffic is
breaking and what looks unusual.

![logsift showing findings for a VPC Flow Log](docs/screenshot.png)

## Who it is for

Engineers who get handed a flow log export, a load balancer access log, a CloudTrail
download, a CloudWatch Logs Insights CSV or a random data dump and want answers before
writing a single query. The cases it cares about most are VPC Flow Logs (rejected flows,
one-way flows, a blocked return path, a port sweep, a noisy host, gaps in the capture), ALB
and NLB access logs (a target failing behind a passing health check, a burst of 5xx, a slow
endpoint, rejected TLS handshakes) and CloudTrail event exports (a key being tested against
every action it might have, console sign-ins without MFA, root activity, instances appearing
in a region nobody uses).

## What it does

- **Loads** comma, tab, semicolon, pipe and space-delimited files, with quoted fields, a
  byte order mark and gzip. Shows row and column counts and any parse warnings.
- **Recognises the format**: generic CSV, VPC Flow Logs in the default version 2 format,
  custom flow-log formats with a header line (fields up to version 5 such as `tcp-flags`,
  `pkt-srcaddr`, `flow-direction` and `traffic-path`), CloudWatch Logs Insights exports
  (flow fields either as parsed columns or inside `@message`), Application Load Balancer
  access logs (every documented field, older files with fewer fields included), Network
  Load Balancer TLS access logs, and CloudTrail event exports as CSV: the console's event
  history download, a CloudTrail Lake or Athena result, or a flattened export with columns
  like `userIdentity.type`. Header names are matched loosely, so `Event name`, `eventName`
  and `eventname` all work.
- **Profiles every column**: inferred type, count, missing, distinct, min/max/mean/median,
  earliest/latest for dates, top values and a small histogram, with a short "what this
  file looks like" summary on top.
- **Finds problems in flow logs** with plain rules, each with a severity, an explanation,
  the likely cause and the rows behind it:
  - rejected traffic by source, destination, port and protocol, and by ENI and subnet
  - asymmetric flows: ACCEPT one way, REJECT on the return path. Security groups are
    stateful and network ACLs are not, so this usually points at a NACL
  - SYN without SYN-ACK when `tcp-flags` is present
  - top talkers by bytes and packets, and traffic to or from public IPs
  - one source hitting many ports or hosts in a short window, stated as a fact to look at
  - NODATA and SKIPDATA records, gaps in the time range
  - a timeline of accepted against rejected flows
- **Finds problems in ALB and NLB access logs** the same way. The request line is split
  into method, host and path, addresses into IP and port, and TLS alert codes get names:
  - 5xx by status code, path and target, telling apart errors the target returned from
    ones the load balancer generated (502, 503, 504)
  - bursts of server errors, judged against the file's own error rate
  - a target failing far more of its requests than its siblings while still in rotation,
    which is what a passing health check in front of a broken process looks like
  - slow paths and 504 timeouts against the file's own p95, 4xx by status, path and client
  - one client probing many paths, stated as a fact to look at rather than a verdict
  - NLB handshakes that never completed, grouped by the TLS alert the client sent, with a
    likely cause per alert (untrusted chain, rejected certificate, no client hello)
  - one client churning through hundreds of very short connections
  - clients still negotiating TLS 1.0 or 1.1, top clients and user agents
  - a timeline of requests against 5xx, or connections against failed handshakes
- **Finds problems in CloudTrail exports** the same way. Role sessions are grouped under
  their role as the `principal`, and the identity type, MFA flag and sign-in result are read
  from the full event record or a `userIdentity` column when the export has no column for
  them:
  - calls refused by a policy, by principal and action, error code and source address
  - bursts of refusals from one principal, telling two dozen different actions tried from a
    new address (someone testing a key) apart from one action retried on a schedule (a
    missing permission), with the access key and the named resource in the likely cause
  - console sign-ins without MFA, with the root account called out, and failed sign-ins
  - root account activity, with its changes and the resources it touched listed first
  - API calls in regions holding under five percent of the account's regional activity,
    high severity when something was created there and low when it was all read-only
  - a principal, service and source address overview, and a timeline of calls against errors
- **Explores** rows in a paginated table with search, a column filter and sorting, and a
  click from any finding straight to its rows.
- **Exports** findings and filtered rows as CSV, JSON and `.xlsx` (bold frozen header, real
  number and date cells, auto-sized columns).
- **Writes a self-contained HTML report** from the command line.

![logsift showing findings for an ALB access log](docs/screenshot-alb.png)

![logsift showing findings for a CloudTrail export](docs/screenshot-cloudtrail.png)

Everything runs locally. Nothing is uploaded, there is no telemetry, no accounts and no
cloud resources. Findings are rules, not models.

## Stack

Python 3.12 managed with [uv](https://docs.astral.sh/uv/). DuckDB does the querying so
files with millions of rows stay fast. FastAPI serves a local web UI built from Jinja2
templates and HTMX (vendored, no Node build step). Charts are server-rendered SVG. openpyxl
writes the `.xlsx` files. pytest for tests, ruff for lint and format.

## Run it

```bash
uv sync --group dev
uv run logsift serve --open          # web UI at http://127.0.0.1:8000
uv run logsift serve samples/vpc_flow_logs_custom_v5.log   # start with a file loaded
uv run logsift report samples/vpc_flow_logs_v2.log         # writes samples/vpc_flow_logs_v2.report.html
uv run logsift inspect samples/cloudtrail_events.csv -v    # summary and findings in the terminal
```

In the browser, drag a file onto the drop zone or pick one. Uploaded files are kept under
`data/uploads/`, which git ignores. The home page also lists the files in `samples/` so you
can open one with a click.

No configuration is needed. `.env.example` lists the optional host, port and data
directory overrides for `logsift serve`.

## Sample data

`samples/` holds fictional files produced by `scripts/generate_samples.py` (seeded, so the
output is reproducible). The flow logs, load balancer logs and CloudTrail export cover the
same two hour window and have known problems planted in them:

| Problem | Where to look |
| --- | --- |
| Network ACL blocking return traffic from `10.0.2.10:8080` to the web subnet | "Return traffic blocked" finding |
| Security group rejecting PostgreSQL `5432` from the app tier to `10.0.3.20` | "TCP port 5432 to 10.0.3.20 rejected" |
| Noisy host `10.0.1.12` pushing gigabytes to `203.0.113.9` | "Top talker" |
| `198.51.100.77` sweeping ports 20 to 220 on `10.0.1.10` | "reached 201 different ports" |
| SYN-only flows to `10.0.2.99:9200` that never complete (custom format only) | "SYN without SYN-ACK" |
| SKIPDATA and NODATA records, and a 21 minute gap | "SKIPDATA", "NODATA", "gap in the time range" |
| ALB target `10.0.2.11:8080` returning 502 for twenty minutes behind a passing health check | "Target 10.0.2.11:8080 failed 48% of its requests", "burst of server errors" |
| ALB endpoint `/api/reports/export` taking seconds and sometimes hitting the 60 s timeout | "slow requests took 2 s or more, 8 timed out" |
| `198.51.100.77` probing sixty well-known paths on the ALB, plus malformed requests | "tried 60 different paths", "client errors" |
| An old integration still on TLS 1.1 (`Java/1.7.0_80`) | "still used TLSv1.1" |
| NLB handshakes aborted with `unknown_ca` and `bad_certificate`, plus plain TCP to the TLS listener | "TLS handshakes failed" |
| `198.51.100.23` opening 600 connections to the NLB in four minutes | "opened 601 connections in 4 minutes" |
| `bob`'s access key used from `203.0.113.77` to try 22 actions in six minutes, nearly all refused | "bob was refused 220 calls in 6 minutes across 22 different actions" |
| The web tier's role refused `ssm:GetParameter` on one parameter every thirty seconds | "shop-web-role was refused 181 calls in 30 minutes, all ssm:GetParameter" |
| `carol` and the root account signing in to the console with a password alone | "3 console sign-ins without MFA, 1 by the root account" |
| Root creating `backup-admin`, attaching `AdministratorAccess` and making it an access key | "The root account made 11 calls, 4 of them changes" |
| `backup-admin` launching instances in `ap-southeast-1` and `us-east-2` | "22 calls in 2 regions this account rarely uses" |

Addresses come from the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and private 10.x space, and the account is the example `123456789012`.
The load balancer logs use `shop.example.com` and `api.example.com`. The CloudTrail export
uses the documentation access key ids (`AKIAIOSFODNN7EXAMPLE` and friends) and carries the
full event record in its last column, the way the console's CSV download does.
`daily_sales.csv` is a generic CSV for a made-up coffee shop.

Regenerate with `uv run python scripts/generate_samples.py`.

## Develop

```bash
uv run ruff check . && uv run ruff format --check .
uv run pytest
```

GitHub Actions runs the same two commands on every push and pull request.

Layout:

```
src/logsift/
  loader.py       delimiter and header sniffing, typed loading into DuckDB, parse warnings
  formats.py      format detection, flow-log, ALB, NLB and CloudTrail field dictionaries
  flow.py         canonical typed flow table
  lb.py           typed lb table for ALB and NLB logs, with derived columns
  trail.py        typed trail table for CloudTrail exports, identity and MFA derived
  profile.py      per-column profile and the plain-English summary
  insights/       rule-based findings: flowlogs.py, lblogs.py and cloudtrail.py
  explore.py      paginated search and filter queries
  export.py       CSV, JSON and .xlsx writers
  report.py       self-contained HTML report
  web/            FastAPI app, Jinja2 templates, vendored HTMX and CSS
  cli.py          logsift serve | report | inspect
scripts/generate_samples.py
samples/
tests/
```

See [ROADMAP.md](ROADMAP.md) for what comes next.

## License

MIT, see [LICENSE](LICENSE).
