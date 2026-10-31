# logsift

Drop in a CSV or log file and understand it right away.

logsift is a small local tool for the moment you open an unfamiliar CSV or log export and
lose time working out what the columns mean and where the interesting rows are. You drop a
file in and get a plain-English read of it: what the file is, what each column holds, and,
for AWS VPC Flow Logs, where traffic is breaking and what looks unusual.

![logsift showing findings for a VPC Flow Log](docs/screenshot.png)

## Who it is for

Engineers who get handed a flow log export, a CloudWatch Logs Insights CSV or a random
data dump and want answers before writing a single query. The case it cares about most is
VPC Flow Logs: rejected flows, one-way flows, a blocked return path, a port sweep, a noisy
host, gaps in the capture.

## What it does

- **Loads** comma, tab, semicolon, pipe and space-delimited files, with quoted fields, a
  byte order mark and gzip. Shows row and column counts and any parse warnings.
- **Recognises the format**: generic CSV, VPC Flow Logs in the default version 2 format,
  custom flow-log formats with a header line (fields up to version 5 such as `tcp-flags`,
  `pkt-srcaddr`, `flow-direction` and `traffic-path`), and CloudWatch Logs Insights exports
  (flow fields either as parsed columns or inside `@message`).
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
- **Explores** rows in a paginated table with search, a column filter and sorting, and a
  click from any finding straight to its rows.
- **Exports** findings and filtered rows as CSV, JSON and `.xlsx` (bold frozen header, real
  number and date cells, auto-sized columns).
- **Writes a self-contained HTML report** from the command line.

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
uv run logsift inspect samples/cloudwatch_insights_export.csv -v   # summary and findings in the terminal
```

In the browser, drag a file onto the drop zone or pick one. Uploaded files are kept under
`data/uploads/`, which git ignores. The home page also lists the files in `samples/` so you
can open one with a click.

No configuration is needed. `.env.example` lists the optional host, port and data
directory overrides for `logsift serve`.

## Sample data

`samples/` holds fictional files produced by `scripts/generate_samples.py` (seeded, so the
output is reproducible). The flow logs cover a two hour window and have known problems
planted in them:

| Problem | Where to look |
| --- | --- |
| Network ACL blocking return traffic from `10.0.2.10:8080` to the web subnet | "Return traffic blocked" finding |
| Security group rejecting PostgreSQL `5432` from the app tier to `10.0.3.20` | "TCP port 5432 to 10.0.3.20 rejected" |
| Noisy host `10.0.1.12` pushing gigabytes to `203.0.113.9` | "Top talker" |
| `198.51.100.77` sweeping ports 20 to 220 on `10.0.1.10` | "reached 201 different ports" |
| SYN-only flows to `10.0.2.99:9200` that never complete (custom format only) | "SYN without SYN-ACK" |
| SKIPDATA and NODATA records, and a 21 minute gap | "SKIPDATA", "NODATA", "gap in the time range" |

Addresses come from the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and private 10.x space, and the account is the example `123456789012`.
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
  formats.py      format detection and the flow-log field dictionary
  flow.py         canonical typed flow table
  profile.py      per-column profile and the plain-English summary
  insights/       rule-based findings for flow logs
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
