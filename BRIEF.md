# Brief: logsift, drop in a CSV or log file and understand it right away

**Project type:** local data-analysis tool (web UI and CLI) · **Stack:** Python 3.12, uv, DuckDB,
FastAPI, Jinja2 and HTMX, pytest, ruff

## Why this exists

When I open a CSV or a log export I lose time working out what the columns mean and where the
interesting rows are. I want to drop a file in and get an immediate, plain-English read of it.
The case I care about most is AWS VPC Flow Logs: I want the tool to tell me where traffic is
breaking (rejected flows, one-way flows, a blocked return path) and what is unusual, without
writing Logs Insights queries by hand.

## Stack

- Python 3.12 managed with `uv`. DuckDB does the querying so files with millions of rows stay
  fast. Use Polars only if it clearly helps.
- FastAPI serves a local web UI built from Jinja2 templates and HTMX. There is no Node build
  step. A small chart library (uPlot or Chart.js) can be vendored as a static file.
- There is also a CLI: `logsift serve` starts the UI, and `logsift report <file>` writes a
  self-contained HTML report.
- pytest for tests, ruff for lint and format, and type hints throughout.

## First pass: build this now

1. **Load:** drag-and-drop or file picker in the browser, plus a CLI path argument. Handle
   comma, tab, semicolon, pipe and space-delimited files, quoted fields, a byte order mark and
   gzip (`.gz`). Show row and column counts and any parse warnings.
2. **Format detection:** recognise these formats and say which one was found:
   - generic CSV
   - VPC Flow Logs in the default version 2 space-delimited format
   - VPC Flow Logs in custom formats with a header line (fields up to version 5, such as
     `tcp-flags`, `pkt-srcaddr`, `flow-direction` and `traffic-path`)
   - CloudWatch Logs Insights CSV exports (`@timestamp`, `@message` and parsed fields)
3. **Generic profile:** an inferred type for each column, with count, missing, distinct,
   min/max/mean/median, earliest/latest for dates, the top values and a small inline histogram.
   Add a short "what this file looks like" summary at the top.
4. **Flow-log insights:** rule-based findings, each with a severity, a plain-English
   explanation, the likely cause and the rows behind it:
   - rejected traffic grouped by source, destination, port and protocol, and by ENI and subnet
     where those fields exist
   - **asymmetric flows:** ACCEPT in one direction and REJECT on the return path. Explain that
     security groups are stateful and network ACLs are not, so this usually points to a NACL.
   - SYN without SYN-ACK when `tcp-flags` is present (connection attempts that never complete)
   - top talkers by bytes and packets, and traffic to or from public IPs
   - one source hitting many ports or hosts in a short window, presented as a fact to look at,
     not as an attack verdict
   - NODATA and SKIPDATA records, and gaps in the time range
   - a timeline of accepted against rejected flows
5. **Explore:** a paginated table with search and a simple filter by column value, plus a click
   from any finding to its rows.
6. **Export:** the findings and the filtered rows as CSV, JSON and `.xlsx`. Use `openpyxl`, or
   a small hand-written writer if that keeps dependencies down: bold frozen header, real number
   and date cells, auto-sized columns.
7. **Sample data:** a seeded generator in `scripts/` that produces fictional flow logs with known
   problems planted in them: a NACL blocking return traffic, a security group rejecting 5432, a
   noisy top talker and a one-to-many port sweep. Also generate one generic CSV, for example
   daily sales for a made-up shop. Ship a few generated files in `samples/`.
8. **Tests:** delimiter and format detection, type inference, each insight rule against the
   planted problems in the samples, and the exports.
9. **Repo basics:** a README (what it does, who it is for, stack, how to run it and a
   screenshot), an MIT LICENSE under "Bello Mohammed", `.gitignore` (including `.env`, `.venv`
   and anything a user drops in under `data/`), and GitHub Actions running ruff and pytest.
10. **ROADMAP.md:** put everything listed under "Later" below there, as concrete items.

## Later: list in ROADMAP.md, do not build now

- More formats: ALB/NLB access logs, CloudTrail CSV exports, S3 server access logs and Route 53
  Resolver query logs
- Streaming and sampling for files larger than memory, with progress
- A saved "investigation" view: pin findings, add notes, export as a report
- A query box that turns a finding into the matching CloudWatch Logs Insights query
- Diffing two files (before and after a change)
- Packaging: `pipx install logsift` and a single-file build

## Ground rules

- Everything runs locally. Nothing is uploaded, and there is no telemetry, no accounts and no
  cloud resources.
- Findings are rule-based. No AI or LLM calls and no model inference.
- Sample data is fictional only. Use the documentation IP ranges (192.0.2.0/24, 198.51.100.0/24,
  203.0.113.0/24) plus private 10.x ranges, and the example account ID `123456789012`.
- No secrets anywhere. If config is needed, ship a `.env.example`.
- Work in small steps. Commit each working step with a clear message, and run ruff and pytest
  before each commit.
- When the first pass is done, tell me exactly what to try in the browser and with the CLI.
