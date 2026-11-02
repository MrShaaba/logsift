# logsift

Drop in a CSV or log file and understand it right away.

logsift is a small local tool for the moment you open an unfamiliar CSV or log export and
lose time working out what the columns mean and where the interesting rows are. You drop a
file in and get a plain-English read of it: what the file is, what each column holds, and,
for AWS VPC Flow Logs, load balancer access logs, CloudTrail exports, S3 server access logs
and Route 53 Resolver query logs, where traffic is breaking and what looks unusual. Every
finding comes with the CloudWatch Logs Insights query that finds the same rows in the live
log group, and findings and rows can be pinned to an investigation with notes and exported
as one HTML page.

![logsift showing findings for a VPC Flow Log](docs/screenshot.png)

## Who it is for

Engineers who get handed a flow log export, a load balancer access log, a CloudTrail
download, an S3 access log, a CloudWatch Logs Insights CSV or a random data dump and want
answers before writing a single query. The cases it cares about most are VPC Flow Logs
(rejected flows, one-way flows, a blocked return path, a port sweep, a noisy host, gaps in
the capture), ALB and NLB access logs (a target failing behind a passing health check, a
burst of 5xx, a slow endpoint, rejected TLS handshakes), CloudTrail event exports (a key
being tested against every action it might have, console sign-ins without MFA, root
activity, instances appearing in a region nobody uses) and S3 server access logs (a public
prefix being read anonymously, a stranger guessing file names, 404s piling up under one
prefix after a cleanup, a batch role refused on a schedule) and Route 53 Resolver query
logs (a host generating names, DNS Firewall blocks, data moving over DNS, an internal zone
failing to resolve).

## What it does

- **Loads** comma, tab, semicolon, pipe and space-delimited files, with quoted fields, a
  byte order mark and gzip, and JSON-lines files (one object per line). Shows row and
  column counts and any parse warnings.
- **Handles large files**: a file streams into DuckDB chunk by chunk, so one bigger than
  memory still loads, with rows and bytes read shown as it goes. The web UI reads the
  first 250,000 rows for a quick first look and offers a button for the full pass; loaded
  files are kept in a local DuckDB database under `data/db/` and are still there after a
  restart. See [Large files](#large-files).
- **Recognises the format**: generic CSV, VPC Flow Logs in the default version 2 format,
  custom flow-log formats with a header line (fields up to version 5 such as `tcp-flags`,
  `pkt-srcaddr`, `flow-direction` and `traffic-path`), CloudWatch Logs Insights exports
  (flow fields either as parsed columns or inside `@message`), Application Load Balancer
  access logs (every documented field, older files with fewer fields included), Network
  Load Balancer TLS access logs, CloudTrail event exports as CSV (the console's event
  history download, a CloudTrail Lake or Athena result, or a flattened export with columns
  like `userIdentity.type`; header names are matched loosely, so `Event name`, `eventName`
  and `eventname` all work), S3 server access logs (the bracketed timestamp and quoted
  request line, older files with fewer fields included) and Route 53 Resolver query logs
  (the JSON records Resolver delivers to CloudWatch Logs, S3 or Firehose, or a CSV export
  of them). Each format is a plug-in, see [Adding a format](#adding-a-format).
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
- **Finds problems in S3 server access logs** the same way. The requester ARN becomes a
  `principal` (or `anonymous`), the key gets a two-level `prefix`, and the request line is
  split into method, path and query:
  - anonymous requests that succeeded, by prefix, address and the largest objects read: a
    bucket policy or ACL open to everyone, with the prefixes to treat as disclosed
  - anonymous requests that were refused, told apart as background noise or one address
    guessing dozens of file names worth stealing
  - failed requests by status and error code, key prefix, principal and client address
  - 404s piling up under one prefix, with the pages still linking to the keys and, when the
    file shows it, who deleted them and when
  - a signed principal refused on a schedule, with the IAM action to grant
  - a burst of deletes by one principal, rated high when the keys were requested afterwards
  - a who-uses-the-bucket overview, and a timeline of requests against errors
- **Finds problems in Route 53 Resolver query logs** the same way. Each query gets its
  registrable `domain`, name length and label count, and flags for a failed or a
  firewall-blocked answer:
  - names DNS Firewall blocked, by name, host and domain, with the rhythm of the queries
    (a process on a timer reads differently from a person)
  - a host getting NXDOMAIN hundreds of times in minutes, told apart as a zone being
    enumerated (names under one zone, reverse lookups) or a domain generation algorithm
    (random labels spread across top-level domains)
  - a host asking for far more different names than the rest of the fleet
  - possible tunnelling: long, never-repeated labels under one domain, with the bytes
    carried in questions and answers
  - SERVFAIL runs per domain, with the forwarding endpoint called out for private zones
  - an error summary by response code, domain and host, the top clients and names, and a
    timeline of answered against failed or blocked queries
- **Gives you the CloudWatch Logs Insights query** for every finding, with a Copy button:
  the finding's own row filter translated into the log group's field names, the time
  window in a comment for the console's time picker, and a `stats` clause for the
  aggregate rules. See [Logs Insights queries](#logs-insights-queries).
- **Keeps investigations**: pin findings and individual rows from any loaded file, add
  notes, and export the lot as one self-contained HTML page. Saved under
  `data/investigations/`. See [Investigations](#investigations).
- **Explores** rows in a paginated table with search, a column filter and sorting, and a
  click from any finding straight to its rows.
- **Exports** findings and filtered rows as CSV, JSON and `.xlsx` (bold frozen header, real
  number and date cells, auto-sized columns).
- **Writes a self-contained HTML report** from the command line, for a file or for an
  investigation.

![logsift showing findings for an ALB access log](docs/screenshot-alb.png)

![logsift showing findings for a CloudTrail export](docs/screenshot-cloudtrail.png)

![logsift showing findings for an S3 server access log](docs/screenshot-s3.png)

![logsift showing findings for a Route 53 Resolver query log](docs/screenshot-route53.png)

![an investigation with a pinned finding, a pinned row and notes](docs/screenshot-investigation.png)

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
uv run logsift inspect samples/s3_access_logs.log --queries  # with the Logs Insights query per finding
uv run logsift investigations                              # list the saved investigations
uv run logsift report --investigation "Blocked replies"    # export one as HTML
```

In the browser, drag a file onto the drop zone or pick one. Uploaded files are kept under
`data/uploads/` and the loaded tables under `data/db/`, both ignored by git, so a file you
opened yesterday is still there when you start the server today. The home page also lists
the files in `samples/` so you can open one with a click.

No configuration is needed. `.env.example` lists the optional host, port, data directory
and sample-size overrides for `logsift serve`.

## Large files

A file is never read into memory whole. The loader sniffs the delimiter and header from
the first few kilobytes, infers each column's type from the first chunk, then streams the
rest through DuckDB in 16 MiB chunks of whole lines straight into the typed table, gzip
included. Memory stays flat however big the file is, and every chunk reports rows and
bytes read: the CLI prints a progress line on stderr, the web UI shows a bar.

In the web UI a file first loads as a **sample**, the first 250,000 rows, which takes a
second or two even for a multi-gigabyte log. The overview says so, the profile and
findings cover only those rows, and **Run the full pass** loads the rest in the
background while the page shows progress and then reloads itself with everything
recomputed. `logsift serve --sample-rows N` (or `LOGSIFT_SAMPLE_ROWS`) changes the sample
size; `logsift inspect --sample N` and `logsift report --sample N` do the same on the
command line, where the default is the whole file.

![The first look at a 5,000,000-row flow log, with the button for the full pass](docs/screenshot-large.png)

Loaded files live in one DuckDB database file per dataset under `data/db/`, next to a small
JSON sidecar with what the sniffer and the format detection found. When the server starts
it reopens them in about a second instead of reloading the files; a sampled file can still
run its full pass later as long as the original file is where it was. **Close** removes
the database, the sidecar and, for an upload, the uploaded copy.

To try it on something big, generate a day of flow logs for the same fictional VPC as the
samples (seeded, written to `data/`, which git ignores, never committed):

```bash
uv run python scripts/generate_big_flow_log.py                  # 5,000,000 rows, about 550 MB, 30 s
uv run python scripts/generate_big_flow_log.py --rows 20000000  # or as many as you like
uv run python scripts/generate_big_flow_log.py --format custom --gzip --rows 1000000
uv run logsift serve --open data/big_vpc_flow_logs.log          # first look in a few seconds
uv run logsift inspect data/big_vpc_flow_logs.log               # the whole file, with progress
```

The planted problems are the sample's, scaled to a day: the blocked return path, the
database security group refusing 5432, a web host pushing tens of gigabytes to one public
address, a thousand-port sweep at 10:00, SYN-only flows, NODATA and SKIPDATA records and a
twenty minute gap at 13:00.

## Logs Insights queries

Every finding carries the CloudWatch Logs Insights query that selects the same rows in
the live log group, under a "CloudWatch Logs Insights query" panel on the finding card
with a Copy button (in the web UI and in the HTML report), under `logsift inspect
--queries`, and as a `query` column in the findings exports.

The query is not written by hand per rule. A finding's row filter is a plain SQL boolean
over the format's canonical table, so `insights/cwlogs.py` parses that small SQL subset
and prints it back in the Logs Insights language, and each plug-in says how its columns
map onto a log group through a `QuerySpec`:

- the Logs Insights field for each column (`srcaddr` is `srcAddr` in a flow log group,
  `event_name` is `eventName` in a trail's, `instance_id` is `srcids.instance` in a
  Resolver's);
- how the derived columns the table builder invented read as real fields: `is_error`
  becomes `http_status >= 400`, `client_ip = '198.51.100.77'` becomes
  `client like /^198\.51\.100\.77:/`, a CloudTrail `principal` becomes a match on
  `userIdentity.arn`;
- which columns are the time axis: conditions on them are lifted out of the filter into
  a comment, because the console has a time picker for that;
- a `parse @message` clause when CloudWatch does not discover the fields itself: custom
  flow-log formats (parsed in the file's own field order), and ALB, NLB and S3 lines,
  which are delivered to S3 rather than CloudWatch Logs and get a note saying so;
- a `stats` clause for the aggregate rules (a rejected cluster by source, a denied burst
  by action and error code, missing keys by key) instead of a row listing.

Anything the language cannot express (a derived `total_time`, a `tcp_flags` bit test
beyond the SYN-only case, a column with no CloudWatch counterpart) is dropped from an
`and` with a comment saying the query returns more rows than the finding, so what remains
still runs. The queries are produced from the documented field names and were not run
against a live log group; treat the first one from a new format as something to check.

## Investigations

Pin a finding from the overview, or a row from the explorer, and it lands in the active
investigation (the picker above the findings and the rows chooses which one receives
pins, or makes a new one; the first pin creates one when there is none). An investigation
holds free-text notes, the pinned findings rendered by the same card as on the overview
(tables and Logs Insights query included), and the pinned rows per file, each with a note
of its own. "Export as HTML" writes the whole thing as one self-contained page, the same
output `logsift report --investigation NAME` gives on the command line, and `logsift
investigations` lists what is saved.

A pin is a snapshot: the finding's text, tables (first ten rows each), filter and query,
or the row's values, so an investigation still reads after the file it came from is
closed, reloaded or replaced. Each investigation is one JSON file under
`data/investigations/`, written atomically. Rows can be pinned from any table with row
numbers, which is every recognised format; a generic file's rows have no stable identity
yet.

## Sample data

`samples/` holds fictional files produced by `scripts/generate_samples.py` (seeded, so the
output is reproducible). The flow logs, load balancer logs, CloudTrail export, S3 access
log and Resolver query log cover the same two hour window and have known problems planted
in them:

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
| A bucket policy letting anyone list the bucket and read `backups/`, and `203.0.113.61` pulling 4 GB of database dumps unsigned | "15 anonymous requests succeeded, reading 13 objects (4.1 GB)" |
| `198.51.100.77` guessing sixty file names (`.env`, `backup.sql`, `id_rsa`) without credentials | "60 anonymous requests were refused, all from 198.51.100.77" |
| `bob` deleting three hundred thumbnails with the CLI while the shop still links to them | "bob deleted 300 objects in 3 minutes", "478 requests for objects that do not exist under images/thumbs/" |
| `shop-reports-role` missing permission on `exports/finance/` and retrying every five minutes | "shop-reports-role was refused 72 requests under exports/finance/" |
| An upload spike throttled with 503 SlowDown | "By status and error code" table under "625 requests failed" |
| `10.0.2.11` walking through 1,500 algorithmically generated names under `.example`, `.test` and `.invalid` | "10.0.2.11 got NXDOMAIN for 1,490 different names in 14 minutes" |
| The bastion `10.0.0.5` looking up every `host-N.corp.example.internal` and the reverse records for `10.0.1.0/24` | "10.0.0.5 got NXDOMAIN for 590 different names in 10 minutes" |
| `10.0.1.11` asking for `c2.bad.example` and friends every twenty seconds, all day, blocked by DNS Firewall | "DNS Firewall blocked 342 queries for 3 names under bad.example" |
| `10.0.2.10` moving data in 700 TXT queries with 48-character labels under `dns.example.net` | "Possible DNS tunnel" |
| Six minutes of SERVFAIL for `corp.example.internal` while the outbound endpoint was down | "SERVFAIL for 68 queries under example.internal over 6 minutes" |

Addresses come from the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) and private 10.x space, and the account is the example `123456789012`.
The load balancer logs use `shop.example.com` and `api.example.com`. The CloudTrail export
uses the documentation access key ids (`AKIAIOSFODNN7EXAMPLE` and friends) and carries the
full event record in its last column, the way the console's CSV download does. The S3 log
is for a bucket called `shop-assets-example`, with presigned URLs signed by those same
example keys. The Resolver log comes as the JSON lines Resolver writes
(`route53_resolver_query_logs.json`) and as a one-hour CSV export of the same records; its
names stay under `example.com`, `example.net`, `example.org`, `corp.example.internal`, the
reserved `.example`, `.test` and `.invalid` top-level domains, and `amazonaws.com`.
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
  loader.py         delimiter, header and JSON-lines sniffing, chunked typed loading into
                    DuckDB with progress and a resumable row limit, parse warnings
  store.py          one DuckDB file and one JSON sidecar per loaded dataset under data/db/
  formats/          one plug-in per format
    base.py         Format, FormatInfo and the FormatPlugin interface
    __init__.py     the ordered registry (PLUGINS) and detect_format
    generic.py      the fallback: any delimited file, no table, no rules
    vpcflow/        VPC Flow Logs and CloudWatch Logs Insights exports
    loadbalancer/   ALB and NLB access logs
    cloudtrail/     CloudTrail event exports
    s3access/       S3 server access logs
    route53resolver/ Route 53 Resolver query logs, JSON lines and CSV
                    each with __init__.py (detector and QuerySpec), table.py (typed table),
                    findings.py (rules)
  insights/base.py  Finding, Severity and Table, and the text helpers the rules share
  insights/cwlogs.py the SQL-to-Logs-Insights translator and QuerySpec
  investigations.py pins, notes and the JSON store under data/investigations/
  sql.py            identifier and literal quoting
  dataset.py        a loaded file: connection, format, table, profile, findings, the sample
                    and the background full pass, saving to and restoring from the store
  profile.py        per-column profile and the plain-English summary
  explore.py        paginated search and filter queries
  export.py         CSV, JSON and .xlsx writers
  report.py         self-contained HTML report, for a file or an investigation
  web/              FastAPI app, Jinja2 templates, vendored HTMX and CSS
  cli.py            logsift serve | report | inspect | investigations
scripts/generate_samples.py        the fictional samples, seeded
scripts/generate_big_flow_log.py   a multi-million-row flow log on demand, seeded, never committed
samples/
tests/
```

### Adding a format

Every format is a plug-in: a sub-package under `src/logsift/formats/` with three parts
behind one small interface, `FormatPlugin` in `formats/base.py`:

- `detect(sniff)` looks at the first few hundred parsed lines and returns a `FormatInfo`
  (the kind, a label, the raw-to-canonical column mapping and a one-line reason shown in
  the UI), or `None` when the file is not in this format.
- `build_table(con, fmt)` creates the plug-in's typed table from the `raw` rows DuckDB
  loaded and returns its column names. The explorer, the profile and the exports all read
  that table.
- `findings(ds)` and `timeline(ds)` run plain SQL over that table and return `Finding`
  objects and a good-against-bad series.
- `query_spec(fmt)` (optional) returns a `QuerySpec` naming the CloudWatch field for each
  column, so every finding gets its Logs Insights query for free; leave it out for a
  format that never reaches CloudWatch.

Set `name`, `table` and `dash_means_missing` on the class, register an instance in
`PLUGINS` in `formats/__init__.py`, and that is all: `Dataset` finds the plug-in by name.
The list is ordered and the first plug-in to recognise a file owns it, so put a specific
shape before a general one. `tests/test_plugins.py` registers a toy plug-in and walks the
whole path from detection to findings in twenty lines.
See [ROADMAP.md](ROADMAP.md) for what comes next.

## License

MIT, see [LICENSE](LICENSE).
