# Roadmap

Items listed under "Later" in the project brief, broken into concrete pieces. Ticked items
are done; everything else is not started.

## More formats

- [x] ALB and NLB access logs (space-delimited with quoted fields; parse the request field
      into method, URL and protocol; findings for 5xx bursts, slow targets, rejected TLS).
      Done in `lb.py` and `insights/lblogs.py` with samples `alb_access_logs.log` and
      `nlb_access_logs.log`. Not covered yet: ALB connection logs (a separate log type
      with the TLS handshake failures that ALB access logs never record), Classic Load
      Balancer logs, and path normalisation (`/products/123` and `/products/456` count as
      two paths in the slow-path tables)
- [x] CloudTrail CSV exports (event name, source, user identity, error code; findings for
      access denied bursts and console logins without MFA). Done in `trail.py` and
      `insights/cloudtrail.py` with the sample `cloudtrail_events.csv`, plus root activity
      and rarely used regions. Not covered yet: the JSON download and raw trail files
      from S3 (gzipped JSON with a `Records` array), data events such as S3 object reads,
      failed console sign-in bursts as their own finding, and a baseline of "normal"
      regions and addresses learned from a longer file rather than from the file itself
- [x] S3 server access logs (bracketed timestamps, quoted request lines; findings for
      4xx by key prefix and anonymous access). Done in `formats/s3access/` with the sample
      `s3_access_logs.log`, plus refused principals, delete bursts and a usage overview.
      Not covered yet: telling CloudFront origin requests from other callers, access
      point and website endpoint specifics (the columns are kept, no rules use them),
      isolating the hot key prefix behind 503 SlowDown, and bytes per prefix over time
- [x] Route 53 Resolver query logs (JSON lines and CSV; findings for NXDOMAIN bursts and
      one client querying many names). Done in `formats/route53resolver/` with the samples
      `route53_resolver_query_logs.json` and `.csv`, plus DNS Firewall blocks, possible
      tunnelling, SERVFAIL runs and an error overview; the loader learned JSON lines for
      it. Not covered yet: the Firehose and S3 deliveries that gzip several records per
      object with no newline between them, telling a resolver or proxy host (which
      legitimately asks for many names) from an enumerating one by anything but the
      number of names, DNS Firewall ALERT and OVERRIDE actions as their own finding, and
      a `search path` heuristic (NXDOMAIN for `name.corp.example.internal` right before
      NOERROR for `name.example.com` is a client appending suffixes, not malware)
- [x] A format plug-in interface so each format ships its own detector, canonical table
      builder and rule set. `FormatPlugin` in `formats/base.py`, one sub-package per
      format, an ordered registry in `formats/__init__.py`. Not covered yet: discovering
      plug-ins from other packages through entry points, and letting a plug-in add its
      own template fragments to the overview page

## Large files

- [x] Stream files larger than memory through DuckDB in chunks instead of one `CREATE
      TABLE AS`. `loader.py` infers types from the first chunk and streams 16 MiB chunks of
      whole lines (staged in a temp file, gzip included) straight into the typed table.
      Not covered yet: a `memory_limit` for DuckDB's own query memory (the defaults spill
      to the database's temp directory), cancelling a pass that is under way, and reading
      several files into one dataset
- [x] Sample the first N rows for the profile and findings, then let the user run the full
      pass on demand. 250,000 rows by default in the web UI (`--sample-rows`), `--sample N`
      on the CLI, the full pass resumes from the byte offset the sample stopped at. Not
      covered yet: a random sample rather than the head of the file, and findings that say
      how much the sample can be trusted (a port sweep at 10:00 is invisible in the first
      hour)
- [x] Progress reporting during load (rows read, bytes read) in the web UI and the CLI.
      The overview polls a progress panel every second during the full pass; the CLI
      rewrites a line on a terminal and prints one every two seconds on a pipe. Not
      covered yet: progress for the browser upload itself, and for the first (sample)
      load, which is short by construction and still blocks the request
- [x] Persist loaded files to an on-disk DuckDB database so a restart does not reload
      them. `store.py` keeps `data/db/<id>.duckdb` and a JSON sidecar per dataset; the
      server restores them on start and skips a preload it already holds. Not covered yet:
      caching the profile and findings themselves (they are recomputed on first view
      after a restart), compacting the database file after the full pass, showing disk
      use per dataset on the home page, and a sidecar format version bump path beyond
      "drop and reload"

## Saved investigations

- [x] Pin findings and individual rows to an investigation. Pin buttons on every finding
      card and every row in the explorer, a picker for which investigation receives pins.
      Not covered yet: pinning a row of a generic file (its table has no row numbers), a
      pin that remembers the search or filter it came from, and pinning a whole filtered
      view rather than one row at a time
- [x] Add free-text notes to pinned items, and to the investigation itself
- [x] Save investigations locally (JSON under `data/investigations/`, one file each,
      written atomically). Not covered yet: refreshing a pinned finding from a reloaded
      file (a pin is a snapshot on purpose), and a version bump path for the JSON beyond
      "unreadable files are skipped"
- [x] Export an investigation as a self-contained HTML report, from the page and with
      `logsift report --investigation`. Not covered yet: a PDF, and exporting the pinned
      rows as CSV or .xlsx

## CloudWatch Logs Insights query box

- [x] Turn a finding into the matching Logs Insights query (rejected cluster, asymmetric
      pair, port sweep, top talker) with the right field names for the log group's format.
      Done for every finding of every format by translating the finding's row filter
      (`insights/cwlogs.py`) with a per-format `QuerySpec`. Not covered yet: running the
      queries against a real log group (they follow the documented field names and the
      Logs Insights syntax guide, nothing more), the `tcp_flags` bit tests beyond the
      SYN-only case, an Athena SQL variant for the formats that live in S3 (ALB, NLB, S3
      access logs), and the CloudTrail `principal` for AWS service principals
- [x] Copy-to-clipboard button (the clipboard API, falling back to selecting the text)
- [ ] A deep link that pre-fills the CloudWatch console with the query, the log group and
      the time range

## Diffing two files: the cutover validator

- [x] Load a "before" and an "after" file side by side. `logsift diff`, the "Compare two
      files" form on the home page, and `/diff/{before}/{after}`; the two files are cut to
      the same number of minutes from each one's first record. Not covered yet: choosing
      the windows by hand (compare 09:00-10:00 of each rather than the first N minutes),
      more than two files (a baseline of several days against today), and a diff against
      a saved baseline rather than a second file
- [x] Diff the findings to confirm a NACL or security group change did what it should.
      Done as per-format cutover checks with a verdict each (clean, review, regression) and
      evidence rows: flow logs (new rejected traffic, lost return paths, traffic that
      disappeared, new talkers), ALB and NLB (5xx per target and path, handshakes,
      targets gone or new, p95), Resolver (new failures, new blocks, names gone, new
      clients) and CloudTrail (new denials, errors per service, principals, regions). Not
      covered yet: S3 access logs, a "resolved" list (problems in the before file that the
      after file no longer has, shown as improvements rather than only as clean checks),
      and thresholds a user can tune per check
- [ ] Diff the profiles (new columns, changed types, shifted distributions), for files of
      any format including generic CSV

## Next

Concrete next items, roughly sized; about thirty-four hours in all, a working week.

- [ ] **NAT and data-transfer cost estimator from flow logs** (6 h). From a custom-format
      flow log with `pkt-srcaddr`, `pkt-dstaddr`, `traffic-path`, `az-id` and
      `flow-direction`: bytes through a NAT gateway (flows whose packet address differs
      from the flow address on the NAT's ENI, or `traffic-path` through an internet
      gateway from a private subnet), cross-AZ bytes (source and destination in different
      `az-id`s), internet egress (`traffic-path` 2 or 8, egress direction) and bytes to
      gateway and interface endpoints (`traffic-path` 3 and 7). Multiply by per-GB prices
      the user supplies in a small config (no built-in price list, prices change and
      differ by region), and show the top talkers behind each bucket so the finding is
      "10.0.1.12 pushes 40 GB a day through the NAT to an S3 endpoint it could reach via a
      gateway endpoint for nothing". Needs the sample generator to plant a NAT ENI and a
      cross-AZ pair, and a `logsift cost` command plus a card on the flow overview.
- [ ] **Hand-picked windows for the diff** (2 h). `--before-window` and `--after-window`
      as `start/end` pairs, and two time pickers on the diff page, so a known deploy
      moment can be compared against the same hour the day before instead of the first N
      minutes of each file.
- [ ] **Resolved problems in the cutover report** (2 h). Checks that fired in the before
      file and not in the after file listed as improvements, so a diff run after a fix
      reads as "fixed" rather than "clean".
- [ ] **S3 access log cutover checks** (2 h). Errors per prefix, principals newly refused,
      prefixes whose traffic disappeared, new clients.
- [ ] **CloudWatch console deep link** (2 h). A link from each finding's query that opens
      the Logs Insights console with the query, log group and time range filled in; the
      log group name comes from a per-dataset setting, the region from the file where it
      has one.
- [ ] **Athena variants of the queries** (3 h). For the formats that live in S3 (ALB,
      NLB, S3 access logs, flow logs delivered to S3): the same finding as a SQL query
      over the documented Athena table layout, next to the Logs Insights one.
- [ ] **Random sample instead of the head** (3 h). The first N rows of a file are the
      first N minutes; a reservoir sample across the file would make the quick look
      representative, at the cost of a full read. Offer it as an option on the first
      load, keep the head sample as the default because it is fast.
- [ ] **Profile diff for any format** (3 h). New and missing columns, changed inferred
      types, and shifted distributions (a column whose top values changed) between two
      files, as a section of the cutover report that works for generic CSV too.
- [ ] **Cached findings on disk** (2 h). Store the profile, findings and timeline in the
      dataset's sidecar after they are computed, invalidated by the row count, so a
      restart or a second visit does not recompute them for a large file.
- [ ] **Multi-file datasets** (4 h). Load a directory or a glob as one dataset (a day of
      hourly flow log files), streaming each file through the same chunked loader and
      recording which file each row came from.
- [ ] **Memory limit and cancellation** (2 h). A `--memory-limit` passed to DuckDB and a
      Cancel button on the progress panel that stops the full pass between chunks.
- [ ] **PyPI release and a single-file build** (3 h). Publish so `pipx install logsift`
      works, and a shiv or PyApp build for machines without Python.

## Packaging

- [ ] Publish to PyPI so `pipx install logsift` works
- [ ] A single-file build (for example with PyApp or shiv) for machines without Python
- [ ] A `--version` check that reports whether a newer release exists, opt-in only
