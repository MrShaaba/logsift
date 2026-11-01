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
- [ ] Route 53 Resolver query logs (JSON lines and CSV; findings for NXDOMAIN bursts and
      one client querying many names)
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

- [ ] Pin findings and individual rows to an investigation
- [ ] Add free-text notes to pinned items
- [ ] Save investigations locally (SQLite or JSON under `data/`)
- [ ] Export an investigation as a self-contained HTML report, reusing `logsift report`

## CloudWatch Logs Insights query box

- [ ] Turn a finding into the matching Logs Insights query (rejected cluster, asymmetric
      pair, port sweep, top talker) with the right field names for the log group's format
- [ ] Copy-to-clipboard button and a deep link that pre-fills the CloudWatch console

## Diffing two files

- [ ] Load a "before" and an "after" file side by side
- [ ] Diff the profiles (new columns, changed types, shifted distributions)
- [ ] Diff the findings (resolved, new, changed counts) to confirm a NACL or security group
      change did what it should

## Packaging

- [ ] Publish to PyPI so `pipx install logsift` works
- [ ] A single-file build (for example with PyApp or shiv) for machines without Python
- [ ] A `--version` check that reports whether a newer release exists, opt-in only
