# Roadmap

Items listed under "Later" in the project brief, broken into concrete pieces. Nothing here
is started yet.

## More formats

- [ ] ALB and NLB access logs (space-delimited with quoted fields; parse the request field
      into method, URL and protocol; findings for 5xx bursts, slow targets, rejected TLS)
- [ ] CloudTrail CSV exports (event name, source, user identity, error code; findings for
      access denied bursts and console logins without MFA)
- [ ] S3 server access logs (bracketed timestamps, quoted request lines; findings for
      4xx by key prefix and anonymous access)
- [ ] Route 53 Resolver query logs (JSON lines and CSV; findings for NXDOMAIN bursts and
      one client querying many names)
- [ ] A format plug-in interface so each format ships its own detector, canonical table
      builder and rule set

## Large files

- [ ] Stream files larger than memory through DuckDB in chunks instead of one `CREATE
      TABLE AS`
- [ ] Sample the first N rows for the profile and findings, then let the user run the full
      pass on demand
- [ ] Progress reporting during load (rows read, bytes read) in the web UI and the CLI
- [ ] Persist loaded files to an on-disk DuckDB database so a restart does not reload them

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
