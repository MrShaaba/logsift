"""Command line entry point: ``logsift serve`` and ``logsift report <file>``."""

from __future__ import annotations

import argparse
import os
import sys
import time
import webbrowser
from pathlib import Path
from typing import IO

from logsift import __version__
from logsift.dataset import SAMPLE_ROWS
from logsift.insights.base import fmt_bytes
from logsift.loader import LoadProgress


class ProgressPrinter:
    """Load progress on stderr.

    On a terminal one line rewrites itself after every chunk and is wiped at the end. When
    stderr is a pipe a line is printed every couple of seconds instead, so a quick load
    prints nothing at all.
    """

    def __init__(self, stream: IO[str] | None = None, every: float = 2.0) -> None:
        self.stream = stream or sys.stderr
        self.tty = self.stream.isatty()
        self.every = every
        self.last = time.monotonic()
        self.shown = False

    def __call__(self, p: LoadProgress) -> None:
        now = time.monotonic()
        if not self.tty and now - self.last < self.every:
            return
        self.last = now
        if p.phase == "building":
            text = f"building the table, {p.rows:,} rows loaded"
        else:
            text = (
                f"{p.rows:,} rows, {fmt_bytes(p.bytes_read)} of {fmt_bytes(p.total_bytes)} "
                f"({p.fraction:.0%})"
            )
        if self.tty:
            self.stream.write("\r\x1b[2K" + text)
            self.shown = True
        else:
            self.stream.write(text + "\n")
        self.stream.flush()

    def done(self) -> None:
        if self.tty and self.shown:
            self.stream.write("\r\x1b[2K")
            self.stream.flush()
            self.shown = False


def sample_note(ds: object) -> str:
    rows = getattr(ds, "rows", 0)
    share = getattr(ds, "fraction_loaded", 0.0)
    return (
        f"Sampled the first {rows:,} rows, about {share:.0%} of the file; the summary and "
        "findings cover only these rows."
    )


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from logsift.web.app import create_app

    preload = [Path(p) for p in args.paths]
    for p in preload:
        if not p.is_file():
            print(f"not a file: {p}", file=sys.stderr)
            return 2
    app = create_app(
        data_dir=args.data_dir,
        samples_dir=args.samples_dir,
        preload=preload,
        sample_rows=args.sample_rows,
    )
    url = f"http://{args.host}:{args.port}"
    print(f"logsift {__version__} serving at {url} (Ctrl+C to stop)")
    if args.open:
        webbrowser.open(url)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from logsift.report import write_report

    path = Path(args.file)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2
    printer = ProgressPrinter()
    out = write_report(
        path, Path(args.output) if args.output else None, limit=args.sample, progress=printer
    )
    printer.done()
    print(f"wrote {out}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    from logsift.dataset import Dataset

    path = Path(args.file)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2
    printer = ProgressPrinter()
    ds = Dataset.open(path, limit=args.sample, progress=printer)
    printer.done()
    print(f"{ds.name}: {ds.format.label} ({'; '.join(ds.format.reasons)})")
    print(f"{ds.rows:,} rows, {len(ds.columns)} columns, {ds.sniff.delimiter_name}-delimited")
    if ds.is_sample:
        print(f"  {sample_note(ds)}")
    for w in ds.load.warnings:
        print(f"  warning: {w}")
    print()
    for line in ds.profile.summary:
        print(f"  {line}")
    if ds.has_rules:
        print()
        for f in ds.findings:
            print(f"  [{f.severity.upper():6s}] {f.title}")
            if args.verbose:
                print(f"           {f.summary}")
                if f.likely_cause:
                    print(f"           Likely cause: {f.likely_cause}")
    ds.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsift", description="Drop in a CSV or log file and understand it right away."
    )
    parser.add_argument("--version", action="version", version=f"logsift {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="start the local web UI")
    serve.add_argument("paths", nargs="*", help="files to load on start")
    serve.add_argument("--host", default=os.environ.get("LOGSIFT_HOST", "127.0.0.1"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("LOGSIFT_PORT", "8000")))
    serve.add_argument("--data-dir", default=os.environ.get("LOGSIFT_DATA_DIR", "data"))
    serve.add_argument("--samples-dir", default="samples")
    serve.add_argument(
        "--sample-rows",
        type=int,
        default=int(os.environ.get("LOGSIFT_SAMPLE_ROWS", str(SAMPLE_ROWS))),
        help="rows to load before the first look at a file (default %(default)s)",
    )
    serve.add_argument("--open", action="store_true", help="open the browser")
    serve.set_defaults(func=cmd_serve)

    sample_help = "only read the first N rows (default: the whole file)"
    report = sub.add_parser("report", help="write a self-contained HTML report")
    report.add_argument("file")
    report.add_argument("-o", "--output", help="output path (default: <file>.report.html)")
    report.add_argument("--sample", type=int, metavar="N", help=sample_help)
    report.set_defaults(func=cmd_report)

    inspect = sub.add_parser("inspect", help="print the summary and findings to the terminal")
    inspect.add_argument("file")
    inspect.add_argument("-v", "--verbose", action="store_true")
    inspect.add_argument("--sample", type=int, metavar="N", help=sample_help)
    inspect.set_defaults(func=cmd_inspect)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
