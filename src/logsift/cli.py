"""Command line entry point: ``logsift serve`` and ``logsift report <file>``."""

from __future__ import annotations

import argparse
import os
import sys
import webbrowser
from pathlib import Path

from logsift import __version__


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from logsift.web.app import create_app

    preload = [Path(p) for p in args.paths]
    for p in preload:
        if not p.is_file():
            print(f"not a file: {p}", file=sys.stderr)
            return 2
    app = create_app(data_dir=args.data_dir, samples_dir=args.samples_dir, preload=preload)
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
    out = write_report(path, Path(args.output) if args.output else None)
    print(f"wrote {out}")
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    from logsift.dataset import Dataset

    path = Path(args.file)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2
    ds = Dataset.open(path)
    print(f"{ds.name}: {ds.format.label} ({'; '.join(ds.format.reasons)})")
    print(f"{ds.rows:,} rows, {len(ds.columns)} columns, {ds.sniff.delimiter_name}-delimited")
    for w in ds.load.warnings:
        print(f"  warning: {w}")
    print()
    for line in ds.profile.summary:
        print(f"  {line}")
    if ds.is_flow_log:
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
    serve.add_argument("--open", action="store_true", help="open the browser")
    serve.set_defaults(func=cmd_serve)

    report = sub.add_parser("report", help="write a self-contained HTML report")
    report.add_argument("file")
    report.add_argument("-o", "--output", help="output path (default: <file>.report.html)")
    report.set_defaults(func=cmd_report)

    inspect = sub.add_parser("inspect", help="print the summary and findings to the terminal")
    inspect.add_argument("file")
    inspect.add_argument("-v", "--verbose", action="store_true")
    inspect.set_defaults(func=cmd_inspect)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
