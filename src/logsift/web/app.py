"""FastAPI application for the local UI."""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from logsift.dataset import Dataset
from logsift.explore import MAX_EXPORT_ROWS, RowQuery, fetch_all, fetch_page
from logsift.export import (
    CONTENT_TYPES,
    findings_to_csv,
    findings_to_json,
    findings_to_xlsx,
    rows_to_csv,
    rows_to_json,
    rows_to_xlsx,
)
from logsift.web.render import make_env

STATIC_DIR = Path(__file__).parent / "static"
SAMPLE_SUFFIXES = {".csv", ".tsv", ".txt", ".log", ".gz", ".psv"}


class Registry:
    def __init__(self, data_dir: Path, samples_dir: Path | None) -> None:
        self.data_dir = data_dir
        self.samples_dir = samples_dir
        self.datasets: dict[str, Dataset] = {}

    def add(self, ds: Dataset) -> Dataset:
        self.datasets[ds.id] = ds
        return ds

    def get(self, ds_id: str) -> Dataset:
        ds = self.datasets.get(ds_id)
        if ds is None:
            raise HTTPException(404, "That file is no longer loaded.")
        return ds

    def remove(self, ds_id: str) -> None:
        ds = self.datasets.pop(ds_id, None)
        if ds is None:
            return
        ds.close()
        uploads = self.data_dir / "uploads"
        if uploads in ds.path.parents:
            ds.path.unlink(missing_ok=True)

    def samples(self) -> list[dict[str, object]]:
        if not self.samples_dir or not self.samples_dir.is_dir():
            return []
        return [
            {"name": p.name, "size": p.stat().st_size}
            for p in sorted(self.samples_dir.iterdir())
            if p.is_file() and p.suffix.lower() in SAMPLE_SUFFIXES
        ]


def create_app(
    data_dir: Path | str = "data",
    samples_dir: Path | str | None = "samples",
    preload: list[Path] | None = None,
) -> FastAPI:
    data_dir = Path(data_dir)
    (data_dir / "uploads").mkdir(parents=True, exist_ok=True)
    registry = Registry(data_dir, Path(samples_dir) if samples_dir else None)
    env = make_env()
    app = FastAPI(title="logsift", docs_url=None, redoc_url=None)
    app.state.registry = registry
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    for p in preload or []:
        registry.add(Dataset.open(p))

    def render(template: str, **ctx: object) -> HTMLResponse:
        return HTMLResponse(env.get_template(template).render(**ctx))

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> HTMLResponse:
        page = render("error.html", status=exc.status_code, detail=exc.detail)
        page.status_code = exc.status_code
        return page

    def parse_query(request: Request, ds: Dataset) -> tuple[RowQuery, dict[str, str]]:
        params = request.query_params
        rq = RowQuery(
            search=params.get("q", "").strip(),
            order_by=params.get("sort", ""),
            descending=params.get("desc", "0") == "1",
        )
        col, val = params.get("col", ""), params.get("val", "")
        if col:
            rq.filters[col] = val
        finding_id = params.get("finding", "")
        if finding_id:
            f = ds.finding(finding_id)
            if f is None:
                raise HTTPException(404, "Unknown finding.")
            rq.where = f.row_filter
        keep = {
            k: v
            for k, v in params.items()
            if k in ("q", "col", "val", "finding", "sort", "desc") and v
        }
        return rq, keep

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return render(
            "index.html",
            nav="home",
            datasets=list(registry.datasets.values()),
            samples=registry.samples(),
            data_dir=str(data_dir / "uploads"),
        )

    @app.post("/upload")
    async def upload(file: UploadFile = File(...)) -> RedirectResponse:  # noqa: B008
        name = Path(file.filename or "upload.csv").name
        target = data_dir / "uploads" / f"{uuid.uuid4().hex[:8]}_{name}"
        with target.open("wb") as fh:
            shutil.copyfileobj(file.file, fh)
        ds = registry.add(Dataset.open(target, name=name))
        return RedirectResponse(f"/d/{ds.id}", status_code=303)

    @app.post("/load-sample")
    def load_sample(name: str = Form(...)) -> RedirectResponse:  # noqa: B008
        if not registry.samples_dir:
            raise HTTPException(404, "No samples directory.")
        path = registry.samples_dir / Path(name).name
        if not path.is_file():
            raise HTTPException(404, "Unknown sample.")
        ds = registry.add(Dataset.open(path))
        return RedirectResponse(f"/d/{ds.id}", status_code=303)

    @app.post("/d/{ds_id}/close")
    def close(ds_id: str) -> RedirectResponse:
        registry.remove(ds_id)
        return RedirectResponse("/", status_code=303)

    @app.get("/d/{ds_id}", response_class=HTMLResponse)
    def overview(ds_id: str) -> HTMLResponse:
        ds = registry.get(ds_id)
        return render(
            "dataset.html",
            nav="overview",
            ds=ds,
            profile=ds.profile,
            findings=ds.findings,
            timeline=ds.timeline,
        )

    @app.get("/d/{ds_id}/explore", response_class=HTMLResponse)
    def explore(ds_id: str, request: Request, page: int = 1) -> HTMLResponse:
        ds = registry.get(ds_id)
        rq, keep = parse_query(request, ds)
        pg = fetch_page(ds.cursor(), ds.table, rq, page)
        return render(
            "explore.html",
            nav="explore",
            ds=ds,
            rq=rq,
            page=pg,
            qs=urlencode(keep),
            finding=ds.finding(keep["finding"]) if "finding" in keep else None,
            filter_col=keep.get("col", ""),
            filter_val=keep.get("val", ""),
            sort=rq.order_by,
            desc=rq.descending,
            export_limit=MAX_EXPORT_ROWS,
        )

    @app.get("/d/{ds_id}/rows", response_class=HTMLResponse)
    def rows(ds_id: str, request: Request, page: int = 1) -> HTMLResponse:
        ds = registry.get(ds_id)
        rq, keep = parse_query(request, ds)
        pg = fetch_page(ds.cursor(), ds.table, rq, page)
        return render(
            "_rows.html",
            ds=ds,
            page=pg,
            qs=urlencode(keep),
            sort=rq.order_by,
            desc=rq.descending,
            export_limit=MAX_EXPORT_ROWS,
        )

    @app.get("/d/{ds_id}/export/findings.{fmt}")
    def export_findings(ds_id: str, fmt: str) -> Response:
        ds = registry.get(ds_id)
        writer = {"csv": findings_to_csv, "json": findings_to_json, "xlsx": findings_to_xlsx}.get(
            fmt
        )
        if writer is None:
            raise HTTPException(404, "Unknown format.")
        return Response(
            writer(ds.findings),
            media_type=CONTENT_TYPES[fmt],
            headers={
                "Content-Disposition": f'attachment; filename="{Path(ds.name).stem}-findings.{fmt}"'
            },
        )

    @app.get("/d/{ds_id}/export/rows.{fmt}")
    def export_rows(ds_id: str, fmt: str, request: Request) -> Response:
        ds = registry.get(ds_id)
        writer = {"csv": rows_to_csv, "json": rows_to_json, "xlsx": rows_to_xlsx}.get(fmt)
        if writer is None:
            raise HTTPException(404, "Unknown format.")
        rq, _ = parse_query(request, ds)
        cols, data = fetch_all(ds.cursor(), ds.table, rq)
        if "row_no" in cols:
            idx = cols.index("row_no")
            cols = [c for i, c in enumerate(cols) if i != idx]
            data = [tuple(v for i, v in enumerate(r) if i != idx) for r in data]
        return Response(
            writer(cols, data),
            media_type=CONTENT_TYPES[fmt],
            headers={
                "Content-Disposition": f'attachment; filename="{Path(ds.name).stem}-rows.{fmt}"'
            },
        )

    return app
