"""FastAPI application for the local UI."""

from __future__ import annotations

import shutil
import uuid
from pathlib import Path
from urllib.parse import urlencode

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from logsift.dataset import SAMPLE_ROWS, Dataset
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
from logsift.investigations import Investigation, InvestigationStore, Pin
from logsift.report import render_investigation
from logsift.store import Store
from logsift.web.render import make_env

STATIC_DIR = Path(__file__).parent / "static"
SAMPLE_SUFFIXES = {".csv", ".tsv", ".txt", ".log", ".gz", ".psv"}


class Registry:
    """The loaded files, backed by an on-disk store so a restart brings them back."""

    def __init__(self, data_dir: Path, samples_dir: Path | None, sample_rows: int) -> None:
        self.data_dir = data_dir
        self.samples_dir = samples_dir
        self.sample_rows = sample_rows
        self.store = Store(data_dir / "db")
        self.datasets: dict[str, Dataset] = {}
        for ds in Dataset.restore_all(self.store):
            self.datasets[ds.id] = ds
        self.investigations = InvestigationStore(data_dir / "investigations")
        # Pins go to the active investigation; the most recently changed one until chosen.
        self.active_id: str | None = None

    def active(self) -> Investigation | None:
        if self.active_id:
            inv = self.investigations.get(self.active_id)
            if inv is not None:
                return inv
            self.active_id = None
        found = self.investigations.list()
        if found:
            self.active_id = found[0].id
            return found[0]
        return None

    def investigation(self, inv_id: str) -> Investigation:
        inv = self.investigations.get(inv_id)
        if inv is None:
            raise HTTPException(404, "No such investigation.")
        return inv

    def open(self, path: Path, name: str | None = None) -> Dataset:
        """Load the first ``sample_rows`` rows of a file and keep it."""
        ds = Dataset.open(path, name=name, store=self.store, limit=self.sample_rows)
        self.datasets[ds.id] = ds
        return ds

    def holds(self, path: Path) -> bool:
        """True when a dataset was already loaded from this very file."""
        try:
            size = path.stat().st_size
        except OSError:
            return False
        return any(
            ds.path.resolve() == path.resolve() and ds.size_bytes == size
            for ds in self.datasets.values()
        )

    def get(self, ds_id: str) -> Dataset:
        ds = self.datasets.get(ds_id)
        if ds is None:
            raise HTTPException(404, "That file is no longer loaded.")
        return ds

    def remove(self, ds_id: str) -> None:
        ds = self.datasets.get(ds_id)
        if ds is None:
            return
        if ds.loading:
            raise HTTPException(409, "That file is still loading. Wait for it to finish first.")
        del self.datasets[ds_id]
        ds.close()
        self.store.remove(ds_id)
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
    sample_rows: int = SAMPLE_ROWS,
) -> FastAPI:
    """The application. ``sample_rows`` is how much of a file loads before the first look."""
    data_dir = Path(data_dir)
    (data_dir / "uploads").mkdir(parents=True, exist_ok=True)
    registry = Registry(data_dir, Path(samples_dir) if samples_dir else None, sample_rows)
    env = make_env()
    app = FastAPI(title="logsift", docs_url=None, redoc_url=None)
    app.state.registry = registry
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    for p in preload or []:
        if not registry.holds(p):  # restored from the store already
            registry.open(p)

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
            store_dir=str(registry.store.root),
        )

    @app.post("/upload")
    async def upload(file: UploadFile = File(...)) -> RedirectResponse:  # noqa: B008
        name = Path(file.filename or "upload.csv").name
        target = data_dir / "uploads" / f"{uuid.uuid4().hex[:8]}_{name}"
        with target.open("wb") as fh:
            shutil.copyfileobj(file.file, fh)
        ds = registry.open(target, name=name)
        return RedirectResponse(f"/d/{ds.id}", status_code=303)

    @app.post("/load-sample")
    def load_sample(name: str = Form(...)) -> RedirectResponse:  # noqa: B008
        if not registry.samples_dir:
            raise HTTPException(404, "No samples directory.")
        path = registry.samples_dir / Path(name).name
        if not path.is_file():
            raise HTTPException(404, "Unknown sample.")
        ds = registry.open(path)
        return RedirectResponse(f"/d/{ds.id}", status_code=303)

    @app.post("/d/{ds_id}/close")
    def close(ds_id: str) -> RedirectResponse:
        registry.remove(ds_id)
        return RedirectResponse("/", status_code=303)

    @app.post("/d/{ds_id}/full")
    def full_pass(ds_id: str) -> RedirectResponse:
        """Load the rest of a sampled file in the background; the overview shows progress."""
        ds = registry.get(ds_id)
        if ds.is_sample and not ds.loading and not ds.source_available:
            raise HTTPException(409, "The original file is gone, so the rest cannot be loaded.")
        ds.start_full_pass()
        return RedirectResponse(f"/d/{ds.id}", status_code=303)

    @app.get("/d/{ds_id}/progress", response_class=HTMLResponse)
    def progress(ds_id: str) -> HTMLResponse:
        """The progress panel the overview polls; once the pass is done it reloads the page."""
        ds = registry.get(ds_id)
        page = render("_progress.html", ds=ds)
        if not ds.loading:
            page.headers["HX-Refresh"] = "true"
        return page

    def pin_context(ds: Dataset, next_url: str) -> dict[str, object]:
        active = registry.active()
        return {
            "active": active,
            "investigations": registry.investigations.list(),
            "pinned_findings": active.pinned_findings(ds.id) if active else set(),
            "pinned_rows": active.pinned_rows(ds.id) if active else set(),
            "next_url": next_url,
        }

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
            **pin_context(ds, f"/d/{ds.id}"),
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
            **pin_context(ds, f"/d/{ds.id}/explore?{urlencode(keep)}"),
        )

    @app.get("/d/{ds_id}/rows", response_class=HTMLResponse)
    def rows(ds_id: str, request: Request, page: int = 1) -> HTMLResponse:
        ds = registry.get(ds_id)
        rq, keep = parse_query(request, ds)
        pg = fetch_page(ds.cursor(), ds.table, rq, page)
        return render(
            "_rows.html",
            ds=ds,
            pinning=True,
            page=pg,
            qs=urlencode(keep),
            sort=rq.order_by,
            desc=rq.descending,
            export_limit=MAX_EXPORT_ROWS,
            **pin_context(ds, f"/d/{ds.id}/explore?{urlencode(keep)}"),
        )

    # ------------------------------------------------------------ investigations

    def back(request: Request, fallback: str) -> RedirectResponse:
        target = request.headers.get("referer") or fallback
        return RedirectResponse(target, status_code=303)

    @app.get("/investigations", response_class=HTMLResponse)
    def investigations() -> HTMLResponse:
        return render(
            "investigations.html",
            nav="investigations",
            investigations=registry.investigations.list(),
            active=registry.active(),
            store_dir=str(registry.investigations.root),
        )

    @app.post("/investigations")
    def create_investigation(
        request: Request, name: str = Form(""), next: str = Form("")
    ) -> RedirectResponse:
        inv = registry.investigations.create(name)
        registry.active_id = inv.id
        return RedirectResponse(next or f"/investigations/{inv.id}", status_code=303)

    @app.post("/investigations/active")
    def choose_investigation(inv: str = Form(...), next: str = Form("/")) -> RedirectResponse:
        registry.investigation(inv)
        registry.active_id = inv
        return RedirectResponse(next or "/", status_code=303)

    @app.get("/investigations/{inv_id}", response_class=HTMLResponse)
    def investigation(inv_id: str) -> HTMLResponse:
        inv = registry.investigation(inv_id)
        return render(
            "investigation.html",
            nav="investigations",
            inv=inv,
            groups=inv.by_dataset(),
            loaded={ds_id for ds_id in registry.datasets},
            active=registry.active(),
        )

    @app.get("/investigations/{inv_id}/report.html")
    def investigation_report(inv_id: str) -> Response:
        inv = registry.investigation(inv_id)
        safe = "".join(c if c.isalnum() or c in "-_ " else "_" for c in inv.name).strip() or inv.id
        return Response(
            render_investigation(inv),
            media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{safe}.investigation.html"'},
        )

    @app.post("/investigations/{inv_id}/rename")
    def rename_investigation(inv_id: str, name: str = Form(...)) -> RedirectResponse:
        inv = registry.investigation(inv_id)
        inv.name = name.strip() or inv.name
        inv.touch()
        registry.investigations.save(inv)
        return RedirectResponse(f"/investigations/{inv.id}", status_code=303)

    @app.post("/investigations/{inv_id}/notes")
    def investigation_notes(inv_id: str, notes: str = Form("")) -> RedirectResponse:
        inv = registry.investigation(inv_id)
        inv.notes = notes.strip()
        inv.touch()
        registry.investigations.save(inv)
        return RedirectResponse(f"/investigations/{inv.id}#notes", status_code=303)

    @app.post("/investigations/{inv_id}/delete")
    def delete_investigation(inv_id: str) -> RedirectResponse:
        registry.investigation(inv_id)
        registry.investigations.delete(inv_id)
        if registry.active_id == inv_id:
            registry.active_id = None
        return RedirectResponse("/investigations", status_code=303)

    @app.post("/investigations/{inv_id}/pins/{pin_id}/note")
    def pin_note(inv_id: str, pin_id: str, note: str = Form("")) -> RedirectResponse:
        inv = registry.investigation(inv_id)
        pin = inv.pin(pin_id)
        if pin is None:
            raise HTTPException(404, "No such pin.")
        pin.note = note.strip()
        inv.touch()
        registry.investigations.save(inv)
        return RedirectResponse(f"/investigations/{inv.id}#pin-{pin.id}", status_code=303)

    @app.post("/investigations/{inv_id}/pins/{pin_id}/remove")
    def pin_remove(inv_id: str, pin_id: str) -> RedirectResponse:
        inv = registry.investigation(inv_id)
        if not inv.remove(pin_id):
            raise HTTPException(404, "No such pin.")
        registry.investigations.save(inv)
        return RedirectResponse(f"/investigations/{inv.id}", status_code=303)

    @app.post("/d/{ds_id}/pin", response_class=HTMLResponse)
    def pin(
        ds_id: str,
        request: Request,
        kind: str = Form(...),
        finding: str = Form(""),
        row_no: int | None = Form(None),
    ) -> Response:
        """Pin a finding or a row to the active investigation, creating one if none exists."""
        ds = registry.get(ds_id)
        inv = registry.active()
        if inv is None:
            inv = registry.investigations.create(f"Investigation: {ds.name}")
            registry.active_id = inv.id
        if kind == "finding":
            f = ds.finding(finding)
            if f is None:
                raise HTTPException(404, "Unknown finding.")
            new_pin = Pin.of_finding(ds, f)
        elif kind == "row" and row_no is not None:
            maybe = Pin.of_row(ds, row_no)
            if maybe is None:
                raise HTTPException(404, "No such row.")
            new_pin = maybe
        else:
            raise HTTPException(400, "Pin a finding or a row.")
        pinned = inv.add(new_pin)
        registry.investigations.save(inv)
        if request.headers.get("hx-request"):
            return render("_pinned.html", inv=inv, pin=pinned)
        return back(request, f"/d/{ds.id}")

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
