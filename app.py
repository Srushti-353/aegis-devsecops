from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from config import AEGIS_BIGQUERY_DATASET, AEGIS_GCP_PROJECT, get_default_finding, get_port, is_demo_mode
from logging_config import LOGGER, log_event
from ui_service import get_dashboard_case

ROOT = Path(__file__).resolve().parent
app = FastAPI(title="AEGIS", version="1.0.0")

app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")

templates = Jinja2Templates(directory=str(ROOT / "templates"))


def _check_bigquery_readiness() -> bool:
    if is_demo_mode():
        return False
    try:
        from google.auth import default

        credentials, project_id = default()
        if credentials is None or not project_id:
            return False

        import bigquery_tools

        client = bigquery_tools.get_bigquery_client()
        if client is None:
            return False
        return True
    except Exception:
        return False


def _dashboard_banner() -> str:
    if is_demo_mode() or not _check_bigquery_readiness():
        return "Demo fallback: using canonical local evidence"
    return "Evidence source: BigQuery"


@app.get("/health")
def health() -> dict[str, str]:
    log_event("AEGIS_STARTUP", env=os.getenv("AEGIS_ENV", "development"), port=get_port())
    return {"status": "ok", "service": "AEGIS"}


@app.get("/ready")
def ready() -> dict[str, str]:
    available = _check_bigquery_readiness()
    if available:
        log_event("BIGQUERY_READY", project=AEGIS_GCP_PROJECT, dataset=AEGIS_BIGQUERY_DATASET)
        return {"status": "ready", "bigquery": "reachable", "dataset": AEGIS_BIGQUERY_DATASET}
    log_event("BIGQUERY_UNAVAILABLE", demo_mode=str(is_demo_mode()).lower())
    return JSONResponse(status_code=503, content={"status": "not_ready", "bigquery": "unreachable"})


@app.get("/api/case/{finding_id}")
def api_case(finding_id: str) -> dict:
    try:
        log_event("CASE_REQUESTED", finding_id=finding_id)
        case = get_dashboard_case(finding_id)
        log_event("CASE_LOADED", finding_id=finding_id)
        return case
    except LookupError as exc:
        log_event("CASE_NOT_FOUND", finding_id=finding_id)
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        log_event("API_ERROR", finding_id=finding_id, error=str(exc))
        raise HTTPException(status_code=500, detail=f"Unable to load case data: {exc}") from exc


@app.get("/", response_class=HTMLResponse)
def dashboard_page(request: Request) -> HTMLResponse:
    finding_id = get_default_finding()
    log_event("CASE_REQUESTED", finding_id=finding_id)
    case = get_dashboard_case(finding_id)
    log_event("CASE_LOADED", finding_id=finding_id)
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "case": case, "banner": _dashboard_banner()},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=get_port(), reload=False)
