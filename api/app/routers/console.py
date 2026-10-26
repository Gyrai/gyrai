"""Server-rendered admin console. Deliberately simple (Jinja + one CSS file) so it
runs in air-gapped environments with no build step. Swap for React when a customer
asks for it; every page reads only the /api/v1 endpoints."""
from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import AISystem, AuditEvent, get_db
from ..evidence import build_report, report_markdown
from .events import stats as stats_endpoint

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))


def _ctx(request: Request, **kw):
    return {"request": request, "product": settings.product_name, "org": settings.org_name, **kw}


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    s = stats_endpoint(db)
    systems = db.scalars(select(AISystem)).all()
    recent_dlp = db.scalars(
        select(AuditEvent).where(AuditEvent.dlp_hit.is_(True)).order_by(AuditEvent.seq.desc()).limit(10)
    ).all()
    return templates.TemplateResponse(request, "dashboard.html", _ctx(request, stats=s, systems=systems,
        unapproved=[x for x in systems if not x.approved],
        recent_dlp=[r.body for r in recent_dlp],
    ))


@router.get("/inventory", response_class=HTMLResponse)
def inventory(request: Request, db: Session = Depends(get_db)):
    systems = db.scalars(select(AISystem).order_by(AISystem.event_count.desc())).all()
    return templates.TemplateResponse(request, "inventory.html", _ctx(request, systems=systems))


@router.get("/events", response_class=HTMLResponse)
def events_page(request: Request, db: Session = Depends(get_db), ai_system: str | None = None, dlp: int = 0):
    q = select(AuditEvent).order_by(AuditEvent.seq.desc())
    if ai_system:
        q = q.where(AuditEvent.ai_system == ai_system)
    if dlp:
        q = q.where(AuditEvent.dlp_hit.is_(True))
    rows = db.scalars(q.limit(200)).all()
    return templates.TemplateResponse(request, "events.html", _ctx(request, events=[r.body for r in rows], ai_system=ai_system, dlp=dlp))


@router.get("/evidence", response_class=HTMLResponse)
def evidence_page(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse(request, "evidence.html", _ctx(request, report=build_report(db)))


@router.get("/evidence/report.md", response_class=PlainTextResponse)
def evidence_md(db: Session = Depends(get_db)):
    return report_markdown(build_report(db))


@router.get("/evidence/report.json")
def evidence_json(db: Session = Depends(get_db)):
    return build_report(db)
