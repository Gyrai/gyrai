"""Server-rendered admin console. Deliberately simple (Jinja + one CSS file) so it
runs in air-gapped environments with no build step. Swap for React when a customer
asks for it; every page reads only the /api/v1 endpoints."""
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_user_page
from ..config import settings
from ..db import AISystem, AuditEvent, User, get_db
from ..evidence import build_report, report_markdown
from .events import stats as stats_endpoint
from .inventory import apply_update, create_declared

router = APIRouter(include_in_schema=False, dependencies=[Depends(require_user_page)])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))


def _ctx(request: Request, **kw):
    """Template variables for every console page. Looks up the current user itself so a page
    can show the name and role; imports are local to avoid a circular import at load time."""
    from ..auth import current_user
    from ..db import SessionLocal
    db = SessionLocal()
    try:
        user = current_user(request, db)
    finally:
        db.close()
    return {"request": request, "product": settings.product_name, "org": settings.org_name, "user": user, **kw}


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    """Home page: headline counts, the AI inventory, unapproved systems and recent flagged events."""
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
    """The AI inventory table, busiest systems first."""
    systems = db.scalars(select(AISystem).order_by(AISystem.event_count.desc())).all()
    return templates.TemplateResponse(request, "inventory.html", _ctx(request, systems=systems))


@router.get("/events", response_class=HTMLResponse)
def events_page(request: Request, db: Session = Depends(get_db), ai_system: str | None = None, dlp: int = 0):
    """Latest 200 audit events, newest first, optionally filtered by system or flagged content."""
    # Build the query step by step: newest first, then add whichever filters were chosen.
    q = select(AuditEvent).order_by(AuditEvent.seq.desc())
    if ai_system:
        q = q.where(AuditEvent.ai_system == ai_system)
    if dlp:
        q = q.where(AuditEvent.dlp_hit.is_(True))
    rows = db.scalars(q.limit(200)).all()
    return templates.TemplateResponse(request, "events.html", _ctx(request, events=[r.body for r in rows], ai_system=ai_system, dlp=dlp))


@router.get("/evidence", response_class=HTMLResponse)
def evidence_page(request: Request, db: Session = Depends(get_db)):
    """The evidence report as an HTML page."""
    return templates.TemplateResponse(request, "evidence.html", _ctx(request, report=build_report(db)))


@router.get("/evidence/report.md", response_class=PlainTextResponse)
def evidence_md(db: Session = Depends(get_db)):
    """The same report as downloadable Markdown."""
    return report_markdown(build_report(db))


@router.get("/evidence/report.json")
def evidence_json(db: Session = Depends(get_db)):
    """The same report as JSON, for other tools."""
    return build_report(db)


# ---------- inventory editing (HTML forms) ----------

def _tri(v: str) -> bool | None:
    """Convert a yes/no/unknown form choice to True/False/None (None means "not decided yet")."""
    return {"yes": True, "no": False}.get(v)


@router.get("/inventory/new", response_class=HTMLResponse)
def declare_form(request: Request, user: User = Depends(require_user_page)):
    return templates.TemplateResponse(request, "system_edit.html", _ctx(request, system=None, error=None, can_edit=user.role == "admin"))


@router.post("/inventory/new")
def declare_submit(request: Request, key: str = Form(...), display_name: str = Form(""), vendor: str = Form(""),
                   hosting: str = Form("unknown"), approved: str = Form("unknown"), cui_in_scope: str = Form("unknown"),
                   owner: str = Form(""), notes: str = Form(""), user: User = Depends(require_user_page), db: Session = Depends(get_db)):
    """Register an AI tool by hand (state "declared"). Admins only. Keys are lower-cased and must be unique."""
    if user.role != "admin":
        raise HTTPException(403, "admin role required")
    key = key.strip().lower()
    if db.get(AISystem, key):
        ctx = _ctx(request, system=None, error=f"'{key}' already exists.", can_edit=True)
        return templates.TemplateResponse(request, "system_edit.html", ctx, status_code=409)
    create_declared(db, {"key": key, "display_name": display_name.strip() or key, "vendor": vendor.strip() or None, "hosting": hosting,
                         "approved": _tri(approved), "cui_in_scope": _tri(cui_in_scope), "owner": owner.strip() or None,
                         "notes": notes.strip() or None}, user.username)
    return RedirectResponse(f"/inventory/{key}", status_code=303)


@router.get("/inventory/{key}", response_class=HTMLResponse)
def system_page(key: str, request: Request, user: User = Depends(require_user_page), db: Session = Depends(get_db)):
    """One system: its details, recent events and the history of changes people made to it.
    Viewers can see the page; only admins can save edits."""
    s = db.get(AISystem, key)
    if not s:
        raise HTTPException(404, "unknown system")
    recent = db.scalars(select(AuditEvent).where(AuditEvent.ai_system == key).order_by(AuditEvent.seq.desc()).limit(20)).all()
    changes = db.scalars(select(AuditEvent).where(AuditEvent.ai_system == key, AuditEvent.event_type == "ai.admin.change")
                         .order_by(AuditEvent.seq.desc()).limit(10)).all()
    return templates.TemplateResponse(request, "system_edit.html", _ctx(
        request, system=s, error=None, can_edit=user.role == "admin",
        recent=[r.body for r in recent], changes=[r.body for r in changes]))


@router.post("/inventory/{key}")
def system_submit(key: str, request: Request, display_name: str = Form(""), vendor: str = Form(""), hosting: str = Form("unknown"),
                  approved: str = Form("unknown"), cui_in_scope: str = Form("unknown"), owner: str = Form(""), notes: str = Form(""),
                  user: User = Depends(require_user_page), db: Session = Depends(get_db)):
    """Save edits to an inventory entry. Admins only. Each real change is audited."""
    if user.role != "admin":
        raise HTTPException(403, "admin role required")
    s = db.get(AISystem, key)
    if not s:
        raise HTTPException(404, "unknown system")
    apply_update(db, s, {"display_name": display_name.strip() or s.key, "vendor": vendor.strip() or None, "hosting": hosting,
                         "approved": _tri(approved), "cui_in_scope": _tri(cui_in_scope), "owner": owner.strip() or None,
                         "notes": notes.strip() or None}, user.username)
    return RedirectResponse(f"/inventory/{key}", status_code=303)
