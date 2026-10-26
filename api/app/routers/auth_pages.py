"""Login / logout / change-password pages."""
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ..auth import (
    attempt_login,
    audit_auth_event,
    change_password,
    clear_session_cookie,
    current_user,
    password_ok,
    require_user_page,
    set_session_cookie,
    verify_password,
)
from ..config import settings
from ..db import User, get_db

router = APIRouter(include_in_schema=False)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "templates"))


def _ctx(request: Request, **kw):
    return {"request": request, "product": settings.product_name, "org": settings.org_name, "user": None, **kw}


def _safe_next(n: str | None) -> str:
    return n if n and n.startswith("/") and not n.startswith("//") else "/"


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/", db: Session = Depends(get_db)):
    if current_user(request, db):
        return RedirectResponse(_safe_next(next), status_code=302)
    return templates.TemplateResponse(request, "login.html", _ctx(request, next=_safe_next(next), error=None))


@router.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/"),
                 db: Session = Depends(get_db)):
    ip = request.client.host if request.client else None
    user = attempt_login(db, username, password, ip)
    if not user:
        return templates.TemplateResponse(request, "login.html",
                                          _ctx(request, next=_safe_next(next), error="Invalid username or password."),
                                          status_code=401)
    dest = "/account/password" if user.must_change_password else _safe_next(next)
    resp = RedirectResponse(dest, status_code=302)
    set_session_cookie(resp, user.username)
    return resp


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    user = current_user(request, db)
    if user:
        audit_auth_event(db, "logout", user.username, request.client.host if request.client else None, True)
    resp = RedirectResponse("/login", status_code=302)
    clear_session_cookie(resp)
    return resp


@router.get("/account/password", response_class=HTMLResponse)
def password_form(request: Request, user: User = Depends(require_user_page)):
    return templates.TemplateResponse(request, "password.html", _ctx(request, user=user, error=None, forced=user.must_change_password))


@router.post("/account/password", response_class=HTMLResponse)
def password_submit(request: Request, current: str = Form(...), new: str = Form(...), confirm: str = Form(...),
                    user: User = Depends(require_user_page), db: Session = Depends(get_db)):
    err = None
    if not verify_password(current, user.password_hash):
        err = "Current password is incorrect."
    elif new != confirm:
        err = "New passwords do not match."
    else:
        err = password_ok(new)
    if err:
        return templates.TemplateResponse(request, "password.html", _ctx(request, user=user, error=err, forced=user.must_change_password), status_code=400)
    change_password(db, user, new, request.client.host if request.client else None)
    return RedirectResponse("/", status_code=302)
