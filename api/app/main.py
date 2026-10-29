"""Gyrai API and console: the FastAPI application.

This module only wires things together. The work happens in the routers:
  events     - receives audit events (/api/v1/events) and lets you query them
  inventory  - the AI inventory
  console    - the HTML pages operators use
  auth_pages - login, logout and password change
"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .auth import LoginRedirect, bootstrap_admin
from .config import settings
from .db import init_db
from .routers import auth_pages, console, events, inventory


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Startup work: create tables, then make sure at least one admin account exists."""
    init_db()
    bootstrap_admin()
    yield


app = FastAPI(
    title=settings.product_name,
    version="0.1.0",
    description="AI usage monitoring, inventory, and compliance evidence. Monitor mode today; the inline gateway writes to the same store.",
    lifespan=lifespan,
)
app.include_router(auth_pages.router)
app.include_router(events.router)
app.include_router(inventory.router)
app.include_router(console.router)
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="static")


@app.exception_handler(LoginRedirect)
async def _login_redirect(request: Request, exc: LoginRedirect):
    """Send visitors to the login page, remembering which page they wanted."""
    return RedirectResponse(f"/login?next={exc.next_path}", status_code=302)


@app.get("/healthz", include_in_schema=False)
def healthz():
    """Liveness probe for docker and load balancers. Needs no login."""
    return {"ok": True}
