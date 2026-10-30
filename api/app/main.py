"""Gyrai API and console: the FastAPI application.

This module only wires things together. The work happens in the routers:
  events     - receives audit events (/api/v1/events) and lets you query them
  inventory  - the AI inventory
  console    - the HTML pages operators use
  auth_pages - login, logout and password change
"""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .auth import LoginRedirect, bootstrap_admin
from .config import settings
from .db import init_db
from .routers import auth_pages, console, events, inventory

log = logging.getLogger("aicp.api")

# The built-in development token. Anyone who has read the source knows it.
DEFAULT_INGEST_TOKEN = "dev-ingest-token-change-me"


def warn_if_default_token() -> bool:
    """Log a warning when the ingest token is still the development default.
    Returns True when the warning fired. Set AICP_INGEST_TOKEN to a long random value."""
    if settings.ingest_token == DEFAULT_INGEST_TOKEN:
        log.warning("AICP_INGEST_TOKEN is still the development default. Anyone can send events "
                    "to this API. Set it to a long random value before exposing the API.")
        return True
    return False


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Startup work: warn about the default token, create tables, then make sure at least
    one admin account exists."""
    warn_if_default_token()
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
