from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .config import settings
from .db import init_db
from .routers import console, events, inventory


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title=settings.product_name,
    version="0.1.0",
    description="AI usage monitoring, inventory, and compliance evidence. Monitor mode today; the inline gateway writes to the same store.",
    lifespan=lifespan,
)
app.include_router(events.router)
app.include_router(inventory.router)
app.include_router(console.router)
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="static")


@app.get("/healthz", include_in_schema=False)
def healthz():
    return {"ok": True}
