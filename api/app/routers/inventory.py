from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import AISystem, get_db, utcnow

router = APIRouter(prefix="/api/v1", tags=["inventory"])


class SystemUpdate(BaseModel):
    display_name: str | None = None
    vendor: str | None = None
    hosting: str | None = None
    cui_in_scope: bool | None = None
    approved: bool | None = None
    owner: str | None = None
    notes: str | None = None


class SystemCreate(SystemUpdate):
    key: str
    display_name: str


def _dump(s: AISystem) -> dict:
    return {
        "key": s.key,
        "display_name": s.display_name,
        "vendor": s.vendor,
        "hosting": s.hosting,
        "governance_state": s.governance_state,
        "cui_in_scope": s.cui_in_scope,
        "approved": s.approved,
        "owner": s.owner,
        "notes": s.notes,
        "first_seen": s.first_seen.isoformat(),
        "last_seen": s.last_seen.isoformat(),
        "event_count": s.event_count,
        "sources": s.sources,
    }


@router.get("/systems")
def list_systems(db: Session = Depends(get_db)):
    rows = db.scalars(select(AISystem).order_by(AISystem.event_count.desc())).all()
    return [_dump(r) for r in rows]


@router.post("/systems", status_code=201)
def declare_system(body: SystemCreate, db: Session = Depends(get_db)):
    """Manually register an AI tool nobody's logs can see (the 'declared' state)."""
    if db.get(AISystem, body.key):
        raise HTTPException(409, "system already exists; use PATCH")
    now = utcnow()
    s = AISystem(
        key=body.key,
        display_name=body.display_name,
        vendor=body.vendor,
        hosting=body.hosting or "unknown",
        governance_state="declared",
        cui_in_scope=body.cui_in_scope,
        approved=body.approved,
        owner=body.owner,
        notes=body.notes,
        first_seen=now,
        last_seen=now,
        event_count=0,
        sources=["manual"],
    )
    db.add(s)
    db.commit()
    return _dump(s)


@router.patch("/systems/{key}")
def update_system(key: str, body: SystemUpdate, db: Session = Depends(get_db)):
    s = db.get(AISystem, key)
    if not s:
        raise HTTPException(404, "unknown system")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(s, field, value)
    db.commit()
    return _dump(s)
