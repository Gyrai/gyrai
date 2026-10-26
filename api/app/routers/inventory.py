import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_admin, require_user
from ..db import AISystem, User, get_db, utcnow

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


def audit_inventory_change(db: Session, actor: str, key: str, changes: dict) -> None:
    """Every inventory decision (approval, CUI scoping, ownership) is itself evidence (CM-3, CM-8)."""
    from ..ingest import ingest_event
    summary = ", ".join(f"{k}={v!r}" for k, v in changes.items()) or "no-op"
    ingest_event(db, {
        "schema_version": "1.0.0",
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "manual",
        "observation_level": "metadata_only",
        "event_type": "ai.admin.change",
        "actor": {"type": "human", "id": actor},
        "target": {"ai_system": key},
        "decision": {"mode": "enforce", "action": "allow", "policy_id": "AICP-INVENTORY",
                     "policy_version": "builtin", "reason": f"inventory update: {summary}"[:500]},
    })


def apply_update(db: Session, s: AISystem, data: dict, actor: str) -> dict:
    changes = {}
    for field, value in data.items():
        if getattr(s, field) != value:
            setattr(s, field, value)
            changes[field] = value
    db.commit()
    if changes:
        audit_inventory_change(db, actor, s.key, changes)
    return changes


def create_declared(db: Session, data: dict, actor: str) -> AISystem:
    now = utcnow()
    s = AISystem(
        key=data["key"],
        display_name=data.get("display_name") or data["key"],
        vendor=data.get("vendor"),
        hosting=data.get("hosting") or "unknown",
        governance_state="declared",
        cui_in_scope=data.get("cui_in_scope"),
        approved=data.get("approved"),
        owner=data.get("owner"),
        notes=data.get("notes"),
        first_seen=now,
        last_seen=now,
        event_count=0,
        sources=["manual"],
    )
    db.add(s)
    db.commit()
    audit_inventory_change(db, actor, s.key, {"declared": True, "hosting": s.hosting})
    return s


@router.get("/systems", dependencies=[Depends(require_user)])
def list_systems(db: Session = Depends(get_db)):
    rows = db.scalars(select(AISystem).order_by(AISystem.event_count.desc())).all()
    return [_dump(r) for r in rows]


@router.post("/systems", status_code=201)
def declare_system(body: SystemCreate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Manually register an AI tool nobody's logs can see (the 'declared' state)."""
    if db.get(AISystem, body.key):
        raise HTTPException(409, "system already exists; use PATCH")
    return _dump(create_declared(db, body.model_dump(), user.username))


@router.patch("/systems/{key}")
def update_system(key: str, body: SystemUpdate, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    s = db.get(AISystem, key)
    if not s:
        raise HTTPException(404, "unknown system")
    apply_update(db, s, body.model_dump(exclude_unset=True), user.username)
    return _dump(s)
