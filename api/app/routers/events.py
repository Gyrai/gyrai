from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import AuditEvent, get_db
from ..ingest import IngestError, ingest_event, verify_chain

router = APIRouter(prefix="/api/v1", tags=["events"])


def require_ingest_token(authorization: str = Header(default="")) -> None:
    if authorization != f"Bearer {settings.ingest_token}":
        raise HTTPException(status_code=401, detail="invalid ingest token")


@router.post("/events", status_code=202, dependencies=[Depends(require_ingest_token)])
def post_events(events: list[dict], db: Session = Depends(get_db)):
    """Batch ingest. Collectors and the gateway both post here."""
    accepted, rejected = 0, []
    for ev in events:
        try:
            ingest_event(db, ev)
            accepted += 1
        except IngestError as e:
            rejected.append({"event_id": ev.get("event_id"), "error": str(e)})
    return {"accepted": accepted, "rejected": rejected}


@router.get("/events")
def list_events(
    db: Session = Depends(get_db),
    limit: int = Query(100, le=1000),
    ai_system: str | None = None,
    event_type: str | None = None,
    actor_id: str | None = None,
    dlp_only: bool = False,
):
    q = select(AuditEvent).order_by(AuditEvent.seq.desc())
    if ai_system:
        q = q.where(AuditEvent.ai_system == ai_system)
    if event_type:
        q = q.where(AuditEvent.event_type == event_type)
    if actor_id:
        q = q.where(AuditEvent.actor_id == actor_id)
    if dlp_only:
        q = q.where(AuditEvent.dlp_hit.is_(True))
    return [r.body for r in db.scalars(q.limit(limit))]


@router.get("/events/stats")
def stats(db: Session = Depends(get_db)):
    total = db.scalar(select(func.count(AuditEvent.seq))) or 0
    by_level = dict(db.execute(
        select(AuditEvent.observation_level, func.count()).group_by(AuditEvent.observation_level)
    ).all())
    by_type = dict(db.execute(
        select(AuditEvent.event_type, func.count()).group_by(AuditEvent.event_type)
    ).all())
    dlp = db.scalar(select(func.count(AuditEvent.seq)).where(AuditEvent.dlp_hit.is_(True))) or 0
    would_block = db.scalar(
        select(func.count(AuditEvent.seq)).where(AuditEvent.decision_action.in_(["block", "mask", "require_approval"]))
    ) or 0
    return {
        "total_events": total,
        "by_observation_level": by_level,
        "by_event_type": by_type,
        "dlp_events": dlp,
        "advisory_would_act": would_block,
    }


@router.get("/events/integrity")
def integrity(db: Session = Depends(get_db)):
    return verify_chain(db)
