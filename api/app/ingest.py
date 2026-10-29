"""Ingest pipeline. Every event, from any source, goes through exactly this path:

  validate (JSON Schema) -> advisory policy (OPA, optional) -> hash-chain -> store -> inventory upsert

The future inline gateway calls the same function; it just sets decision.mode = "enforce".
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
from jsonschema import Draft202012Validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .db import AISystem, AuditEvent, utcnow

# The one JSON Schema every event must satisfy, whichever collector or the gateway produced it.
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "audit-event.schema.json"
_validator = Draft202012Validator(json.loads(SCHEMA_PATH.read_text()))


class IngestError(ValueError):
    """The event is not valid against the audit-event schema. The message says which fields."""


def validate(event: dict) -> None:
    """Raise IngestError listing up to five schema problems, or return quietly if the event is valid."""
    errors = sorted(_validator.iter_errors(event), key=lambda e: e.path)
    if errors:
        msg = "; ".join(f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors[:5])
        raise IngestError(msg)


def _canonical(event: dict) -> bytes:
    """Serialize an event the same way every time (sorted keys, no spaces) so that
    hashing it twice always gives the same answer."""
    return json.dumps(event, sort_keys=True, separators=(",", ":")).encode()


def advisory_decision(event: dict) -> dict | None:
    """Ask OPA what it *would* do. Returns None when OPA is disabled or unreachable;
    monitoring must never fail because the policy engine is down."""
    if not settings.opa_enabled:
        return None
    try:
        r = httpx.post(f"{settings.opa_url}/v1/data/aicp/advisory", json={"input": event}, timeout=2.0)
        r.raise_for_status()
        result = r.json().get("result")
        if result:
            result.setdefault("mode", "monitor")
        return result
    except httpx.HTTPError:
        return None


def ingest_event(db: Session, event: dict) -> AuditEvent:
    """Validate and store one event, and return its database row.

    Steps: reject invalid events; return the existing row if this event_id was already
    stored; stamp `received_at`; fill in an advisory policy decision if the sender gave none;
    add the hash-chain link; save the row and update the inventory.
    """
    validate(event)

    # Idempotent: re-collecting the same upstream record is a no-op.
    existing = db.scalar(select(AuditEvent).where(AuditEvent.event_id == event["event_id"]))
    if existing:
        return existing

    event = dict(event)
    event["received_at"] = utcnow().isoformat()

    if "decision" not in event or event.get("decision") is None:
        adv = advisory_decision(event)
        if adv:
            event["decision"] = adv

    # Hash chain: each event's hash covers the previous hash plus the event itself, so
    # changing or deleting any stored event breaks every hash after it. verify_chain()
    # re-computes the chain to detect this. The first event links to 64 zeros.
    prev_hash = None
    this_hash = None
    if settings.hash_chain_enabled:
        last = db.scalar(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(1))
        prev_hash = last.hash if last else "0" * 64
        this_hash = hashlib.sha256(prev_hash.encode() + _canonical(event)).hexdigest()
        event["integrity"] = {"prev_hash": prev_hash, "hash": this_hash}

    # Copy the fields the console filters on into their own columns; the full event stays in `body`.
    dlp = event.get("content", {}).get("dlp_findings") or []
    row = AuditEvent(
        event_id=event["event_id"],
        timestamp=datetime.fromisoformat(event["timestamp"]),
        received_at=datetime.fromisoformat(event["received_at"]),
        source=event["source"],
        observation_level=event["observation_level"],
        event_type=event["event_type"],
        actor_id=event.get("actor", {}).get("id"),
        ai_system=event["target"]["ai_system"],
        decision_action=(event.get("decision") or {}).get("action"),
        dlp_hit=bool(dlp),
        body=event,
        prev_hash=prev_hash,
        hash=this_hash,
    )
    db.add(row)
    _upsert_system(db, event)
    db.commit()
    return row


def _aware(dt: datetime) -> datetime:
    """SQLite hands back naive datetimes; treat them as UTC."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _upsert_system(db: Session, event: dict) -> None:
    """Keep the AI inventory current: add the target system if it is new, then update its
    first/last seen times, event count and sources. Seeing an "enforced" event (one that
    passed through the gateway) upgrades a system from "observed" to "governed"."""
    key = event["target"]["ai_system"]
    ts = datetime.fromisoformat(event["timestamp"])
    sys_row = db.get(AISystem, key)
    level = event["observation_level"]
    if sys_row is None:
        sys_row = AISystem(
            key=key,
            display_name=key,
            hosting=event["target"].get("hosting", "unknown"),
            governance_state="governed" if level == "enforced" else "observed",
            first_seen=ts,
            last_seen=ts,
            event_count=0,
            sources=[],
        )
        db.add(sys_row)
    sys_row.last_seen = max(_aware(sys_row.last_seen), ts)
    sys_row.first_seen = min(_aware(sys_row.first_seen), ts)
    sys_row.event_count += 1
    if event["source"] not in sys_row.sources:
        sys_row.sources = [*sys_row.sources, event["source"]]
    if level == "enforced":
        sys_row.governance_state = "governed"


def verify_chain(db: Session) -> dict:
    """Walk the chain and confirm every hash links. Cheap integrity check an assessor can run."""
    rows = db.scalars(select(AuditEvent).order_by(AuditEvent.seq)).all()
    prev = "0" * 64
    for r in rows:
        if r.hash is None:
            continue
        body = dict(r.body)
        body.pop("integrity", None)
        expect = hashlib.sha256(prev.encode() + _canonical(body)).hexdigest()
        if expect != r.hash or r.prev_hash != prev:
            return {"ok": False, "broken_at_seq": r.seq, "checked": len(rows)}
        prev = r.hash
    return {"ok": True, "checked": len(rows), "head": prev}
