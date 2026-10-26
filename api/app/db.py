"""Database layer. SQLAlchemy 2.x, works against SQLite (dev) and Postgres (prod).

Two tables only:
  audit_events  - append-only. One row per schema event. Never updated in place.
  ai_systems    - the inventory. Upserted by ingest and by manual registration.
"""
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


class AuditEvent(Base):
    __tablename__ = "audit_events"

    # Surrogate key keeps inserts cheap and ordered for hash-chaining.
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    source: Mapped[str] = mapped_column(String(64), index=True)
    observation_level: Mapped[str] = mapped_column(String(32), index=True)
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(256), index=True)
    ai_system: Mapped[str] = mapped_column(String(128), index=True)
    decision_action: Mapped[str | None] = mapped_column(String(32), index=True)
    dlp_hit: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    # Full event as written, for export and SIEM forwarding.
    body: Mapped[dict] = mapped_column(JSON)
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    hash: Mapped[str | None] = mapped_column(String(64), index=True)


class AISystem(Base):
    __tablename__ = "ai_systems"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(256))
    vendor: Mapped[str | None] = mapped_column(String(128))
    hosting: Mapped[str] = mapped_column(String(32), default="unknown")
    # governed | observed | declared  -- the three inventory states assessors ask about
    governance_state: Mapped[str] = mapped_column(String(16), default="observed", index=True)
    # Does the org believe CUI can reach this system? Set by the consultant during scoping.
    cui_in_scope: Mapped[bool | None] = mapped_column(Boolean, default=None)
    approved: Mapped[bool | None] = mapped_column(Boolean, default=None)
    owner: Mapped[str | None] = mapped_column(String(256))
    notes: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    sources: Mapped[list] = mapped_column(JSON, default=list)


def _make_engine(url: str):
    kwargs = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    eng = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _fk(dbapi_conn, _):
            dbapi_conn.execute("PRAGMA journal_mode=WAL")
    return eng


engine = _make_engine(settings.database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
