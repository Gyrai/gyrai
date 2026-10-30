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
    """Common base for all ORM tables; Base.metadata is what init_db() creates."""


class AuditEvent(Base):
    """One audit event. The searchable columns are copied out of `body` so the console
    can filter and sort quickly; `body` keeps the complete original event.
    `prev_hash` and `hash` link each row to the one before it (see ingest.py)."""

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
    """One entry in the AI inventory: a model, tool or agent that has been seen or declared."""

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


class User(Base):
    """A console login. Only a bcrypt hash of the password is stored."""

    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(128), primary_key=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16), default="admin")  # admin | viewer
    display_name: Mapped[str | None] = mapped_column(String(256))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_logins: Mapped[int] = mapped_column(Integer, default=0)


def _make_engine(url: str):
    """Create the SQLAlchemy engine. SQLite gets two tweaks: allow use from several threads
    (FastAPI runs handlers in a pool) and write-ahead logging so readers do not block the writer."""
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
    """Create any missing tables. Safe to call on every startup."""
    Base.metadata.create_all(engine)


def get_db():
    """FastAPI dependency: give a handler its own database session and always close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utcnow() -> datetime:
    """Current time as a timezone-aware UTC datetime. Use this instead of datetime.now()."""
    return datetime.now(timezone.utc)
