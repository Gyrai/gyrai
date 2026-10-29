"""Console authentication: local accounts, bcrypt, signed session cookie.

Why local accounts and not OIDC first: air-gapped and small customers need a
login that works with nothing else running. Entra/Okta OIDC is additive (0.3).

Every authentication event is written to the audit store as an `ai.admin.change`
event with source "manual", so the tool's own access is part of the evidence.
"""
import logging
import secrets
import uuid
from datetime import datetime, timezone

import bcrypt
from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .db import SessionLocal, User, get_db, utcnow

log = logging.getLogger("aicp.auth")
COOKIE = "aicp_session"

_secret = settings.session_secret or secrets.token_urlsafe(48)
if not settings.session_secret:
    log.warning("AICP_SESSION_SECRET not set; using a random secret (sessions reset on restart)")
_serializer = URLSafeTimedSerializer(_secret, salt="aicp-console")


# ---------- passwords ----------

def hash_password(pw: str) -> str:
    """bcrypt hash with 12 rounds. The salt is generated per password and stored in the hash."""
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(pw: str, pw_hash: str) -> bool:
    """True if `pw` matches the stored hash. A malformed hash counts as a mismatch, not an error."""
    try:
        return bcrypt.checkpw(pw.encode(), pw_hash.encode())
    except ValueError:
        return False


# ---------- sessions ----------

def make_session(username: str) -> str:
    """Create a signed, tamper-proof cookie value. The random `n` makes each token unique."""
    return _serializer.dumps({"u": username, "n": secrets.token_hex(8)})


def read_session(token: str | None) -> str | None:
    """Return the username in a valid, unexpired session cookie, or None."""
    if not token:
        return None
    try:
        data = _serializer.loads(token, max_age=settings.session_hours * 3600)
        return data.get("u")
    except (BadSignature, SignatureExpired):
        return None


def set_session_cookie(response, username: str) -> None:
    """Attach the session cookie. HttpOnly keeps scripts from reading it; SameSite=Lax blunts CSRF."""
    response.set_cookie(
        COOKIE, make_session(username),
        max_age=settings.session_hours * 3600,
        httponly=True, samesite="lax", secure=settings.cookie_secure, path="/",
    )


def clear_session_cookie(response) -> None:
    """Log out by deleting the session cookie."""
    response.delete_cookie(COOKIE, path="/")


# ---------- dependencies ----------

def current_user(request: Request, db: Session = Depends(get_db)) -> User | None:
    """The logged-in user, or None. Disabled accounts are treated as logged out even with a valid cookie."""
    username = read_session(request.cookies.get(COOKIE))
    if not username:
        return None
    user = db.get(User, username)
    if not user or user.disabled:
        return None
    return user


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    """For API routes: 401 JSON when not logged in."""
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    """For routes that change things: logged in AND role "admin" (viewers get 403)."""
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return user


class LoginRedirect(Exception):
    """Raised by console pages; the app converts it to a 302 to /login."""
    def __init__(self, next_path: str):
        self.next_path = next_path


def require_user_page(request: Request, db: Session = Depends(get_db)) -> User:
    """For HTML pages: redirect to /login instead of 401."""
    user = current_user(request, db)
    if not user:
        raise LoginRedirect(request.url.path)
    return user


# ---------- login / audit ----------

def audit_auth_event(db: Session, action: str, username: str, ip: str | None, ok: bool, reason: str = "") -> None:
    """Write a schema-valid audit event for an authentication action."""
    from .ingest import ingest_event  # local import avoids a cycle at module load
    ev = {
        "schema_version": "1.0.0",
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "manual",
        "observation_level": "metadata_only",
        "event_type": "ai.admin.change",
        "actor": {"type": "human", "id": username, **({"ip": ip} if ip else {})},
        "target": {"ai_system": "aicp.console", "hosting": "on_prem"},
        "decision": {"mode": "enforce", "action": "allow" if ok else "block",
                     "policy_id": "AICP-AUTH", "policy_version": "builtin", "reason": f"{action}: {reason or ('ok' if ok else 'denied')}"},
    }
    try:
        ingest_event(db, ev)
    except Exception as e:  # noqa: BLE001 - auth must not fail because audit did
        log.error("could not audit auth event: %s", e)


def attempt_login(db: Session, username: str, password: str, ip: str | None) -> User | None:
    """Check credentials and return the user, or None on any failure.

    Every outcome, good or bad, is written to the audit store. Failures return None without
    saying which check failed, so the login page cannot be used to discover usernames.
    """
    username = (username or "").strip().lower()
    user = db.get(User, username)
    if not user or user.disabled:
        # Hash anyway so timing doesn't reveal whether the account exists.
        bcrypt.checkpw(b"x", bcrypt.gensalt(rounds=4))
        audit_auth_event(db, "login", username or "<empty>", ip, False, "unknown or disabled account")
        return None
    if settings.lockout_after and user.failed_logins >= settings.lockout_after:
        audit_auth_event(db, "login", username, ip, False, "account locked")
        return None
    if not verify_password(password, user.password_hash):
        user.failed_logins += 1
        db.commit()
        audit_auth_event(db, "login", username, ip, False, f"bad password (failed_logins={user.failed_logins})")
        return None
    user.failed_logins = 0
    user.last_login = utcnow()
    db.commit()
    audit_auth_event(db, "login", username, ip, True)
    return user


def change_password(db: Session, user: User, new_password: str, ip: str | None) -> None:
    """Store a new password hash, clear the must-change flag and audit the change.
    The caller must already have checked the password with password_ok()."""
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    db.commit()
    audit_auth_event(db, "password_change", user.username, ip, True)


def password_ok(pw: str) -> str | None:
    """Return an error message or None. Keep policy simple and explainable (IA-5)."""
    if len(pw) < 12:
        return "Password must be at least 12 characters."
    if pw.lower() in {"password1234", "changeme1234", "administrator"}:
        return "That password is too common."
    return None


def bootstrap_admin() -> None:
    """Create the first admin if the users table is empty. Called at startup."""
    db = SessionLocal()
    try:
        if db.scalar(select(func.count(User.username))):
            return
        pw = settings.admin_password or secrets.token_urlsafe(14)
        db.add(User(username="admin", password_hash=hash_password(pw), role="admin",
                    display_name="Administrator", created_at=utcnow(),
                    must_change_password=not settings.admin_password))
        db.commit()
        if settings.admin_password:
            log.warning("Created initial 'admin' user from AICP_ADMIN_PASSWORD.")
        else:
            # Printed exactly once. Operators read it from `docker compose logs api`.
            log.warning("=" * 70)
            log.warning("Created initial console user.  username: admin   password: %s", pw)
            log.warning("You will be asked to change it at first login.")
            log.warning("=" * 70)
    finally:
        db.close()
