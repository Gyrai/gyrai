"""Stage 1: who is calling.

Apps present `Authorization: Bearer <gateway key>`. The key maps to an identity
record. The provider key is never accepted from the client and never forwarded
from it; the gateway substitutes its own.
"""
import json
from pathlib import Path

from fastapi import HTTPException, Request

from .config import settings

# Cache of the keys file, loaded lazily on first use. None means "not loaded yet".
_keys: dict[str, dict] | None = None


def _load() -> dict[str, dict]:
    """Return the gateway-key table, reading the keys file once and caching it.
    A missing file gives an empty table, so every caller is "unknown"."""
    global _keys
    if _keys is None:
        p = Path(settings.keys_file)
        _keys = json.loads(p.read_text()) if p.exists() else {}
    return _keys


def reload_keys() -> None:
    """Drop the cache so the next request re-reads the keys file (used by tests)."""
    global _keys
    _keys = None


def identify(request: Request) -> dict:
    """Work out who is calling and return an `actor` block for the audit event:
    {"type": "human|agent|service|unknown", "id": ..., optional "on_behalf_of", "ip"}.

    Monitor mode lets unknown keys through as actor "unknown" so nothing breaks while
    an organization is still learning who calls what. Enforce mode rejects them with 401.
    """
    auth = request.headers.get("authorization", "")
    # Strip the "Bearer " prefix. Any other header form counts as no key at all.
    key = auth.removeprefix("Bearer ").strip() if auth.lower().startswith("bearer ") else ""
    rec = _load().get(key)
    if rec:
        actor = {"type": rec.get("type", "service"), "id": rec["id"]}
        if rec.get("on_behalf_of"):
            actor["on_behalf_of"] = rec["on_behalf_of"]
    elif settings.mode == "enforce":
        raise HTTPException(401, "unknown gateway key")
    else:
        actor = {"type": "unknown", "id": "unknown"}
    # Optional explicit sponsor header for agent frameworks that know the human user.
    if request.headers.get("x-aicp-on-behalf-of"):
        actor["on_behalf_of"] = request.headers["x-aicp-on-behalf-of"]
    if request.client:
        actor["ip"] = request.client.host
    return actor
