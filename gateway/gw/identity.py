"""Stage 1: who is calling.

Apps present `Authorization: Bearer <gateway key>`. The key maps to an identity
record. The provider key is never accepted from the client and never forwarded
from it; the gateway substitutes its own.
"""
import json
from pathlib import Path

from fastapi import HTTPException, Request

from .config import settings

_keys: dict[str, dict] | None = None


def _load() -> dict[str, dict]:
    global _keys
    if _keys is None:
        p = Path(settings.keys_file)
        _keys = json.loads(p.read_text()) if p.exists() else {}
    return _keys


def reload_keys() -> None:
    global _keys
    _keys = None


def identify(request: Request) -> dict:
    auth = request.headers.get("authorization", "")
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
