"""Stage 2 (decision half): ask OPA, then apply the mode.

Monitor mode: whatever OPA says, the effective action is "allow"; the advisory
decision is recorded on the audit event so the customer can see what enforce
mode would have done.

Enforce mode: OPA's action is binding. If OPA is unreachable the gateway fails
CLOSED in enforce mode (a security proxy that silently passes traffic when its
policy engine is down is not a security proxy) and fails OPEN in monitor mode.
"""
import logging

import httpx

from .config import settings

log = logging.getLogger("aicp.gateway.policy")


def evaluate(event: dict) -> dict:
    """Returns the decision block to stamp on the event. `effective` is what the
    gateway will actually do; `action` is what policy said."""
    mode = settings.mode
    decision = {"mode": mode, "action": "allow", "policy_id": "AICP-000",
                "policy_version": "unknown", "reason": "policy engine disabled"}

    if settings.opa_enabled:
        try:
            r = httpx.post(f"{settings.opa_url}/v1/data/aicp/advisory", json={"input": event}, timeout=2.0)
            r.raise_for_status()
            res = r.json().get("result") or {}
            decision.update({k: res[k] for k in ("action", "policy_id", "policy_version", "reason") if k in res})
            decision["mode"] = mode
        except httpx.HTTPError as e:
            log.error("OPA unreachable: %s", e)
            if mode == "enforce":
                decision.update({"action": "block", "policy_id": "AICP-FAILCLOSED",
                                 "reason": "policy engine unreachable; enforce mode fails closed"})
            else:
                decision["reason"] = "policy engine unreachable; monitor mode fails open"

    return decision


def effective_action(decision: dict) -> str:
    if settings.mode != "enforce":
        return "allow"
    a = decision.get("action", "allow")
    if a == "route_local" and not settings.local_upstream_url:
        return "block"
    return a
