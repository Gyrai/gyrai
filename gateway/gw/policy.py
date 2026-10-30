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
    """Ask OPA what policy says about this event and return the `decision` block to
    stamp on it: {"mode", "action", "policy_id", "policy_version", "reason"}.

    `action` is what policy said. What the gateway actually does is decided separately
    by effective_action(), because monitor mode never acts on it."""
    mode = settings.mode
    # Default decision, used when OPA is switched off or its answer lacks a field.
    decision = {"mode": mode, "action": "allow", "policy_id": "AICP-000",
                "policy_version": "unknown", "reason": "policy engine disabled"}

    if settings.opa_enabled:
        try:
            # Short timeout: a slow policy engine must not noticeably slow every request.
            r = httpx.post(f"{settings.opa_url}/v1/data/aicp/advisory", json={"input": event}, timeout=2.0)
            r.raise_for_status()
            res = r.json().get("result") or {}
            # Copy only the fields we expect from OPA's answer, so unexpected extras never reach the audit event.
            decision.update({k: res[k] for k in ("action", "policy_id", "policy_version", "reason") if k in res})
            # The mode always comes from gateway settings, never from the policy engine.
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
    """Turn a recorded decision into the action the gateway will really take:
    allow, mask, block, route_local or require_approval.

    Monitor mode always allows. In enforce mode `route_local` degrades to `block` when
    no local model is configured, so regulated content is never sent to the public upstream.
    """
    if settings.mode != "enforce":
        return "allow"
    a = decision.get("action", "allow")
    if a == "route_local" and not settings.local_upstream_url:
        return "block"
    return a
