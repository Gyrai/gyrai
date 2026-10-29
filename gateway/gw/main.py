"""Gyrai — inline gateway.

OpenAI-compatible proxy. Apps set base_url to this service and keep working.

  POST /v1/chat/completions   (streaming and non-streaming)
  POST /v1/embeddings
  GET  /v1/models             (pass-through)

Pipeline per request:  identify -> ingress (DLP + policy) -> forward -> egress (DLP + unmask) -> audit
"""
import hashlib
import json
import logging
from collections.abc import AsyncIterator

import httpx
from aicp_collectors.dlp import redact, scan, unredact
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .audit import new_event, sink
from .config import settings
from .identity import identify
from .policy import effective_action, evaluate

log = logging.getLogger("aicp.gateway")
app = FastAPI(title="Gyrai Gateway", version="0.1.0")


# ---------- helpers ----------

def _sha(s: str) -> str:
    """SHA-256 of the text. Audit events carry hashes, never the prompt or response itself."""
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def _text_of_messages(messages: list[dict]) -> str:
    """Flatten chat messages to one string for scanning. Handles string content and
    multimodal part lists (text parts only; images are counted as attachments)."""
    parts = []
    for m in messages or []:
        c = m.get("content")
        if isinstance(c, str):
            parts.append(c)
        elif isinstance(c, list):
            for p in c:
                if isinstance(p, dict) and p.get("type") == "text":
                    parts.append(p.get("text", ""))
        for tc in m.get("tool_calls") or []:
            parts.append(json.dumps((tc.get("function") or {}).get("arguments", "")))
    return "\n".join(parts)


def _count_attachments(messages: list[dict]) -> int:
    """Count non-text message parts (images, files) so the audit event can note them."""
    n = 0
    for m in messages or []:
        if isinstance(m.get("content"), list):
            n += sum(1 for p in m["content"] if isinstance(p, dict) and p.get("type") != "text")
    return n


def _apply_to_messages(messages: list[dict], fn) -> list[dict]:
    """Return a copy of the messages with `fn` applied to every text part (used for masking).
    The caller's original list is not modified."""
    out = []
    for m in messages:
        m = dict(m)
        c = m.get("content")
        if isinstance(c, str):
            m["content"] = fn(c)
        elif isinstance(c, list):
            m["content"] = [{**p, "text": fn(p["text"])} if isinstance(p, dict) and p.get("type") == "text" else p for p in c]
        out.append(m)
    return out


def _target(payload: dict, local: bool = False) -> dict:
    """Describe the model being called for the audit event: system, model id, hosting and endpoint.
    `local=True` describes the on-prem model used by the route_local action."""
    return {
        "ai_system": "gateway.local" if local else settings.upstream_system_key,
        "model_id": payload.get("model", ""),
        "hosting": "on_prem" if local else settings.upstream_hosting,
        "endpoint": settings.local_upstream_url if local else settings.upstream_url,
    }


async def _forward(path: str, payload: dict, stream: bool, local: bool = False) -> httpx.Response:
    """Send the request to the upstream model and return its response.

    The gateway's own provider key is attached here, so client apps never hold one.
    The HTTP client must outlive this function when streaming, so it is stored on the
    response as `_aicp_client` and the caller closes it once the body has been read.
    """
    base = settings.local_upstream_url if local else settings.upstream_url
    key = settings.local_upstream_key if local else settings.upstream_key
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
        headers["api-key"] = key  # Azure OpenAI uses this header name
    client = httpx.AsyncClient(timeout=settings.upstream_timeout_seconds)
    req = client.build_request("POST", f"{base.rstrip('/')}{path}", json=payload, headers=headers)
    try:
        resp = await client.send(req, stream=stream)
    except httpx.RequestError as e:
        await client.aclose()
        raise HTTPException(502, f"upstream unreachable: {e}") from e
    resp._aicp_client = client  # closed after streaming completes
    return resp


# ---------- routes ----------

@app.get("/healthz")
def healthz():
    """Liveness probe. Also reports the mode so operators can see monitor vs enforce at a glance."""
    return {"ok": True, "mode": settings.mode}


@app.get("/v1/models")
async def models(request: Request):
    """Pass the model list through from the upstream. The caller is still identified."""
    identify(request)
    r = await _forward("/v1/models", {}, stream=False)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"data": []}
    await r._aicp_client.aclose()
    return JSONResponse(body, status_code=r.status_code)


@app.post("/v1/embeddings")
async def embeddings(request: Request):
    """Embeddings follow the same stages as chat (identify, scan, decide, forward, audit),
    but there is no streaming and no response text to scan."""
    actor = identify(request)
    payload = await request.json()
    inp = payload.get("input", "")
    text = "\n".join(inp) if isinstance(inp, list) else str(inp)
    findings = scan(text)
    ev = new_event("ai.embedding.created", actor, _target(payload),
                   content={"prompt_sha256": _sha(text), "prompt_tokens": max(1, len(text) // 4),
                            **({"dlp_findings": findings} if findings else {})})
    if findings:
        ev["event_type"] = "ai.dlp.match"
    ev["decision"] = evaluate(ev)
    act = effective_action(ev["decision"])
    if act in ("block", "require_approval"):
        ev["event_type"] = "ai.policy.violation"
        sink().emit(ev)
        raise HTTPException(403, {"error": "blocked by policy", "policy_id": ev["decision"]["policy_id"], "reason": ev["decision"]["reason"]})
    local = act == "route_local"
    if act == "mask":
        masked, _ = redact(text)
        payload["input"] = masked
    r = await _forward("/v1/embeddings", payload, stream=False, local=local)
    body = r.json()
    await r._aicp_client.aclose()
    if local:
        ev["target"] = _target(payload, local=True)
    sink().emit(ev)
    return JSONResponse(body, status_code=r.status_code)


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    """The main route. Stages: identify the caller, scan the prompt, ask policy, then
    block, mask, reroute or allow, forward upstream, and audit both prompt and response."""
    actor = identify(request)
    payload = await request.json()
    messages = payload.get("messages", [])
    stream = bool(payload.get("stream"))

    # ---- Stage 2: ingress ----
    text = _text_of_messages(messages)
    findings = scan(text)
    content = {"prompt_sha256": _sha(text), "prompt_tokens": max(1, len(text) // 4),
               "attachments": _count_attachments(messages)}
    if findings:
        content["dlp_findings"] = findings
    ev = new_event("ai.dlp.match" if findings else "ai.prompt.submitted", actor, _target(payload), content=content)
    if payload.get("tools"):
        ev["target"]["tool_server"] = "inline"
    ev["decision"] = evaluate(ev)
    act = effective_action(ev["decision"])

    if act in ("block", "require_approval"):
        # require_approval becomes a real HITL queue in 0.4; today it is a block with a distinct reason.
        ev["event_type"] = "ai.policy.violation"
        sink().emit(ev)
        raise HTTPException(403, {"error": "blocked by policy", "policy_id": ev["decision"]["policy_id"], "reason": ev["decision"]["reason"]})

    # Maps each placeholder inserted by masking back to the original value, so the
    # model's reply can be restored before the user sees it. It never leaves this request.
    vault: dict[str, str] = {}
    if act == "mask":
        def _mask(s: str) -> str:
            nonlocal vault
            masked, v = redact(s)
            vault.update(v)
            return masked
        payload["messages"] = _apply_to_messages(messages, _mask)
        ev["decision"]["reason"] = f"{ev['decision']['reason']} (masked {len(vault)} values)"

    local = act == "route_local"
    if local:
        ev["target"] = _target(payload, local=True)

    sink().emit(ev)

    # ---- Stage 3/4: forward + egress ----
    r = await _forward("/v1/chat/completions", payload, stream=stream, local=local)

    if r.status_code >= 400 and not stream:
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"error": r.text}
        await r._aicp_client.aclose()
        return JSONResponse(body, status_code=r.status_code)

    if not stream:
        body = r.json()
        await r._aicp_client.aclose()
        out_text = ""
        for ch in body.get("choices", []):
            msg = ch.get("message") or {}
            if isinstance(msg.get("content"), str):
                msg["content"] = unredact(msg["content"], vault)
                out_text += msg["content"]
        _emit_response(actor, ev["target"], out_text, body.get("usage") or {}, vault)
        return JSONResponse(body, status_code=r.status_code)

    return StreamingResponse(_stream(r, actor, ev["target"], vault), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _emit_response(actor: dict, target: dict, out_text: str, usage: dict, vault: dict) -> None:
    """Scan the model's reply and audit it. Uses the provider's token count when given,
    otherwise estimates about four characters per token."""
    findings = scan(out_text)
    content = {"response_sha256": _sha(out_text),
               "response_tokens": usage.get("completion_tokens") or max(1, len(out_text) // 4)}
    if findings:
        content["dlp_findings"] = findings
    ev = new_event("ai.dlp.match" if findings else "ai.response.delivered", actor, target, content=content,
                   decision={"mode": settings.mode, "action": "allow", "policy_id": "AICP-EGRESS",
                             "policy_version": "unknown", "reason": "egress scan" + (f"; unmasked {len(vault)} values" if vault else "")})
    sink().emit(ev)


async def _stream(r: httpx.Response, actor: dict, target: dict, vault: dict) -> AsyncIterator[bytes]:
    """Pass SSE chunks through as they arrive, un-masking text deltas and
    accumulating the response for an egress scan at the end. Streaming egress
    *blocking* (holding the tail until a scan clears) is a 0.5 feature; today the
    stream is monitored, not held."""
    collected = []
    try:
        async for line in r.aiter_lines():
            if not line:
                yield b"\n"
                continue
            if line.startswith("data: ") and line != "data: [DONE]":
                try:
                    chunk = json.loads(line[6:])
                    for ch in chunk.get("choices", []):
                        delta = ch.get("delta") or {}
                        if isinstance(delta.get("content"), str):
                            if vault:
                                delta["content"] = unredact(delta["content"], vault)
                            collected.append(delta["content"])
                    line = "data: " + json.dumps(chunk)
                except json.JSONDecodeError:
                    pass
            yield (line + "\n").encode()
    finally:
        await r.aclose()
        await r._aicp_client.aclose()
        _emit_response(actor, target, "".join(collected), {}, vault)
