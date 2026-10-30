"""Gateway tests. The mock upstream runs in-process via httpx's ASGI transport,
so no network and no provider key are needed. OPA is replaced by a stub that
returns the policy decision each test wants."""
import json
import os
import sys
from pathlib import Path

import httpx
import pytest

os.environ["AICP_GW_OPA_ENABLED"] = "false"
os.environ["AICP_GW_KEYS_FILE"] = str(Path(__file__).resolve().parents[1] / "gateway" / "gateway_keys.example.json")
os.environ["AICP_GW_UPSTREAM_URL"] = "http://mock-upstream"

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))
import mock_upstream  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from gw import audit, main, policy  # noqa: E402
from gw.config import settings  # noqa: E402

ALICE = {"Authorization": "Bearer gw-dev-key-alice"}


@pytest.fixture(autouse=True)
def wire(monkeypatch):
    """Route the gateway's upstream calls into the in-process mock server."""
    transport = httpx.ASGITransport(app=mock_upstream.app)
    real_client = httpx.AsyncClient

    def patched(*a, **kw):
        kw["transport"] = transport
        return real_client(*a, **kw)

    monkeypatch.setattr(main.httpx, "AsyncClient", patched)
    sink = audit.ListSink()
    audit.set_sink(sink)
    monkeypatch.setattr(settings, "mode", "monitor")
    monkeypatch.setattr(settings, "local_upstream_url", "")
    yield sink


@pytest.fixture
def client():
    return TestClient(main.app)


def set_policy(monkeypatch, action, pid="AICP-TEST"):
    monkeypatch.setattr(policy, "evaluate", lambda ev: {"mode": settings.mode, "action": action, "policy_id": pid,
                                                        "policy_version": "t", "reason": "test"})
    monkeypatch.setattr(main, "evaluate", policy.evaluate)


def chat(client, text, **kw):
    return client.post("/v1/chat/completions", headers=ALICE,
                       json={"model": "mock-1", "messages": [{"role": "user", "content": text}], **kw})


def test_passthrough_and_audit(client, wire):
    r = chat(client, "hello there")
    assert r.status_code == 200
    assert r.json()["choices"][0]["message"]["content"] == "You said: hello there"
    types = [e["event_type"] for e in wire.events]
    assert types == ["ai.prompt.submitted", "ai.response.delivered"]
    e = wire.events[0]
    assert e["source"] == "gateway" and e["observation_level"] == "enforced"
    assert e["actor"]["id"] == "alice@example-dib.com"
    assert e["decision"]["mode"] == "monitor" and "prompt_sha256" in e["content"]


def test_monitor_mode_records_but_never_blocks(client, wire, monkeypatch):
    set_policy(monkeypatch, "block", "AICP-001")
    r = chat(client, "CUI//SP-CTI bracket load 400 lbf")
    assert r.status_code == 200
    e = wire.events[0]
    assert e["event_type"] == "ai.dlp.match"
    assert e["decision"]["action"] == "block" and e["decision"]["mode"] == "monitor"


def test_enforce_mode_blocks(client, wire, monkeypatch):
    monkeypatch.setattr(settings, "mode", "enforce")
    set_policy(monkeypatch, "block", "AICP-001")
    r = chat(client, "CUI//SP-CTI bracket load 400 lbf")
    assert r.status_code == 403
    assert r.json()["detail"]["policy_id"] == "AICP-001"
    assert wire.events[0]["event_type"] == "ai.policy.violation"
    assert len(wire.events) == 1  # nothing forwarded, no response event


def test_enforce_mode_masks_and_unmasks(client, wire, monkeypatch):
    monkeypatch.setattr(settings, "mode", "enforce")
    set_policy(monkeypatch, "mask", "AICP-004")
    secret = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWx1234567890"
    r = chat(client, f"my config has api_key = {secret} is that ok")
    assert r.status_code == 200
    # the user gets the real value back...
    assert secret in r.json()["choices"][0]["message"]["content"]
    # ...and the audit trail says masking happened
    assert "masked 1 values" in wire.events[0]["decision"]["reason"]
    assert "unmasked 1 values" in wire.events[1]["decision"]["reason"]


def test_enforce_mode_route_local_without_local_upstream_blocks(client, wire, monkeypatch):
    monkeypatch.setattr(settings, "mode", "enforce")
    set_policy(monkeypatch, "route_local", "AICP-003")
    assert chat(client, "ITAR data").status_code == 403


def test_unknown_key(client, wire, monkeypatch):
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer nope"},
                    json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200 and wire.events[0]["actor"]["id"] == "unknown"
    monkeypatch.setattr(settings, "mode", "enforce")
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer nope"},
                    json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 401


def test_streaming_passthrough_and_egress_audit(client, wire):
    with client.stream("POST", "/v1/chat/completions", headers=ALICE,
                       json={"model": "mock-1", "stream": True, "messages": [{"role": "user", "content": "stream me"}]}) as r:
        assert r.status_code == 200
        text = "".join(json.loads(ln[6:])["choices"][0]["delta"].get("content", "")
                       for ln in r.iter_lines() if ln.startswith("data: ") and ln != "data: [DONE]")
    assert text == "You said: stream me"
    assert [e["event_type"] for e in wire.events] == ["ai.prompt.submitted", "ai.response.delivered"]
    assert wire.events[1]["content"]["response_sha256"]


def test_embeddings_scanned(client, wire):
    r = client.post("/v1/embeddings", headers=ALICE, json={"model": "e", "input": "USML Category VIII test results"})
    assert r.status_code == 200 and r.json()["data"][0]["embedding"]
    assert wire.events[0]["event_type"] == "ai.dlp.match"
    assert wire.events[0]["content"]["dlp_findings"][0]["category"] == "ITAR_TERM"


def test_agent_key_carries_sponsor(client, wire):
    r = client.post("/v1/chat/completions", headers={"Authorization": "Bearer gw-dev-key-ops-agent"},
                    json={"model": "m", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200
    a = wire.events[0]["actor"]
    assert a["type"] == "agent" and a["on_behalf_of"] == "ops-lead@example-dib.com"


def test_events_validate_against_schema(wire, client):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
    from app.ingest import validate  # the governance plane's validator
    chat(client, "hello")
    client.post("/v1/embeddings", headers=ALICE, json={"model": "e", "input": "x"})
    for e in wire.events:
        validate(e)
