"""API tests: ingest, validation, the hash chain, authentication, inventory editing and
the evidence report. They run the real FastAPI app in-process against a throwaway SQLite
file that is rebuilt before every test."""
import os
import uuid
from datetime import datetime, timezone

import pytest

os.environ["AICP_DATABASE_URL"] = "sqlite:///./test_aicp.db"
os.environ["AICP_OPA_ENABLED"] = "false"
os.environ["AICP_ADMIN_PASSWORD"] = "test-admin-password-123"
os.environ["AICP_SESSION_SECRET"] = "test-secret"

from app.auth import bootstrap_admin  # noqa: E402
from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

TOKEN = {"Authorization": "Bearer dev-ingest-token-change-me"}


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    bootstrap_admin()
    yield


@pytest.fixture
def anon():
    """Client with no session."""
    with TestClient(app) as c:
        yield c


@pytest.fixture
def client(anon):
    """Client logged in as admin."""
    r = anon.post("/login", data={"username": "admin", "password": "test-admin-password-123", "next": "/"}, follow_redirects=False)
    assert r.status_code == 302, r.text
    return anon


def ev(**over):
    base = {
        "schema_version": "1.0.0",
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "collector.file",
        "observation_level": "content_visible",
        "event_type": "ai.prompt.submitted",
        "actor": {"type": "human", "id": "a@example.com"},
        "target": {"ai_system": "openai.chatgpt", "hosting": "external_saas"},
    }
    base.update(over)
    return base


def test_ingest_requires_token(client):
    assert client.post("/api/v1/events", json=[ev()]).status_code == 401


def test_ingest_and_inventory(client):
    r = client.post("/api/v1/events", json=[ev(), ev(target={"ai_system": "m365.copilot", "hosting": "cloud_tenant"})], headers=TOKEN)
    assert r.status_code == 202 and r.json()["accepted"] == 2
    systems = {s["key"]: s for s in client.get("/api/v1/systems").json()}
    assert set(systems) == {"openai.chatgpt", "m365.copilot", "aicp.console"}  # console login is audited too
    assert systems["openai.chatgpt"]["governance_state"] == "observed"


def test_schema_rejects_bad_event(client):
    bad = ev(event_type="not.a.real.type")
    r = client.post("/api/v1/events", json=[bad], headers=TOKEN)
    assert r.json()["accepted"] == 0 and "event_type" in r.json()["rejected"][0]["error"]


def test_idempotent(client):
    e = ev()
    client.post("/api/v1/events", json=[e], headers=TOKEN)
    client.post("/api/v1/events", json=[e], headers=TOKEN)
    assert client.get("/api/v1/events/stats").json()["by_event_type"]["ai.prompt.submitted"] == 1


def test_hash_chain_verifies(client):
    client.post("/api/v1/events", json=[ev(), ev(), ev()], headers=TOKEN)
    r = client.get("/api/v1/events/integrity").json()
    assert r["ok"] and r["checked"] == 4  # 3 events + the login event


def test_enforced_event_marks_system_governed(client):
    client.post("/api/v1/events", json=[ev(source="gateway", observation_level="enforced",
                                           decision={"mode": "enforce", "action": "mask", "policy_id": "AICP-004", "policy_version": "abc"})], headers=TOKEN)
    s = next(x for x in client.get("/api/v1/systems").json() if x["key"] == "openai.chatgpt")
    assert s["governance_state"] == "governed"


def test_declare_and_patch_system(client):
    r = client.post("/api/v1/systems", json={"key": "otter.ai", "display_name": "Otter.ai", "hosting": "external_saas"})
    assert r.status_code == 201 and r.json()["governance_state"] == "declared"
    r = client.patch("/api/v1/systems/otter.ai", json={"approved": False, "cui_in_scope": False})
    assert r.json()["approved"] is False


def test_evidence_report_reflects_levels(client):
    client.post("/api/v1/events", json=[ev(event_type="ai.dlp.match",
                                           content={"dlp_findings": [{"category": "CUI_MARKING", "detector": "regex.cui_banner", "count": 1}]})], headers=TOKEN)
    rep = client.get("/evidence/report.json").json()
    c313 = next(c for c in rep["controls"] if c["id"] == "3.1.3")
    assert c313["status"] == "evidence_available"
    assert c313["strength"] == "partial"          # content_visible, not enforced -> never claims "full"
    assert rep["summary"]["dlp_count"] == 1
    md = client.get("/evidence/report.md").text
    assert "3.1.3" in md and "Appendix A" in md


def test_console_pages_render(client):
    client.post("/api/v1/events", json=[ev()], headers=TOKEN)
    for path in ["/", "/inventory", "/events", "/evidence"]:
        assert client.get(path).status_code == 200


# ---------- authentication ----------

def test_console_redirects_to_login_when_anonymous(anon):
    r = anon.get("/inventory", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("/login")


def test_api_requires_session(anon):
    assert anon.get("/api/v1/systems").status_code == 401
    assert anon.patch("/api/v1/systems/x", json={"approved": True}).status_code == 401


def test_ingest_still_uses_machine_token(anon):
    assert anon.post("/api/v1/events", json=[ev()], headers=TOKEN).status_code == 202


def test_bad_password_rejected_and_audited(anon, client):
    r = anon.post("/login", data={"username": "admin", "password": "wrong", "next": "/"})
    assert r.status_code == 401
    events = client.get("/api/v1/events?event_type=ai.admin.change").json()
    reasons = [e["decision"]["reason"] for e in events]
    assert any("bad password" in x for x in reasons)
    assert any(x.startswith("login: ok") for x in reasons)


def test_logout_clears_session(client):
    client.post("/logout", follow_redirects=False)
    assert client.get("/api/v1/systems").status_code == 401


def test_password_change_policy(client):
    r = client.post("/account/password", data={"current": "test-admin-password-123", "new": "short", "confirm": "short"})
    assert r.status_code == 400
    good = {"current": "test-admin-password-123", "new": "a-much-longer-passphrase", "confirm": "a-much-longer-passphrase"}
    r = client.post("/account/password", data=good, follow_redirects=False)
    assert r.status_code == 302
    client.post("/logout", follow_redirects=False)
    r = client.post("/login", data={"username": "admin", "password": "a-much-longer-passphrase", "next": "/"}, follow_redirects=False)
    assert r.status_code == 302


def test_lockout_after_repeated_failures(anon):
    for _ in range(10):
        anon.post("/login", data={"username": "admin", "password": "wrong", "next": "/"})
    r = anon.post("/login", data={"username": "admin", "password": "test-admin-password-123", "next": "/"}, follow_redirects=False)
    assert r.status_code == 401  # locked even with the right password


# ---------- inventory editing ----------

def test_inventory_edit_form_roundtrip_and_audit(client):
    client.post("/api/v1/events", json=[ev()], headers=TOKEN)
    r = client.get("/inventory/openai.chatgpt")
    assert r.status_code == 200 and "Can CUI reach this system?" in r.text
    r = client.post("/inventory/openai.chatgpt", data={
        "display_name": "ChatGPT (web)", "vendor": "OpenAI", "hosting": "external_saas",
        "approved": "no", "cui_in_scope": "no", "owner": "CISO", "notes": "Blocked for CUI by policy."}, follow_redirects=False)
    assert r.status_code == 303
    s = next(x for x in client.get("/api/v1/systems").json() if x["key"] == "openai.chatgpt")
    assert s["approved"] is False and s["cui_in_scope"] is False and s["owner"] == "CISO"
    changes = client.get("/api/v1/events?event_type=ai.admin.change&ai_system=openai.chatgpt").json()
    assert changes and "approved=False" in changes[0]["decision"]["reason"]


def test_declare_form(client):
    r = client.post("/inventory/new", data={"key": "Adobe.Acrobat-AI", "display_name": "Acrobat AI Assistant", "vendor": "Adobe",
                                           "hosting": "external_saas", "approved": "unknown", "cui_in_scope": "unknown",
                                           "owner": "", "notes": ""}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/inventory/adobe.acrobat-ai"
    s = next(x for x in client.get("/api/v1/systems").json() if x["key"] == "adobe.acrobat-ai")
    assert s["governance_state"] == "declared" and s["approved"] is None
    # declaring twice is rejected
    assert client.post("/inventory/new", data={"key": "adobe.acrobat-ai"}).status_code == 409


def test_default_ingest_token_warns(caplog):
    """The API logs a warning at startup while the ingest token is the development default."""
    from app import main as api_main
    from app.config import settings
    old = settings.ingest_token
    try:
        settings.ingest_token = api_main.DEFAULT_INGEST_TOKEN
        with caplog.at_level("WARNING", logger="aicp.api"):
            assert api_main.warn_if_default_token() is True
        assert "development default" in caplog.text
        settings.ingest_token = "a-real-secret"
        assert api_main.warn_if_default_token() is False
    finally:
        settings.ingest_token = old
