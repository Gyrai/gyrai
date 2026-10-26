import os
import uuid
from datetime import datetime, timezone

import pytest

os.environ["AICP_DATABASE_URL"] = "sqlite:///./test_aicp.db"
os.environ["AICP_OPA_ENABLED"] = "false"

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

TOKEN = {"Authorization": "Bearer dev-ingest-token-change-me"}


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


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
    assert set(systems) == {"openai.chatgpt", "m365.copilot"}
    assert systems["openai.chatgpt"]["governance_state"] == "observed"


def test_schema_rejects_bad_event(client):
    bad = ev(event_type="not.a.real.type")
    r = client.post("/api/v1/events", json=[bad], headers=TOKEN)
    assert r.json()["accepted"] == 0 and "event_type" in r.json()["rejected"][0]["error"]


def test_idempotent(client):
    e = ev()
    client.post("/api/v1/events", json=[e], headers=TOKEN)
    client.post("/api/v1/events", json=[e], headers=TOKEN)
    assert client.get("/api/v1/events/stats").json()["total_events"] == 1


def test_hash_chain_verifies(client):
    client.post("/api/v1/events", json=[ev(), ev(), ev()], headers=TOKEN)
    r = client.get("/api/v1/events/integrity").json()
    assert r["ok"] and r["checked"] == 3


def test_enforced_event_marks_system_governed(client):
    client.post("/api/v1/events", json=[ev(source="gateway", observation_level="enforced",
                                           decision={"mode": "enforce", "action": "mask", "policy_id": "AICP-004", "policy_version": "abc"})], headers=TOKEN)
    s = client.get("/api/v1/systems").json()[0]
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
