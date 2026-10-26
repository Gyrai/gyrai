"""Forwarder tests against the real API (in-process) and a mock Splunk HEC + a real local syslog socket."""
import json
import os
import socket
import sys
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

os.environ.setdefault("AICP_DATABASE_URL", "sqlite:///./test_aicp.db")
os.environ.setdefault("AICP_OPA_ENABLED", "false")
os.environ.setdefault("AICP_ADMIN_PASSWORD", "test-admin-password-123")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "forwarder"))

from app.db import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from fwd.main import Forwarder  # noqa: E402
from fwd.outputs import FileOutput, SplunkHECOutput, SyslogCEFOutput  # noqa: E402

TOKEN = "dev-ingest-token-change-me"


def ev(i):
    return {"schema_version": "1.0.0", "event_id": str(uuid.uuid4()), "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "collector.file", "observation_level": "content_visible", "event_type": "ai.dlp.match",
            "actor": {"type": "human", "id": f"u{i}@x.com", "ip": "10.0.0.5"},
            "target": {"ai_system": "openai.chatgpt", "hosting": "external_saas"},
            "content": {"dlp_findings": [{"category": "CUI_MARKING", "detector": "t", "count": 1}]},
            "decision": {"mode": "monitor", "action": "block", "policy_id": "AICP-001", "policy_version": "t", "reason": "r=1"}}


@pytest.fixture
def api(monkeypatch):
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    with TestClient(app) as c:
        c.post("/api/v1/events", json=[ev(i) for i in range(7)], headers={"Authorization": f"Bearer {TOKEN}"})
        # route the forwarder's httpx.get calls into the in-process app
        def fake_get(url, **kw):
            return c.get(url.replace("http://api", ""), **kw)
        monkeypatch.setattr(httpx, "get", fake_get)
        yield c


def test_file_output_and_checkpoint(api, tmp_path):
    out = tmp_path / "out.jsonl"
    f = Forwarder("http://api", TOKEN, [FileOutput(str(out))], tmp_path / "cp.json", batch=3)
    assert f.run_once() == 7
    lines = out.read_text().splitlines()
    assert len(lines) == 7 and "seq" not in json.loads(lines[0])
    assert json.loads((tmp_path / "cp.json").read_text())["after_seq"] == 7
    # nothing new -> nothing shipped; new events -> only those
    assert f.run_once() == 0
    api.post("/api/v1/events", json=[ev(99)], headers={"Authorization": f"Bearer {TOKEN}"})
    assert f.run_once() == 1
    # a fresh forwarder resumes from the checkpoint, not from zero
    f2 = Forwarder("http://api", TOKEN, [FileOutput(str(out))], tmp_path / "cp.json", batch=3)
    assert f2.after_seq == 8 and f2.run_once() == 0


def test_failed_output_does_not_advance_checkpoint(api, tmp_path):
    class Flaky(FileOutput):
        calls = 0

        def send(self, events):
            Flaky.calls += 1
            return False if Flaky.calls == 1 else super().send(events)

    f = Forwarder("http://api", TOKEN, [Flaky(str(tmp_path / "o.jsonl"))], tmp_path / "cp.json", batch=100)
    assert f.run_once() == 0 and f.after_seq == 0      # first attempt rejected, nothing lost
    assert f.run_once() == 7 and f.after_seq == 7      # retry succeeds


def test_splunk_hec_payload(api, tmp_path, monkeypatch):
    captured = {}

    def fake_post(url, content=None, headers=None, **kw):
        captured["url"], captured["auth"], captured["lines"] = url, headers["Authorization"], content.splitlines()
        return httpx.Response(200, json={"text": "Success", "code": 0})
    monkeypatch.setattr(httpx, "post", fake_post)
    f = Forwarder("http://api", TOKEN, [SplunkHECOutput("https://splunk.example:8088", "hec-token", index="ai")], tmp_path / "cp.json")
    assert f.run_once() == 7
    assert captured["url"].endswith("/services/collector/event") and captured["auth"] == "Splunk hec-token"
    rec = json.loads(captured["lines"][0])
    assert rec["index"] == "ai" and rec["sourcetype"] == "aicp:audit" and rec["event"]["event_type"] == "ai.dlp.match"


def test_syslog_cef_over_tcp(api, tmp_path):
    received = []
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def accept():
        conn, _ = srv.accept()
        with conn:
            buf = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
        received.extend(buf.decode().splitlines())
    t = threading.Thread(target=accept, daemon=True)
    t.start()
    f = Forwarder("http://api", TOKEN, [SyslogCEFOutput("127.0.0.1", port, "tcp")], tmp_path / "cp.json")
    assert f.run_once() == 7
    t.join(5)
    srv.close()
    assert len(received) == 7
    assert "CEF:0|ConsultantWorks|AIControlPlane|1.0|ai.dlp.match|" in received[0]
    assert "cs2=AICP-001" in received[0] and "act=block" in received[0] and "msg=r\\=1" in received[0]  # '=' escaped
