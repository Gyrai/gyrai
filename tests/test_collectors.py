"""Collector tests: the content scanner (DLP) and the file collector."""
import json
from pathlib import Path

from aicp_collectors.base import stable_event_id
from aicp_collectors.dlp import scan
from aicp_collectors.file_collector import FileCollector

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "sample-events.jsonl"


def test_dlp_detects_markings():
    cats = {f["category"] for f in scan("CUI//SP-CTI see DISTRIBUTION STATEMENT D, CAGE code 1AB23, ITAR data")}
    assert {"CUI_MARKING", "DISTRIBUTION_STATEMENT", "CAGE_CODE", "ITAR_TERM"} <= cats


def test_dlp_clean_text():
    assert scan("Summarize the standup notes.") == []


def test_dlp_secret():
    assert any(f["category"] == "SECRET" for f in scan("api_key = sk-proj-AbCdEfGhIjKlMnOpQrStUvWx1234567890"))


def test_stable_ids():
    assert stable_event_id("collector.m365", "abc") == stable_event_id("collector.m365", "abc")
    assert stable_event_id("collector.m365", "abc") != stable_event_id("collector.file", "abc")


def test_file_collector_normalizes_samples(tmp_path):
    c = FileCollector(str(SAMPLES), api_url="http://x", token="t", state_dir=tmp_path, dry_run=True)
    events = [c.normalize(r) for r in c.fetch(None)]
    assert len(events) == 14
    assert all(e["schema_version"] == "1.0.0" for e in events)
    flagged = [e for e in events if e.get("content", {}).get("dlp_findings")]
    assert len(flagged) >= 5
    # raw text never leaves the collector
    assert not any("text" in e or "text" in e.get("content", {}) for e in events)
    json.dumps(events)  # serializable
