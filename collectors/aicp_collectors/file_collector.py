"""File collector: reads a JSONL file of *already-normalized* schema events or of
simple generic records, scans any `text` field with the DLP layer, and posts them.

Two uses:
  1. Demo/sample data (samples/sample-events.jsonl) so the console has something to show.
  2. Customer log exports that don't yet have a dedicated collector: export to JSONL,
     map the fields with a tiny jq script, feed it here.
"""
import json
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path

from .base import Collector, sha256
from .dlp import scan


class FileCollector(Collector):
    source = "collector.file"
    observation_level = "content_visible"

    def __init__(self, path: str, **kw):
        super().__init__(**kw)
        self.path = Path(path)

    def fetch(self, since: datetime) -> Iterable[dict]:
        with self.path.open() as f:
            for i, line in enumerate(f):
                line = line.strip()
                if line:
                    rec = json.loads(line)
                    rec.setdefault("_line", i)
                    yield rec

    def normalize(self, rec: dict) -> dict | None:
        # Already a schema event? Pass through, but scan text if present and strip it.
        if rec.get("schema_version") == "1.0.0":
            return rec
        ts = datetime.fromisoformat(rec.get("timestamp") or datetime.now(timezone.utc).isoformat())
        ev = self.base_event(rec.get("event_type", "ai.prompt.submitted"), ts, rec.get("id") or f"{self.path.name}:{rec['_line']}")
        ev["observation_level"] = rec.get("observation_level", self.observation_level)
        ev["actor"] = {"type": rec.get("actor_type", "human"), "id": rec.get("user", "")}
        ev["target"] = {
            "ai_system": rec.get("ai_system", "unknown"),
            "hosting": rec.get("hosting", "unknown"),
        }
        if rec.get("model"):
            ev["target"]["model_id"] = rec["model"]
        if rec.get("tool"):
            ev["target"]["tool_name"] = rec["tool"]
        text = rec.get("text")
        if text:
            findings = scan(text)
            ev["content"] = {"prompt_sha256": sha256(text), "prompt_tokens": max(1, len(text) // 4)}
            if findings:
                ev["content"]["dlp_findings"] = findings
                ev["event_type"] = "ai.dlp.match"
        if rec.get("decision"):
            ev["decision"] = rec["decision"]
        return ev
