"""Collector framework. A collector is anything that turns an upstream log into
schema events and posts them to the API. Adding a source = subclass + one method.

    class MyCollector(Collector):
        source = "collector.something"
        observation_level = "metadata_only"
        def fetch(self, since) -> Iterable[dict]:   # yield upstream records
        def normalize(self, record) -> dict | None: # return a schema event

Run with:  python -m aicp_collectors.run <name> --api http://localhost:8000 --token ...
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

log = logging.getLogger("aicp.collector")
NAMESPACE = uuid.UUID("6c2a0f6e-7f3a-4e1c-9a1e-a1c900000001")


def stable_event_id(source: str, raw_ref: str) -> str:
    """Deterministic UUID from the upstream record ID, so re-runs don't duplicate."""
    return str(uuid.uuid5(NAMESPACE, f"{source}:{raw_ref}"))


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class Collector(ABC):
    source: str = "collector.file"
    observation_level: str = "metadata_only"

    def __init__(self, api_url: str, token: str, state_dir: Path | None = None, dry_run: bool = False):
        self.api_url = api_url.rstrip("/")
        self.token = token
        self.dry_run = dry_run
        self.state_dir = state_dir or Path.home() / ".aicp"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / f"{self.source}.state.json"

    # ---- state (high-water mark) ----
    def load_since(self, default_hours: int = 24) -> datetime:
        if self.state_file.exists():
            return datetime.fromisoformat(json.loads(self.state_file.read_text())["since"])
        return datetime.now(timezone.utc) - timedelta(hours=default_hours)

    def save_since(self, ts: datetime) -> None:
        self.state_file.write_text(json.dumps({"since": ts.isoformat()}))

    # ---- to implement ----
    @abstractmethod
    def fetch(self, since: datetime) -> Iterable[dict]: ...

    @abstractmethod
    def normalize(self, record: dict) -> dict | None: ...

    # ---- shared ----
    def base_event(self, event_type: str, ts: datetime, raw_ref: str) -> dict:
        return {
            "schema_version": "1.0.0",
            "event_id": stable_event_id(self.source, raw_ref),
            "timestamp": ts.astimezone(timezone.utc).isoformat(),
            "source": self.source,
            "observation_level": self.observation_level,
            "event_type": event_type,
            "actor": {"type": "unknown"},
            "target": {"ai_system": "unknown"},
            "raw_ref": raw_ref,
        }

    def post(self, events: list[dict]) -> dict:
        if not events:
            return {"accepted": 0, "rejected": []}
        if self.dry_run:
            for e in events:
                print(json.dumps(e))
            return {"accepted": len(events), "rejected": [], "dry_run": True}
        last_err: Exception | None = None
        for attempt in range(10):
            try:
                r = httpx.post(
                    f"{self.api_url}/api/v1/events",
                    json=events,
                    headers={"Authorization": f"Bearer {self.token}"},
                    timeout=30.0,
                )
                r.raise_for_status()
                return r.json()
            except httpx.HTTPError as e:  # governance plane not up yet; wait and retry
                last_err = e
                log.warning("post failed (%s); retry %d/10", e, attempt + 1)
                time.sleep(3)
        raise RuntimeError(f"governance plane unreachable after retries: {last_err}")

    def run_once(self, batch_size: int = 200) -> dict:
        since = self.load_since()
        newest = since
        batch, totals = [], {"accepted": 0, "rejected": 0}
        for rec in self.fetch(since):
            ev = self.normalize(rec)
            if not ev:
                continue
            batch.append(ev)
            ts = datetime.fromisoformat(ev["timestamp"])
            newest = max(newest, ts)
            if len(batch) >= batch_size:
                res = self.post(batch)
                totals["accepted"] += res["accepted"]
                totals["rejected"] += len(res["rejected"])
                for rej in res["rejected"]:
                    log.warning("rejected %s: %s", rej["event_id"], rej["error"])
                batch = []
        res = self.post(batch)
        totals["accepted"] += res["accepted"]
        totals["rejected"] += len(res["rejected"])
        for rej in res["rejected"]:
            log.warning("rejected %s: %s", rej["event_id"], rej["error"])
        if not self.dry_run:
            self.save_since(newest)
        log.info("%s: accepted=%d rejected=%d since=%s", self.source, totals["accepted"], totals["rejected"], since.isoformat())
        return totals
