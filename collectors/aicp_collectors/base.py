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
# Fixed namespace for stable_event_id(). Never change it: doing so would give every
# already-collected record a new id and cause duplicates on the next run.
NAMESPACE = uuid.UUID("6c2a0f6e-7f3a-4e1c-9a1e-a1c900000001")


def stable_event_id(source: str, raw_ref: str) -> str:
    """Deterministic UUID from the upstream record ID, so re-runs don't duplicate."""
    return str(uuid.uuid5(NAMESPACE, f"{source}:{raw_ref}"))


def sha256(text: str) -> str:
    """Hex SHA-256 of the text. Collectors store hashes of prompts and responses, never the text."""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


class Collector(ABC):
    """Base class for log collectors.

    Subclasses set `source` and `observation_level` and implement fetch() and normalize().
    run_once() does the rest: read the high-water mark, fetch new records, convert them to
    schema events, post them in batches and save the new mark.
    """

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
        """When the last run stopped. First run looks back `default_hours` (24 by default)."""
        if self.state_file.exists():
            return datetime.fromisoformat(json.loads(self.state_file.read_text())["since"])
        return datetime.now(timezone.utc) - timedelta(hours=default_hours)

    def save_since(self, ts: datetime) -> None:
        """Remember the newest event time seen, so the next run only fetches newer records."""
        self.state_file.write_text(json.dumps({"since": ts.isoformat()}))

    # ---- to implement ----
    @abstractmethod
    def fetch(self, since: datetime) -> Iterable[dict]:
        """Yield raw upstream records newer than `since`."""


    @abstractmethod
    def normalize(self, record: dict) -> dict | None:
        """Convert one raw record to a schema event, or return None to skip it."""


    # ---- shared ----
    def base_event(self, event_type: str, ts: datetime, raw_ref: str) -> dict:
        """Start a schema event with the required fields filled in. Subclasses then set the
        real actor, target and content. `raw_ref` is the upstream record's own id; it makes the
        event_id repeatable, so collecting the same record twice does not create a duplicate."""
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
        """Send events to the API, retrying up to 10 times three seconds apart (the API may still be
        starting). With dry_run, print them instead. Returns the API's accepted/rejected summary."""
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
        """Collect once: fetch, normalize, post in batches, then advance the high-water mark.
        The mark moves only after posting succeeds, so a failed run is retried from the same point."""
        since = self.load_since()
        newest = since
        batch, totals = [], {"accepted": 0, "rejected": 0}
        # Stream records through in batches so memory stays flat even with a large backlog.
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
        # A dry run must not move the high-water mark.
        if not self.dry_run:
            self.save_since(newest)
        log.info("%s: accepted=%d rejected=%d since=%s", self.source, totals["accepted"], totals["rejected"], since.isoformat())
        return totals
