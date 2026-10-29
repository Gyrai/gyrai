"""Audit emission. Non-blocking: events go on an in-memory queue and a background
thread posts them to the governance plane in batches. If the governance plane is down
they spill to a local JSONL file (AU-5: never lose the record, never stall the
request). The schema is the same one collectors use."""
import json
import logging
import queue
import threading
import time
import uuid
from datetime import datetime, timezone

import httpx

from .config import settings

log = logging.getLogger("aicp.gateway.audit")


class AuditSink:
    """Where audit events go. Subclasses implement emit(); the gateway only ever
    calls sink().emit(event), so tests can swap in ListSink without a network."""

    def emit(self, event: dict) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class ListSink(AuditSink):
    """Keeps events in a list so tests can assert on exactly what was audited."""
    def __init__(self):
        self.events: list[dict] = []

    def emit(self, event: dict) -> None:
        self.events.append(event)


class HttpSink(AuditSink):
    """Production sink. emit() only enqueues, so a slow or dead governance plane can
    never delay a user request. A daemon thread drains the queue and posts events in
    batches (default 50 events or one second, whichever comes first)."""

    def __init__(self, api_url: str, token: str, fallback: str, batch: int = 50, flush_s: float = 1.0):
        self.api_url, self.token, self.fallback = api_url.rstrip("/"), token, fallback
        self.batch, self.flush_s = batch, flush_s
        self.q: queue.Queue = queue.Queue(maxsize=10000)
        self._t = threading.Thread(target=self._worker, daemon=True)
        self._t.start()

    def emit(self, event: dict) -> None:
        """Queue an event. If the queue is full, write it to the fallback file instead of dropping it."""
        try:
            self.q.put_nowait(event)
        except queue.Full:
            self._spill([event], "QUEUE_FULL")

    def flush(self, timeout: float = 5.0) -> None:
        """Wait (best effort) for queued events to be sent. Used by tests and shutdown."""
        deadline = time.time() + timeout
        while not self.q.empty() and time.time() < deadline:
            time.sleep(0.05)
        time.sleep(self.flush_s + 0.2)

    def _worker(self):
        """Background loop: collect events and send a batch when it is full or old enough."""
        buf, last = [], time.time()
        while True:
            try:
                buf.append(self.q.get(timeout=0.2))
            except queue.Empty:
                pass
            if buf and (len(buf) >= self.batch or time.time() - last >= self.flush_s):
                self._send(buf)
                buf, last = [], time.time()

    def _send(self, events: list[dict]):
        """POST one batch to the governance plane. Any failure spills the whole batch to disk."""
        try:
            r = httpx.post(f"{self.api_url}/api/v1/events", json=events,
                           headers={"Authorization": f"Bearer {self.token}"}, timeout=10.0)
            r.raise_for_status()
            rej = r.json().get("rejected", [])
            for x in rej:
                log.warning("governance plane rejected %s: %s", x.get("event_id"), x.get("error"))
        except Exception as e:  # noqa: BLE001
            log.warning("governance plane unreachable (%s); spilling %d events", e, len(events))
            self._spill(events, "GOVERNANCE_PLANE_UNREACHABLE")

    def _spill(self, events: list[dict], reason: str):
        """Append events to the fallback JSONL file, tagged with why and when they were spilled.
        The file is the record of last resort when the governance plane is unreachable."""
        with open(self.fallback, "a") as f:
            for e in events:
                e = {**e, "_spill": {"reason": reason, "at": datetime.now(timezone.utc).isoformat()}}
                f.write(json.dumps(e) + "\n")


def new_event(event_type: str, actor: dict, target: dict, **extra) -> dict:
    """Build an audit event that follows schemas/audit-event.schema.json.

    Extra keyword arguments (content, decision, ...) are added when they are not None.
    Events from the gateway are marked observation_level "enforced" because the gateway
    sits in the request path, unlike collectors that only observe after the fact.
    """
    ev = {
        "schema_version": "1.0.0",
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "gateway",
        "observation_level": "enforced",
        "event_type": event_type,
        "actor": actor,
        "target": target,
    }
    ev.update({k: v for k, v in extra.items() if v is not None})
    return ev


_default: AuditSink | None = None


def sink() -> AuditSink:
    """Return the process-wide sink, creating the HTTP sink on first use."""
    global _default
    if _default is None:
        _default = HttpSink(settings.api_url, settings.ingest_token, settings.fallback_log)
    return _default


def set_sink(s: AuditSink) -> None:
    """Replace the process-wide sink (tests install a ListSink here)."""
    global _default
    _default = s
