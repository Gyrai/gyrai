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
    def emit(self, event: dict) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class ListSink(AuditSink):
    """For tests."""
    def __init__(self):
        self.events: list[dict] = []

    def emit(self, event: dict) -> None:
        self.events.append(event)


class HttpSink(AuditSink):
    def __init__(self, api_url: str, token: str, fallback: str, batch: int = 50, flush_s: float = 1.0):
        self.api_url, self.token, self.fallback = api_url.rstrip("/"), token, fallback
        self.batch, self.flush_s = batch, flush_s
        self.q: queue.Queue = queue.Queue(maxsize=10000)
        self._t = threading.Thread(target=self._worker, daemon=True)
        self._t.start()

    def emit(self, event: dict) -> None:
        try:
            self.q.put_nowait(event)
        except queue.Full:
            self._spill([event], "QUEUE_FULL")

    def flush(self, timeout: float = 5.0) -> None:
        deadline = time.time() + timeout
        while not self.q.empty() and time.time() < deadline:
            time.sleep(0.05)
        time.sleep(self.flush_s + 0.2)

    def _worker(self):
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
        with open(self.fallback, "a") as f:
            for e in events:
                e = {**e, "_spill": {"reason": reason, "at": datetime.now(timezone.utc).isoformat()}}
                f.write(json.dumps(e) + "\n")


def new_event(event_type: str, actor: dict, target: dict, **extra) -> dict:
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
    global _default
    if _default is None:
        _default = HttpSink(settings.api_url, settings.ingest_token, settings.fallback_log)
    return _default


def set_sink(s: AuditSink) -> None:
    global _default
    _default = s
