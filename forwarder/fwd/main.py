"""Gyrai — SIEM forwarder.

Reads the audit store in sequence order through /api/v1/events/stream, keeps a
checkpoint on disk, and ships each batch to every configured output. A batch is
only checkpointed once *all* outputs accept it, so a SIEM outage causes a delay,
never a gap (AU-5). At-least-once delivery; the event_id is the dedup key.

Config via environment (prefix AICP_FWD_):
  API_URL, INGEST_TOKEN, POLL_SECONDS, BATCH, CHECKPOINT_FILE, OUTPUTS=file,splunk_hec,...
  FILE_PATH
  SPLUNK_URL, SPLUNK_TOKEN, SPLUNK_INDEX, SPLUNK_VERIFY_TLS
  SENTINEL_DCE_URL, SENTINEL_DCR_ID, SENTINEL_STREAM, SENTINEL_TENANT_ID, SENTINEL_CLIENT_ID, SENTINEL_CLIENT_SECRET
  SYSLOG_HOST, SYSLOG_PORT, SYSLOG_PROTOCOL, SYSLOG_TLS
"""
import json
import logging
import os
import sys
import time
from pathlib import Path

import httpx

from .outputs import OUTPUTS, Output

log = logging.getLogger("aicp.forwarder")
E = os.environ.get


def build_outputs() -> list[Output]:
    outs = []
    for name in [n.strip() for n in E("AICP_FWD_OUTPUTS", "file").split(",") if n.strip()]:
        if name == "file":
            outs.append(OUTPUTS["file"](E("AICP_FWD_FILE_PATH", "./aicp-forwarded.jsonl")))
        elif name == "splunk_hec":
            outs.append(OUTPUTS["splunk_hec"](E("AICP_FWD_SPLUNK_URL"), E("AICP_FWD_SPLUNK_TOKEN"), E("AICP_FWD_SPLUNK_INDEX", ""),
                                              verify=E("AICP_FWD_SPLUNK_VERIFY_TLS", "true").lower() != "false"))
        elif name == "sentinel":
            outs.append(OUTPUTS["sentinel"](E("AICP_FWD_SENTINEL_DCE_URL"), E("AICP_FWD_SENTINEL_DCR_ID"),
                                            E("AICP_FWD_SENTINEL_STREAM", "Custom-AICPAudit_CL"), E("AICP_FWD_SENTINEL_TENANT_ID"),
                                            E("AICP_FWD_SENTINEL_CLIENT_ID"), E("AICP_FWD_SENTINEL_CLIENT_SECRET")))
        elif name == "syslog_cef":
            outs.append(OUTPUTS["syslog_cef"](E("AICP_FWD_SYSLOG_HOST"), int(E("AICP_FWD_SYSLOG_PORT", "514")),
                                              E("AICP_FWD_SYSLOG_PROTOCOL", "tcp"), E("AICP_FWD_SYSLOG_TLS", "false").lower() == "true"))
        else:
            log.error("unknown output %r; valid: %s", name, ", ".join(OUTPUTS))
            sys.exit(2)
    return outs


class Forwarder:
    def __init__(self, api_url: str, token: str, outputs: list[Output], checkpoint: Path, batch: int = 500):
        self.api_url, self.token, self.outputs, self.checkpoint, self.batch = api_url.rstrip("/"), token, outputs, checkpoint, batch
        self.after_seq = self._load()

    def _load(self) -> int:
        try:
            return int(json.loads(self.checkpoint.read_text())["after_seq"])
        except (OSError, ValueError, KeyError):
            return 0

    def _save(self):
        self.checkpoint.parent.mkdir(parents=True, exist_ok=True)
        self.checkpoint.write_text(json.dumps({"after_seq": self.after_seq}))

    def fetch(self) -> tuple[list[dict], int]:
        r = httpx.get(f"{self.api_url}/api/v1/events/stream", params={"after_seq": self.after_seq, "limit": self.batch},
                      headers={"Authorization": f"Bearer {self.token}"}, timeout=30.0)
        r.raise_for_status()
        d = r.json()
        return d["events"], d["next_after_seq"]

    def run_once(self) -> int:
        """Forward everything new. Returns number of events shipped."""
        shipped = 0
        while True:
            try:
                events, nxt = self.fetch()
            except httpx.HTTPError as e:
                log.warning("governance plane unreachable: %s", e)
                return shipped
            if not events:
                return shipped
            for e in events:
                e.pop("seq", None)
            ok = all(o.send(events) for o in self.outputs)
            if not ok:
                log.warning("an output rejected the batch; will retry (checkpoint stays at %d)", self.after_seq)
                return shipped
            self.after_seq = nxt
            self._save()
            shipped += len(events)
            log.info("forwarded %d events (through seq %d) to %s", len(events), nxt, ",".join(o.name for o in self.outputs))
            if len(events) < self.batch:
                return shipped


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    fwd = Forwarder(E("AICP_FWD_API_URL", "http://localhost:8000"), E("AICP_FWD_INGEST_TOKEN", "dev-ingest-token-change-me"),
                    build_outputs(), Path(E("AICP_FWD_CHECKPOINT_FILE", "./forwarder.checkpoint.json")),
                    int(E("AICP_FWD_BATCH", "500")))
    poll = float(E("AICP_FWD_POLL_SECONDS", "10"))
    log.info("forwarder starting; outputs=%s poll=%ss from seq %d", [o.name for o in fwd.outputs], poll, fwd.after_seq)
    while True:
        fwd.run_once()
        if poll <= 0:
            break
        time.sleep(poll)


if __name__ == "__main__":
    main()
