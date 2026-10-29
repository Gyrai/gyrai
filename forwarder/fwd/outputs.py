"""SIEM output adapters. Each takes a list of schema events and returns True on success.
Add a SIEM = add a class here and a name in OUTPUTS."""
import json
import logging
import socket
import ssl
from datetime import datetime, timezone

import httpx

log = logging.getLogger("aicp.forwarder")


class Output:
    """Interface every SIEM adapter follows: send() takes a list of schema events and returns
    True only if the destination accepted them all. Returning False makes the forwarder retry the
    same batch later, so adapters must not raise for ordinary network errors."""
    name = "base"

    def send(self, events: list[dict]) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


class FileOutput(Output):
    """JSONL file. Useful for air-gapped sites (sneakernet to the SOC) and for tests."""
    name = "file"

    def __init__(self, path: str):
        self.path = path

    def send(self, events):
        with open(self.path, "a") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
        return True


class SplunkHECOutput(Output):
    """Splunk HTTP Event Collector. Sends one JSON line per event with the original event time."""
    name = "splunk_hec"

    def __init__(self, url: str, token: str, index: str = "", sourcetype: str = "aicp:audit", verify: bool = True):
        self.url, self.token, self.index, self.sourcetype, self.verify = url.rstrip("/"), token, index, sourcetype, verify

    def send(self, events):
        lines = []
        for e in events:
            rec = {"time": datetime.fromisoformat(e["timestamp"]).timestamp(), "sourcetype": self.sourcetype,
                   "source": "aicp", "event": e}
            if self.index:
                rec["index"] = self.index
            lines.append(json.dumps(rec))
        try:
            r = httpx.post(f"{self.url}/services/collector/event", content="\n".join(lines),
                           headers={"Authorization": f"Splunk {self.token}"}, timeout=15.0, verify=self.verify)
            if r.status_code != 200:
                log.warning("splunk HEC %s: %s", r.status_code, r.text[:200])
            return r.status_code == 200
        except httpx.HTTPError as e:
            log.warning("splunk HEC error: %s", e)
            return False


class SentinelOutput(Output):
    """Microsoft Sentinel via the Logs Ingestion API (DCE + DCR). Needs an Entra app with
    'Monitoring Metrics Publisher' on the DCR. Table is a custom log, e.g. AICPAudit_CL."""
    name = "sentinel"

    def __init__(self, dce_url: str, dcr_id: str, stream: str, tenant_id: str, client_id: str, client_secret: str):
        self.dce_url, self.dcr_id, self.stream = dce_url.rstrip("/"), dcr_id, stream
        self.tenant_id, self.client_id, self.client_secret = tenant_id, client_id, client_secret
        self._token = None

    def _auth(self) -> str:
        if self._token:
            return self._token
        r = httpx.post(f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token", data={
            "client_id": self.client_id, "client_secret": self.client_secret,
            "scope": "https://monitor.azure.com/.default", "grant_type": "client_credentials"}, timeout=15.0)
        r.raise_for_status()
        self._token = r.json()["access_token"]
        return self._token

    def send(self, events):
        # Sentinel wants flat-ish records; keep the full event under RawEvent and lift the useful fields.
        body = [{
            "TimeGenerated": e["timestamp"], "EventType": e["event_type"], "Source": e["source"],
            "ObservationLevel": e["observation_level"], "ActorId": (e.get("actor") or {}).get("id", ""),
            "AISystem": (e.get("target") or {}).get("ai_system", ""), "ModelId": (e.get("target") or {}).get("model_id", ""),
            "DecisionAction": (e.get("decision") or {}).get("action", ""), "PolicyId": (e.get("decision") or {}).get("policy_id", ""),
            "DlpCategories": ",".join(f["category"] for f in (e.get("content") or {}).get("dlp_findings", [])),
            "RawEvent": json.dumps(e),
        } for e in events]
        try:
            r = httpx.post(f"{self.dce_url}/dataCollectionRules/{self.dcr_id}/streams/{self.stream}?api-version=2023-01-01",
                           json=body, headers={"Authorization": f"Bearer {self._auth()}"}, timeout=15.0)
            if r.status_code == 401:
                self._token = None
            if r.status_code not in (200, 204):
                log.warning("sentinel %s: %s", r.status_code, r.text[:200])
            return r.status_code in (200, 204)
        except httpx.HTTPError as e:
            log.warning("sentinel error: %s", e)
            return False


class SyslogCEFOutput(Output):
    """CEF over syslog (TCP, optional TLS, or UDP). Works with QRadar, ArcSight, Elastic, Graylog, rsyslog."""
    name = "syslog_cef"

    def __init__(self, host: str, port: int = 514, protocol: str = "tcp", tls: bool = False):
        self.host, self.port, self.protocol, self.tls = host, port, protocol, tls

    @staticmethod
    def _esc(v) -> str:
        """Escape a value for a CEF extension field (backslash and equals sign; newlines become spaces)."""
        return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ")

    def cef(self, e: dict) -> str:
        """Format one event as a CEF line. Severity (0-10) rises with how strongly policy acted:
        block 7, require_approval 6, mask 5, route_local 4, otherwise 3; policy violations are 8."""
        d = e.get("decision") or {}
        sev = {"block": 7, "require_approval": 6, "mask": 5, "route_local": 4}.get(d.get("action"), 3)
        if e["event_type"] in ("ai.policy.violation",):
            sev = 8
        ext = {
            "rt": int(datetime.fromisoformat(e["timestamp"]).timestamp() * 1000),
            "suser": (e.get("actor") or {}).get("id", ""), "src": (e.get("actor") or {}).get("ip", ""),
            "cs1Label": "aiSystem", "cs1": (e.get("target") or {}).get("ai_system", ""),
            "cs2Label": "policyId", "cs2": d.get("policy_id", ""), "act": d.get("action", ""),
            "cs3Label": "observationLevel", "cs3": e["observation_level"],
            "cs4Label": "dlp", "cs4": ",".join(f["category"] for f in (e.get("content") or {}).get("dlp_findings", [])),
            "externalId": e["event_id"], "msg": d.get("reason", ""),
        }
        ext_s = " ".join(f"{k}={self._esc(v)}" for k, v in ext.items() if v != "")
        return f"CEF:0|ConsultantWorks|AIControlPlane|1.0|{e['event_type']}|{e['event_type']}|{sev}|{ext_s}"

    def send(self, events):
        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        msgs = [f"<134>{ts} aicp {self.cef(e)}\n".encode() for e in events]
        try:
            if self.protocol == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    for m in msgs:
                        s.sendto(m, (self.host, self.port))
                return True
            raw = socket.create_connection((self.host, self.port), timeout=10)
            sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host) if self.tls else raw
            with sock:
                for m in msgs:
                    sock.sendall(m)
            return True
        except OSError as e:
            log.warning("syslog error: %s", e)
            return False


OUTPUTS = {"file": FileOutput, "splunk_hec": SplunkHECOutput, "sentinel": SentinelOutput, "syslog_cef": SyslogCEFOutput}
