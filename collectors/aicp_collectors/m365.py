"""Microsoft 365 collector. Pulls three things from Microsoft Graph:

  1. Copilot interaction history   -> ai.prompt.submitted / ai.response.delivered  (content_visible)
     GET /copilot/users/{id}/interactionHistory/getAllEnterpriseInteractions
  2. Sign-ins to AI-related apps    -> ai.signin / ai.app.discovered               (metadata_only)
     GET /auditLogs/signIns  (filtered to known AI app display names + any 3rd-party AI apps)
  3. Purview DLP alerts for AI      -> ai.dlp.match                                 (content_visible)
     GET /security/alerts_v2 filtered to DLP / Copilot categories

App registration (one-time, in the customer's Entra tenant):
  Application permissions: AuditLog.Read.All, Directory.Read.All, SecurityAlert.Read.All,
  and for Copilot interactions: AiEnterpriseInteraction.Read.All (requires Copilot licensing;
  the endpoint is in the beta Graph surface at time of writing — verify in the customer tenant).
  Grant admin consent. Put tenant id, client id, client secret (or certificate) in env.

Each capability degrades independently: if the tenant has no Copilot license the
interaction call 403s and we still collect sign-ins and alerts.
"""
import logging
import os
from collections.abc import Iterable
from datetime import datetime, timezone

import httpx

from .base import Collector, sha256
from .dlp import scan

log = logging.getLogger("aicp.collector.m365")
GRAPH = "https://graph.microsoft.com"

# Entra app display names that indicate AI usage. Extend per customer.
AI_APPS = {
    "Microsoft 365 Copilot": ("m365.copilot", "cloud_tenant"),
    "Microsoft Copilot": ("microsoft.copilot", "external_saas"),
    "Copilot": ("microsoft.copilot", "external_saas"),
    "ChatGPT": ("openai.chatgpt", "external_saas"),
    "OpenAI": ("openai.chatgpt", "external_saas"),
    "Claude": ("anthropic.claude", "external_saas"),
    "Gemini": ("google.gemini", "external_saas"),
    "Perplexity": ("perplexity.ai", "external_saas"),
    "Otter.ai": ("otter.ai", "external_saas"),
    "Grammarly": ("grammarly", "external_saas"),
    "Notion AI": ("notion.ai", "external_saas"),
    "GitHub Copilot": ("github.copilot", "external_saas"),
}


class M365Collector(Collector):
    """Collects AI-related activity from one Microsoft 365 tenant through Microsoft Graph."""

    source = "collector.m365"
    observation_level = "metadata_only"  # per-event override below

    def __init__(self, tenant_id: str | None = None, client_id: str | None = None,
                 client_secret: str | None = None, **kw):
        super().__init__(**kw)
        self.tenant_id = tenant_id or os.environ["AICP_M365_TENANT_ID"]
        self.client_id = client_id or os.environ["AICP_M365_CLIENT_ID"]
        self.client_secret = client_secret or os.environ["AICP_M365_CLIENT_SECRET"]
        self._token: str | None = None

    # ---- auth ----
    def _auth(self) -> str:
        """Get an app-only access token (client-credentials flow) and cache it. Not refreshed:
        a run is short, and the token is fetched again on the next run."""
        if self._token:
            return self._token
        r = httpx.post(
            f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": f"{GRAPH}/.default",
                "grant_type": "client_credentials",
            },
            timeout=30.0,
        )
        r.raise_for_status()
        self._token = r.json()["access_token"]
        return self._token

    def _get(self, url: str, params: dict | None = None, beta: bool = False) -> Iterable[dict]:
        """Follow @odata.nextLink pagination."""
        full = url if url.startswith("http") else f"{GRAPH}/{'beta' if beta else 'v1.0'}{url}"
        while full:
            r = httpx.get(full, params=params, headers={"Authorization": f"Bearer {self._auth()}"}, timeout=60.0)
            # 403 or 404 usually means the tenant lacks the license or admin consent for this data. Skip it rather than failing the whole run.
            if r.status_code in (403, 404):
                log.warning("%s -> %s (capability not licensed or not consented); skipping", url, r.status_code)
                return
            r.raise_for_status()
            data = r.json()
            yield from data.get("value", [])
            full, params = data.get("@odata.nextLink"), None

    # ---- fetch ----
    def fetch(self, since: datetime) -> Iterable[dict]:
        """Yield records from the three Graph sources. Each is tagged with `_kind` so normalize()
        knows how to convert it."""
        # Graph filters need UTC timestamps in exactly this format.
        iso = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Sign-ins to AI apps
        for s in self._get("/auditLogs/signIns", {"$filter": f"createdDateTime ge {iso}", "$top": 999}):
            # Keep only sign-ins to known AI apps, plus apps whose names look like AI tools.
            if s.get("appDisplayName") in AI_APPS or self._looks_like_ai(s.get("appDisplayName", "")):
                yield {"_kind": "signin", **s}

        # 2. Copilot enterprise interactions (beta). Needs per-user enumeration in some tenants;
        #    the tenant-wide endpoint is used first.
        for ix in self._get("/copilot/interactionHistory/getAllEnterpriseInteractions",
                            {"$filter": f"createdDateTime gt {iso}"}, beta=True):
            yield {"_kind": "copilot", **ix}

        # 3. Security alerts (Purview DLP, Copilot-related)
        for a in self._get("/security/alerts_v2",
                           {"$filter": f"createdDateTime ge {iso} and (serviceSource eq 'microsoftDataLossPrevention')"}):
            yield {"_kind": "alert", **a}

    @staticmethod
    def _looks_like_ai(name: str) -> bool:
        """Rough check for AI apps not in AI_APPS. It can over-match; the inventory page lets an
        admin review whatever it finds."""
        n = name.lower()
        return any(k in n for k in ("copilot", "gpt", "openai", "claude", "gemini", " ai", "ai ", "llm"))

    # ---- normalize ----
    def normalize(self, rec: dict) -> dict | None:
        """Route a record to the converter for its kind (sign-in, Copilot interaction, DLP alert)."""
        kind = rec["_kind"]
        if kind == "signin":
            return self._signin(rec)
        if kind == "copilot":
            return self._copilot(rec)
        if kind == "alert":
            return self._alert(rec)
        return None

    def _signin(self, s: dict) -> dict:
        """A sign-in to an AI app. Metadata only: who, from where, to which app."""
        app = s.get("appDisplayName", "")
        # Known apps get a stable system key; unknown ones get a key derived from the app name.
        key, hosting = AI_APPS.get(app, (f"entra.{app.lower().replace(' ', '_')}", "external_saas"))
        ts = datetime.fromisoformat(s["createdDateTime"].replace("Z", "+00:00"))
        ev = self.base_event("ai.signin", ts, s["id"])
        ev["observation_level"] = "metadata_only"
        ev["actor"] = {"type": "human", "id": s.get("userPrincipalName", ""), "display_name": s.get("userDisplayName", ""),
                       "ip": s.get("ipAddress", ""), "device_id": (s.get("deviceDetail") or {}).get("deviceId", "")}
        ev["target"] = {"ai_system": key, "hosting": hosting, "endpoint": f"entra://{s.get('appId', '')}"}
        return ev

    def _copilot(self, ix: dict) -> dict:
        """A Copilot prompt or reply. The text is scanned and then kept only as a hash."""
        ts = datetime.fromisoformat(ix["createdDateTime"].replace("Z", "+00:00"))
        # Copilot history holds both the user's prompts and Copilot's replies; they become different event types.
        is_prompt = (ix.get("interactionType") or "").lower() == "userprompt"
        ev = self.base_event("ai.prompt.submitted" if is_prompt else "ai.response.delivered", ts, ix["id"])
        ev["observation_level"] = "content_visible"
        user = (ix.get("from") or {}).get("user") or {}
        ev["actor"] = {"type": "human", "id": user.get("userPrincipalName") or user.get("id", ""),
                       "display_name": user.get("displayName", "")}
        ev["target"] = {"ai_system": "m365.copilot", "hosting": "cloud_tenant",
                        "model_id": ix.get("appClass", "copilot")}
        # Only a hash of the text is kept. A scanner hit changes the event type so it stands out.
        text = ((ix.get("body") or {}).get("content")) or ""
        attachments = len(ix.get("attachments") or [])
        content = {"attachments": attachments}
        if text:
            content["prompt_sha256" if is_prompt else "response_sha256"] = sha256(text)
            findings = scan(text)
            if findings:
                content["dlp_findings"] = findings
                ev["event_type"] = "ai.dlp.match"
        ev["content"] = content
        return ev

    def _alert(self, a: dict) -> dict:
        """A Purview DLP alert. We record that a match happened and who it involved, not what matched."""
        ts = datetime.fromisoformat(a["createdDateTime"].replace("Z", "+00:00"))
        ev = self.base_event("ai.dlp.match", ts, a["id"])
        ev["observation_level"] = "content_visible"
        # Alerts list evidence items; take the first user account as the person involved.
        users = [e for e in a.get("evidence", []) if e.get("@odata.type", "").endswith("userEvidence")]
        upn = ((users[0].get("userAccount") or {}).get("userPrincipalName")) if users else ""
        ev["actor"] = {"type": "human", "id": upn or ""}
        ev["target"] = {"ai_system": "m365.copilot", "hosting": "cloud_tenant"}
        ev["content"] = {"dlp_findings": [
            {"category": "CUSTOM", "detector": f"purview.{a.get('category', 'dlp')}", "count": 1, "confidence": 0.8}
        ]}
        return ev
