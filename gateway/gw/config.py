"""Gateway settings. All via environment (prefix AICP_GW_)."""
from pydantic_settings import BaseSettings


class GatewaySettings(BaseSettings):
    """Every tunable for the gateway, read from AICP_GW_* environment variables or a
    local .env file. Field names map to variables, e.g. `upstream_url` is
    AICP_GW_UPSTREAM_URL. A single module-level instance, `settings`, is shared by
    the rest of the package."""

    # monitor: record policy decisions, never alter traffic.
    # enforce: block / mask / require_approval per policy.
    mode: str = "monitor"

    # Upstream provider. Any OpenAI-compatible endpoint: api.openai.com, Azure OpenAI
    # (with api-version in the URL), LiteLLM, vLLM, Ollama, a local mock.
    upstream_url: str = "https://api.openai.com"
    upstream_key: str = ""              # the ONLY place a provider key lives
    upstream_timeout_seconds: float = 120.0

    # Optional second upstream for the `route_local` action: an on-prem model that
    # may receive CUI. Leave empty to treat route_local as block in enforce mode.
    local_upstream_url: str = ""
    local_upstream_key: str = ""

    # Where to find the governance plane (audit store) and OPA.
    api_url: str = "http://localhost:8000"
    ingest_token: str = "dev-ingest-token-change-me"
    opa_url: str = "http://localhost:8181"
    opa_enabled: bool = True

    # Gateway keys: JSON map of key -> {"id": ..., "type": "human|agent|service", "on_behalf_of": ...}
    # Replace with OIDC/JWT validation before customer deployment.
    keys_file: str = "gateway_keys.json"
    # In monitor mode, unknown keys pass through as actor.id="unknown". In enforce mode they are rejected.

    # Fallback audit sink when the governance plane is unreachable (fail-open on audit, never drop).
    fallback_log: str = "gateway_audit_fallback.jsonl"

    # Hosting classification of the primary upstream, used by policy.
    upstream_hosting: str = "external_saas"
    upstream_system_key: str = "gateway.openai"

    model_config = {"env_prefix": "AICP_GW_", "env_file": ".env", "extra": "ignore"}


# Shared instance. Tests change fields on it directly (e.g. settings.mode = "enforce").
settings = GatewaySettings()
