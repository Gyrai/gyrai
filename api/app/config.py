"""Runtime settings. Everything comes from environment variables so the same
image runs in docker compose, Kubernetes, or a laptop."""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # SQLite by default so the API runs with zero dependencies in dev/tests.
    # Compose overrides this with a Postgres URL.
    database_url: str = "sqlite:///./aicp.db"

    # Shared secret collectors present as a bearer token on /api/v1/events.
    # Replace with OIDC/mTLS before any customer deployment.
    ingest_token: str = "dev-ingest-token-change-me"

    # OPA sidecar. Advisory decisions are computed on ingest when reachable.
    opa_url: str = "http://localhost:8181"
    opa_enabled: bool = False

    # Hash-chain every event on ingest (AU-9 / AU-10). Costs one hash per event.
    hash_chain_enabled: bool = True

    # Branding for evidence reports.
    org_name: str = "Consultant Works"
    product_name: str = "AI Control Plane"

    model_config = {"env_prefix": "AICP_", "env_file": ".env", "extra": "ignore"}


settings = Settings()
