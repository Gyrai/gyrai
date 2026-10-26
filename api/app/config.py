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

    # Console authentication (local accounts). OIDC/Entra layers on top in 0.3.
    # Secret used to sign session cookies. MUST be set to a long random value in production;
    # if left empty a random one is generated at startup (sessions reset on restart).
    session_secret: str = ""
    session_hours: int = 12
    # Initial admin password. If unset and no users exist, one is generated and printed to the log once.
    admin_password: str = ""
    # Set true only behind TLS (cookie gets the Secure flag).
    cookie_secure: bool = False
    # Lock an account after this many consecutive failed logins (0 disables).
    lockout_after: int = 10

    # Branding for evidence reports.
    org_name: str = "Consultant Works"
    product_name: str = "AI Control Plane"

    model_config = {"env_prefix": "AICP_", "env_file": ".env", "extra": "ignore"}


settings = Settings()
