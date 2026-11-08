from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ATLAS_", env_file=".env", extra="ignore")

    env: str = "development"
    debug: bool = False
    database_url: str = "postgresql+psycopg://atlas:atlas@localhost:5432/atlas_core"
    redis_url: str = "redis://localhost:6379/0"
    secret_key: str = "change-me"
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 7 * 24 * 3600
    password_hash_iterations: int = 600_000
    max_failed_logins: int = 5
    lockout_seconds: int = 900
    reset_token_ttl_seconds: int = 3600
    mfa_issuer: str = "ATLAS"
    rate_limit_backend: str = "redis"        # redis | memory
    rate_limit_fail_mode: str = "memory"     # memory (degrade to per-process) | closed | open
    auth_rate_limit_per_minute: int = 10
    trust_proxy_headers: bool = False
    cors_origins: str = "http://localhost:5173"
    max_redirects: int = 3
    allowed_ports: str = "80,443,8080,8443"
    rate_limit_per_minute: int = 120
    collector_min_interval_seconds: float = 1.0
    user_agent: str = "ATLAS-CORE/0.1 (authorized security assessment)"
    ai_provider: str = "none"
    ai_api_key: str = ""
    ai_model: str = "claude-sonnet-4-6"
    ai_base_url: str = ""
    api_prefix: str = "/api/v1"

    def validate_for_runtime(self) -> None:
        if self.env != "development" and self.secret_key == "change-me":
            raise RuntimeError("ATLAS_SECRET_KEY must be set outside development")


@lru_cache
def get_settings() -> Settings:
    return Settings()
