from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Union
from pydantic import field_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── OpenAI ────────────────────────────────────────────────
    OPENAI_API_KEY: str = "sk-placeholder"
    OPENAI_MODEL: str = "gpt-4o-mini"
    OPENAI_EMBEDDING_MODEL: str = "text-embedding-3-small"

    # ── Database ──────────────────────────────────────────────
    DATABASE_URL: str = (
        "postgresql+asyncpg://threatsync:threatsync@localhost:5432/threatsync"
    )

    # ── Redis ─────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── ChromaDB ──────────────────────────────────────────────
    CHROMA_PERSIST_DIR: str = "./chroma_db"

    # ── Application ───────────────────────────────────────────
    APP_NAME: str = "ThreatSync AI Investigator"
    DEBUG: bool = False
    SECRET_KEY: str = "change-this-in-production"
    CORS_ORIGINS: List[str] = [
        "http://localhost:8000",
        "http://localhost:3000",
    ]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, list):
            return v
        # Handle comma-separated string: "http://a,http://b"
        v = v.strip()
        if v.startswith("["):
            import json
            return json.loads(v)
        return [origin.strip() for origin in v.split(",") if origin.strip()]

    # ── API Security (optional, recommended for production) ───
    API_AUTH_ENABLED: bool = False
    API_KEY_SERVICE: str = "service-dev-key"
    API_KEY_ANALYST: str = "analyst-dev-key"

    # ── Investigation ─────────────────────────────────────────
    APPROVAL_THRESHOLD: float = 7.0
    RAG_TOP_K: int = 5


settings = Settings()
