"""Application configuration using Pydantic Settings."""

import secrets
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    APP_NAME: str = "CodeFort API"
    ENVIRONMENT: str = "development"
    PORT: int = 8000
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/codefort"

    # Security & Auth
    SESSION_SECRET: str = Field(default_factory=lambda: secrets.token_hex(32))
    EXTENSION_TOKEN_SIGNING_KEY: str = Field(default_factory=lambda: secrets.token_hex(32))
    ALLOWED_WEB_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "https://codefort-web.vercel.app",
    ]

    @field_validator("ALLOWED_WEB_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    # GitHub App Integration
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_APP_ID: str = ""
    GITHUB_APP_PRIVATE_KEY: str = ""
    GITHUB_WEBHOOK_SECRET: str = "development-webhook-secret"
    GITHUB_TOKEN: str = ""

    # LLM / AI (BARQAI Engine)
    LLM_PROVIDER: str = "gemini"
    LLM_API_KEY: str = ""
    GEMINI_API_KEY: str = ""

    # Queue & Cache
    REDIS_URL: str = "redis://localhost:6379/0"


settings = Settings()
