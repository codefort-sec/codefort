"""Configuration module alias for app.core.config."""

from app.core.config import Settings, settings


def get_settings() -> Settings:
    """Returns application settings instance."""
    return settings


__all__ = ["Settings", "settings", "get_settings"]
