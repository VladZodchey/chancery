"""Manages configuration variables.

This module provides:
- Config: a base class for pulling environment variables
- DevelopmentConfig: a dev config class for test environments
- ProductionConfig: a config class for production
- config: a dict for getting configuration depending on environment
"""

import os
from secrets import token_bytes

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base class for pulling environment variables."""

    SECRET_KEY = os.getenv("AUTH_SECRET", token_bytes(32))
    DATABASE_URI = os.getenv("DB_PATH", "file::memory:?cache=shared")
    PASTES_PATH = os.getenv("PASTES_PATH", "./pastes")
    PROTECTED_PATH = os.getenv("PROTECTED_PATH", "./protected")
    AUTHORIZED = os.getenv("AUTHORIZED", "True").lower() == "true"
    LOG_REQUESTS = os.getenv("LOG_REQUESTS", "False").lower() == "true"


class DevelopmentConfig(Config):
    """Config class with DEBUG on."""

    DEBUG = True
    LOG_REQUESTS = False


class ProductionConfig(Config):
    """Config class with DEBUG off."""

    DEBUG = False
    LOG_REQUESTS = True


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
