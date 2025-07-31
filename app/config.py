"""Manages configuration variables.

This module provides:
- Config: a base class for pulling environment variables
- DevelopmentConfig: a dev config class for test environments
- ProductionConfig: a config class for production
- config: a dict for getting configuration depending on environment
"""

import os
from secrets import token_bytes
from base64 import b64encode

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base class for pulling environment variables."""

    AUTH_KEY = os.getenv("AUTH_SECRET", b64encode(token_bytes(32)).decode('utf-8'))

    DATABASE_URI = os.getenv("DB_PATH", "file::memory:?cache=shared")

    PASTES_PATH = os.getenv("PASTES_PATH", "./pastes")

    ANONYMOUS = os.getenv("ANONYMOUS", "False").lower() == "true"
    ANONYMOUS_REGISTER = os.getenv("ANONYMOUS", "False").lower() == "true"
    ANONYMOUS_PASTE = os.getenv("ANONYMOUS", "False").lower() == "true"
    ANONYMOUS_READ = os.getenv("ANONYMOUS", "True").lower() == "true"
    ANONYMOUS_LIST = os.getenv("ANONYMOUS", "False").lower() == "true"

    LOG_ACTIONS = os.getenv("LOG_ACTIONS", "True").lower() == "true"
    LOG_REQUESTS = os.getenv("LOG_REQUESTS", "False").lower() == "true"


class DevelopmentConfig(Config):
    """Config class with DEBUG on."""

    DEBUG = True


class ProductionConfig(Config):
    """Config class with DEBUG off."""

    DEBUG = False


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
}
