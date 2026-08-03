"""Logging setup for chancery."""

import logging
import sys
from collections.abc import Mapping
from typing import Any

from uvicorn.logging import DefaultFormatter

_FORMAT = "%(levelprefix)s %(message)s"

_LEVELS = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


def _resolve_level(level: str) -> int:
    name = level.upper()
    if name not in _LEVELS:
        logging.getLogger("chancery.logging").warning(
            "unknown log level %r, falling back to INFO", level
        )
        return logging.INFO
    return _LEVELS[name]


def setup_logging(level: str = "INFO") -> None:
    logger = logging.getLogger("chancery")
    logger.handlers.clear()
    logger.setLevel(_resolve_level(level))
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(DefaultFormatter(fmt=_FORMAT))
    logger.addHandler(handler)
    logger.propagate = True


def _fmt(fields: Mapping[str, Any]) -> str:
    if not fields:
        return ""
    return " " + " ".join(f"{key}={value}" for key, value in fields.items())


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    public: Mapping[str, Any] | None = None,
    private: Mapping[str, Any] | None = None,
) -> None:
    """Log a domain event.

    ``public`` fields are safe at the default INFO level. ``private`` fields
    (paste ids, sizes, flags) are only included when the logger is at DEBUG.
    """
    if logger.isEnabledFor(logging.DEBUG):
        fields = {**(public or {}), **(private or {})}
        logger.debug("%s%s", event, _fmt(fields))
    else:
        logger.info("%s%s", event, _fmt(public or {}))
