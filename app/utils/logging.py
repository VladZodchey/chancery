"""Gives out a production-ready logger.

This module provides:
- setup_logging: a function to assign app logging to a rotating file handler
"""

import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logging(app):
    """Sets logging of a Flask app to .log file and std stream.

    Args:
        app (Flask): The Flask app to configure
    """

    log_level = logging.DEBUG if app.config["DEBUG"] else logging.INFO

    if not os.path.exists("logs"):
        os.makedirs("logs")

    file_handler = RotatingFileHandler("logs/app.log", maxBytes=10_000_000, backupCount=5)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]")
    )
    file_handler.setLevel(log_level)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
    console_handler.setLevel(log_level)

    app.logger.handlers = []
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(log_level)
