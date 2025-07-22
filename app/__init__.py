"""Pulls pieces together to brew a Flask of distilled Chancery.

This module provides:
- create_app: a function to get a Flask considering a dev/prod environment
"""

import time

from flask import Flask, g, request

from .api.endpoints import register_endpoints
from .config import config
from .glue import Glue
from .utils.logging import setup_logging


def create_app(config_name="development"):
    """Initializes a Chancery Flask app with DB Glue."""
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    setup_logging(app)

    db = Glue(
        paseto_key=app.config["SECRET_KEY"],
        pastes_path=app.config["PASTES_PATH"],
        protected_path=app.config["PROTECTED_PATH"],
        db_path=app.config["DATABASE_URI"],
        authorized=app.config["AUTHORIZED"],
    )

    register_endpoints(app, db)

    @app.before_request
    def _start_timer():
        g.start_time = time.time()

    @app.after_request
    def _log_request(response):
        if app.config["LOG_REQUESTS"]:
            duration = (time.time() - g.start_time) * 1000
            log_message = (
                f"{request.remote_addr} - {request.method} {request.path} "
                f"HTTP/{request.environ.get('SERVER_PROTOCOL')} "
                f"{response.status_code} - {duration:.2f}ms"
            )
            app.logger.info(log_message)
        return response

    return app
