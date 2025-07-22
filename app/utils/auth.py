"""Auth middleware for authorization-required endpoints.

This module provides:
- require_auth: a decorator that requires and checks a Bearer token, unless authorized is False
- optional_auth: a decorator that checks a Bearer token, unless authorized is False
"""

from collections.abc import Callable
from functools import wraps
from http import HTTPStatus

from flask import abort, request


def require_auth(f: Callable) -> Callable:
    """Requires a PASETO Bearer token to continue and passes ``user_id`` downstream.

    If `authorized` is `False`, skips checks and passes ``None`` as ``user_id``.
    """

    @wraps(f)
    def decorated(self, *_args, **kwargs):
        if not self.authorized:
            return f(self, user_id=None, **kwargs)
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            abort(HTTPStatus.UNAUTHORIZED, description="Authentication header is missing")
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":  # noqa PLR2004
            abort(
                HTTPStatus.UNAUTHORIZED,
                description="Invalid authentication scheme. Use Bearer token",
            )
        token = parts[1]
        try:
            uid = self.db.verify(token)
            if not uid:
                abort(HTTPStatus.UNAUTHORIZED, description="Invalid or expired token")
            return f(self, user_id=uid, **kwargs)
        except TypeError as e:
            abort(HTTPStatus.BAD_REQUEST, description=f"Invalid token format {e}")

    return decorated


def optional_auth(f: Callable) -> Callable:
    """Accepts a PASETO Bearer token and passes ``user_id`` downstream.

    Passes ``None`` if no token was given or ``authorized`` is ``False``.
    """

    @wraps(f)
    def decorated(self, *_args, **kwargs):
        if not self.db.authorized:
            return f(self, user_id=None, **kwargs)
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return f(self, user_id=None, **kwargs)
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":  # noqa PLR2004
            abort(
                HTTPStatus.UNAUTHORIZED,
                description="Invalid authentication scheme. Use Bearer token",
            )
        token = parts[1]
        try:
            uid = self.db.verify(token)
            if not uid:
                abort(HTTPStatus.UNAUTHORIZED, description="Invalid or expired token")
            return f(self, user_id=uid, **kwargs)
        except TypeError as e:
            abort(HTTPStatus.BAD_REQUEST, description=f"Invalid token format {e}")

    return decorated
