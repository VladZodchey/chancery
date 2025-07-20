"""The main endpoints file.

This module provides:
- API: a class of all endpoints
- register_endpoints: a function that registers endpoints onto an app and assigns a DB glue
"""
import logging
from http import HTTPStatus

from flask import Response, abort, jsonify, request

from ..constants import ADMIN, READ, WRITE
from ..glue import Glue
from ..utils.auth import optional_auth, require_auth
from . import api_bp


class API:
    """The dome API class to store endpoint methods + DB."""
    def __init__(self, db: Glue, authorized: bool = False):
        """Populates variables that are used by endpoints.

        Args:
            db (Glue): An instance of DB Glue that will be used
            authorized (bool): True if it should check for
                user permissions and authorization, False if trust anyone
        """
        self.db = db
        self.authorized = authorized
        self.logger = logging.getLogger(__name__)

    def login(self):
        """Attempts to log in a user and create a pair of session/access tokens.

        Requires ``username`` and ``password`` fields in request JSON body.
        Optionally takes a ``remember`` boolean.
        """
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        remember = bool(data.get("remember"))
        if not username or not password:
            abort(HTTPStatus.BAD_REQUEST, description="Credentials are missing")
        try:
            user_id, refresh_token, access_token = self.db.login(
                username, password, remember
            )
            returnable = {
                "user_id": user_id,
                "access_token": access_token,
                "refresh_token": refresh_token,
            }
            return jsonify(returnable)
        except TypeError:
            abort(HTTPStatus.UNPROCESSABLE_ENTITY, description="Credentials are invalid")
        except ValueError:
            abort(HTTPStatus.BAD_REQUEST, description="Credentials are incorrect")
        except KeyError:
            abort(HTTPStatus.BAD_REQUEST, description="User not found")

    def refresh(self):
        """Generates a new access token using a ``refresh_token`` from JSON body."""
        refresh_token = request.cookies.get("refreshToken") or request.get_json().get(
            "refresh_token"
        )  # CHANGE! some... time... later... i guess...
        if refresh_token:
            try:
                access_token = self.db.refresh_access(refresh_token)
                return jsonify(
                        {"access_token": access_token, "refresh_token": refresh_token}
                )
            except (TypeError, ValueError):
                abort(
                    HTTPStatus.UNAUTHORIZED,
                    description="Refresh token is invalid or expired",
                )
        abort(HTTPStatus.BAD_REQUEST, description="Refresh token missing")

    @require_auth
    def register(self, user_id):
        """Attempts to register a user.

        If ``authorized`` is ``True``, will require the user creating the account to be admin.
        Takes ``username``, ``password`` and ``privileges`` fields from JSON body.
        """
        try:
            if not self.db.is_permitted(user_id, ADMIN):
                abort(
                    HTTPStatus.UNAUTHORIZED,
                    description="You don't have enough rights to do that.",
                )
        except (KeyError, TypeError, ValueError):
            abort(HTTPStatus.BAD_REQUEST, description="Bad authorization")
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")
        privileges = data.get("permissions") or READ
        try:
            uid = self.db.register_user(username, password, privileges)
            return jsonify({"uid": uid})
        except (TypeError, ValueError) as e:
            abort(HTTPStatus.BAD_REQUEST, description=f"Credentials are invalid: {e}")
        except RuntimeError:
            abort(HTTPStatus.CONFLICT, description="User already exists")

    @require_auth
    def logout(self, user_id):
        """Invalidates a session using ``refresh_token`` JSON body."""
        data = request.get_json()
        refresh_token = data.get("refresh_token")  # CHANGE! later.
        if not refresh_token:
            abort(
                HTTPStatus.BAD_REQUEST,
                description="No session to log out of is supplied",
            )
        try:
            self.db.logout(refresh_token, user_id)
        except (TypeError, ValueError):
            abort(HTTPStatus.BAD_REQUEST, description="Invalid supplied session token")
        except PermissionError:
            abort(
                HTTPStatus.BAD_REQUEST,
                description="Error happened when processing logout",
            )

    def fetch_raw(self):
        """Attempts to read a non-read protected raw paste with ``paste_id`` in request arg."""
        paste_id = request.args.get("paste_id")
        if paste_id:
            try:
                return Response(self.db.read_paste_raw(paste_id), 200)
            except FileNotFoundError:
                abort(HTTPStatus.NOT_FOUND, description="Paste was not found")
            except (ValueError, TypeError):
                abort(HTTPStatus.BAD_REQUEST, description="Paste ID is invalid")
        abort(HTTPStatus.BAD_REQUEST, description="Paste ID missing")

    @optional_auth
    def fetch(self, user_id):
        """Attempts to fetch a paste with its metadata under ``paste_id`` request arg."""
        paste_id = request.args.get("paste_id")
        if paste_id:
            try:
                if self.authorized and self.db.is_protected(paste_id):
                    if user_id is None:
                        abort(
                            HTTPStatus.FORBIDDEN,
                            description="You must authorize to read that.",
                        )
                    if not self.db.is_permitted(user_id, READ):
                        raise PermissionError("You have no rights to read that.")
                return jsonify(self.db.read_paste(paste_id))
            except PermissionError:
                abort(
                    HTTPStatus.FORBIDDEN, description="You have no rights to read that."
                )
            except KeyError:
                abort(HTTPStatus.NOT_FOUND, description="Paste was not found")
            except (TypeError, ValueError):
                abort(HTTPStatus.BAD_REQUEST, description="Paste ID is invalid")
        abort(HTTPStatus.BAD_REQUEST, description="Paste ID missing")

    @require_auth
    def create(self, user_id):
        """Attempts to create a new paste.

        todo: write a comprehensive doc here
        """
        data = request.get_json()
        content = data.get("content")
        del data["content"]
        try:
            if not self.authorized or self.db.is_permitted(user_id, WRITE):
                return Response(self.db.insert_paste(content, data, user_id))
            abort(HTTPStatus.FORBIDDEN, description="You have no rights to write that.")
        except (ValueError, TypeError):
            abort(
                HTTPStatus.BAD_REQUEST,
                description="Paste content or metadata is malformed",
            )
        except RuntimeError:
            abort(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                description="Server failed generating unique link",
            )
        except KeyError:
            abort(HTTPStatus.UNAUTHORIZED, description="Malformed authentication token")

    @require_auth
    def cleanup(self, user_id):
        """A clean-up root that removes expired pastes and sessions."""
        try:
            if not self.authorized or self.db.is_permitted(user_id, ADMIN):
                self.db.cleanup()
        except RuntimeError:
            abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Cleanup failed")
        except (KeyError, ValueError, TypeError):
            abort(HTTPStatus.BAD_REQUEST, description="Bad authorization")

    @staticmethod
    def hello():
        """A root plug to test connections and inform users."""
        return Response(
            """
        <h1>Hello!</h1>
        <p>Chancery API does not provide a web interface. Yet.</p>
        """,
            200,
        )



def register_endpoints(app, db):
    """Binds endpoints to a Flask app.

    Args:
        app (Flask): The app to bind endpoints to
        db (Glue): The DB Glue that will be used for logic
    """
    api = API(db, app.config["AUTHORIZED"])
    api_bp.add_url_rule("/fetch", view_func=api.fetch, methods=["GET"])
    api_bp.add_url_rule("/raw", view_func=api.fetch_raw, methods=["GET"])
    api_bp.add_url_rule("/paste", view_func=api.create, methods=["POST"])
    api_bp.add_url_rule("/cleanup", view_func=api.cleanup, methods=["POST"])
    api_bp.add_url_rule("/", view_func=api.hello, methods=["GET"])
    if app.config["AUTHORIZED"]:
        api_bp.add_url_rule("/login", view_func=api.login, methods=["POST"])
        api_bp.add_url_rule("/register", view_func=api.register, methods=["POST"])
        api_bp.add_url_rule("/refresh", view_func=api.refresh, methods=["POST"])
        api_bp.add_url_rule("/logout", view_func=api.logout, methods=["POST"])
    app.register_blueprint(api_bp, url_prefix="/api")