"""The main business & auth logic with DB.

This module provides:
- Glue: a class of DB glue to perform authentication and actual paste processing
"""
# this file is horrifyingly large!

import logging
from base64 import b64decode
from contextlib import AbstractContextManager
from sqlite3 import connect, Row

from flask import session
from pyseto import Paseto, Key, VerifyError, DecryptError
from bcrypt import hashpw, gensalt
from secrets import token_bytes, token_urlsafe, choice
from typing import Any
from .constants import (
    ID_LENGTH,
    ID_CHARACTER_SET,
    VALIDATION_MASK,
    USERNAME_RE,
    PASSWORD_RE,
    ID_CHARACTER_RE,
    MAX_BOT_DESCRIPTION,
    CONCURRENT_SESSIONS
)
import hmac
from hashlib import blake2b
from .utils.errors import UserNotFoundError, ConflictError, CredentialsError, ExpirationError, \
    ResourceNotFoundError
from re import fullmatch
from .utils.ids import Generator
from datetime import datetime, timedelta
from json import loads


class Glue:
    """A glue class for database interactions and user/paste business logic.

    Behaves in admin mode when performing actions, without checking permission.
    """

    class QueryContext(AbstractContextManager):
        """Manages a thread-secure context for performing queries."""
        def __init__(self, db_path: str, timeout: int = 10, row: bool = True):
            """Sets connection-specific variables"""
            self.row = row
            self.timeout = timeout
            self.db_path = db_path
            self.conn = None
            self.cursor = None

        def __enter__(self):
            self.conn = connect(self.db_path, timeout=self.timeout)
            if self.row:
                self.conn.row_factory = Row
            self.cursor = self.conn.cursor()

        def __exit__(self, exc_type, exc_value, traceback):
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()

        def query(
                self,
                sql: str,
                params: tuple | dict = (),
                fetch: int = 1
        ) -> list[tuple] | tuple | None | list[dict] | dict:
            """Performs an SQL query.

            Args:
                sql (str): The query to run
                params (tuple | dict): Parameters to pass
                fetch (int): How many results to return.
                    If -1, does not return anything.
                    If 0, returns a list of all.
                    If 1, returns the first row.
                    If >1, returns a list of that many rows or all, whatever is less

            Returns:
                Nothing if ``fetch`` is -1.
                The first row if ``fetch`` is 1.
                A list or rows if ``fetch`` is 0 or >1.

            Raises:
                TypeError: If any of arguments are of wrong type
                ValueError: If fetch is less than -1
            """
            if not isinstance(sql, str):
                raise TypeError("Query must be a string")
            if not isinstance(params, tuple):
                raise TypeError("Parameters must be a tuple")
            if not isinstance(fetch, int):
                raise TypeError("Fetch must be an integer")
            if fetch < -1:
                raise ValueError("Fetch cannot be less than -1")
            self.cursor.execute(sql, params)
            match fetch:
                case -1:
                    return None
                case 0:
                    result = self.cursor.fetchall()
                case 1:
                    result = self.cursor.fetchone()
                case _:
                    result = self.cursor.fetchmany(size=fetch)
            return result if not self.row else dict(result)

        def commit(self) -> None:
            """Commits current DB changes."""
            self.conn.commit()

    def __init__(self, config: dict):
        """Uses configuration from a Flask config object or a dict."""
        self.db_path = config["DB_PATH"]

        self.anonymous = config["ANONYMOUS"]

        self.text_to_db = config["TO_DB"]

        if not self.text_to_db:
            self.pastes_path = config["PASTES_PATH"]

        self.secret_key = config["SECRET_KEY"]

        self.generator = Generator()
        self.logger = logging.getLogger(__name__)

        if not self.anonymous:
            self.auth = b64decode(config["AUTH_KEY"])
            self.paseto_key = Key.new(version=4, purpose='local', key=self.auth)
            self.paseto = Paseto(leeway=60)

            self.anonymous_register = config["ANONYMOUS_REGISTER"]
            self.anonymous_paste = config["ANONYMOUS_PASTE"]
            self.anonymous_read = config["ANONYMOUS_READ"]
            self.anonymous_list = config["ANONYMOUS_LIST"]

            with self.querying() as sql:
                sql.query("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER NOT NULL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password BLOB NOT NULL,
                    created_at TEXT NOT NULL DEFAULT datetime('now', 'localtime'),
                    privileges INTEGER NOT NULL
                )
                """)
                sql.query("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER NOT NULL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    token TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT datetime('now', 'localtime'),
                    expires_at TEXT NOT NULL DEFAULT datetime('now', 'localtime', '7 day'),
                    last_used_at TEXT NOT NULL DEFAULT datetime('now', 'localtime'),
                    FOREIGN KEY (user_id) REFERENCES (users.id)
                )
                """)
                sql.query("""
                CREATE TABLE IF NOT EXISTS bots (
                    id INTEGER NOT NULL PRIMARY KEY,
                    token TEXT NOT NULL,
                    description TEXT,
                    scope INTEGER NOT NULL,
                    created_by INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT datetime('now', 'localtime'),
                    last_used_at TEXT NOT NULL DEFAULT datetime('now', 'localtime'),
                    expires_at TEXT,
                    FOREIGN KEY (created_by) REFERENCES (users.id)
                )
                """)
                sql.query(f"""
                CREATE TABLE IF NOT EXISTS pastes (
                    id TEXT NOT NULL PRIMARY KEY,
                    author TEXT,
                    title TEXT NOT NULL DEFAULT 'untitled',
                    filetype TEXT NOT NULL DEFAULT 'txt',
                    {"content BLOB," if self.text_to_db else ""}
                    private INTEGER NOT NULL DEFAULT 0,
                    password BLOB,
                    created_at TEXT NOT NULL DEFAULT datetime('now', 'localtime'),
                    expires_at TEXT,
                    FOREIGN KEY (author) REFERENCES (users.username)
                )
                """)
                user_count = sql.query("""SELECT COUNT(*) FROM users""")
                if not user_count:
                    self.register_user('admin', 'admin', VALIDATION_MASK)
                    self.logger.warning("No users found. Created default user admin:admin")
        else:
            with self.querying() as sql:
                sql.query(f"""
                CREATE TABLE IF NOT EXISTS pastes (
                    id TEXT NOT NULL PRIMARY KEY,
                    author TEXT,
                    title TEXT NOT NULL DEFAULT 'untitled',
                    filetype TEXT NOT NULL DEFAULT 'txt',
                    {"content BLOB" if self.text_to_db else ""}
                    password BLOB,
                    created_at TEXT NOT NULL DEFAULT datetime('now', 'localtime'),
                    expires_at TEXT,
                    FOREIGN KEY (author) REFERENCES (users.author)
                )
                """)

    def querying(self, timeout: int = 10, row: bool = False) -> QueryContext:
        return self.QueryContext(db_path=self.db_path, timeout=timeout, row=row)

    @staticmethod
    def get_item(
            store: dict,
            key: str | int | bool | float,
            default: Any = None,
            types: type[Any] | tuple | None = None,
            pop: bool = False
    ) -> Any:
        """Retrieves a value from a dictionary, defaulting to a specified value and checking type.

        Args:
              store (dict): The dictionary to retrieve value from
              key (str | int | float | bool): The key of a dictionary item
              default (Any): The value to default to
              types (type | tuple[type]): The type(s) to check value against. None if any is allowed
              pop (bool): If True, will remove the key-value pair after getting

        Returns:
            Any: The value associated with the key in the dictionary.

        Raises:
            TypeError: If ``store`` is not a dict, ``key`` is not a string or value is of wrong type
        """
        if not isinstance(store, dict):
            raise TypeError("store must a dict")
        if not isinstance(key, int | float | str | bool):
            raise TypeError("key must be immutable")
        if not isinstance(pop, bool):
            raise TypeError("pop must be a bool")
        item = (store.get, store.pop)[int(pop)](key, default)
        if types is None or isinstance(item, types):
            return item
        raise TypeError("Value of wrong type")

    def query(
            self,
            query: str,
            params: tuple | dict = (),
            row: bool = False,
            fetch: int = 1
    ) -> Any:
        """Performs a thread-safe query. Note: Consider using ``QueryContext`` instead.

        Args:
            query (str): The SQL query
            params (tuple | dict): Parameters to pass into the query
            row (bool): True if the cursor factory should be Row,
                False if default
            fetch (int): How many results to return.
                    If -1, does not return anything.
                    If 0, returns a list of all.
                    If 1, returns the first row.
                    If >1, returns a list of that many rows or all, whatever is less

        Returns:
            Any: All results of the query.
        """
        with connect(self.db_path) as conn:
            if row:
                conn.row_factory = Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            match fetch:
                case -1:
                    result = None
                case 0:
                    result = cursor.fetchall()
                case 1:
                    result = cursor.fetchone()
                case _:
                    result = cursor.fetchmany(size=fetch)
            conn.commit()
            return result if not row else dict(result)

    @staticmethod
    def salt(factor: int = 12) -> bytes:
        """Generates a random salt.

        Args:
            factor (int): The salt's work factor. >=4 <32
        Returns:
            bytes: Generated salt in bytes.

        Raises:
            ValueError: Work factor is outside defined range or not an integer
        """
        if not isinstance(factor, int):
            raise TypeError("factor must be an integer")
        if not 4 <= factor < 32:  # noqa: PLR2004   shut the fuck up
            raise ValueError("factor should be inside [4;32)")
        return gensalt(rounds=factor)

    @staticmethod
    def hash_password(password: str, salt: bytes) -> bytes:
        """Hashes a password using bcrypt.

        Args:
            password (str): The password to hash. Will be truncated to 32 characters
            salt (bytes): The salt to add
        Returns:
            bytes: Hashed result in bytes.

        Raises:
            TypeError: Provided password is not a string or salt is not bytes
            ValueError: Provided password is empty
        """
        if not isinstance(password, str):
            raise TypeError("password must be a string")
        if not password:
            raise ValueError("password cannot be empty")
        if not isinstance(salt, bytes):
            raise TypeError("salt must be bytes")
        password = password[:32]
        try:
            return hashpw(password=password.encode("utf-8"), salt=salt)
        except Exception as e:
            raise ValueError("Hashing failed") from e

    @staticmethod
    def compare_password(true_hash: bytes, suggestion: str) -> bool:
        """Compares the true value hash to provided password.

        Args:
            true_hash (bytes): The true value hash
            suggestion (str): The suggested password. Will be truncated to 32 characters
        Returns:
            bool: True if passwords match, False otherwise.

        Raises:
            TypeError: Provided hash is not bytes or suggestion is not a string
            ValueError: Provided suggestion is empty or verification failed
        """
        if not isinstance(suggestion, str):
            raise TypeError("suggestion must be a string")
        if not suggestion:
            raise ValueError("suggestion cannot be empty")
        if not isinstance(true_hash, bytes):
            raise TypeError("true_hash must be bytes")
        suggestion = suggestion[:32]
        try:
            return hashpw(password=suggestion.encode("utf-8"), salt=true_hash) == true_hash
        except Exception as e:
            raise ValueError("Verification failed") from e

    def hash_token(self, token: bytes) -> str:
        """Hashes a token (in bytes) using BLAKE2b.

        Args:
            token (bytes): The bytes to hash

        Returns:
            str: Hashed value in hex

        Raises:
            TypeError: If ``token`` is not ``bytes``
        """
        if not isinstance(token, bytes):
            raise TypeError("token must be bytes")
        return hmac.new(self.auth, token, blake2b).hexdigest()

    def verify_token(self, provided_token: bytes, stored_hash: str) -> bool:
        """Verifies a token with its hashed stored version.

        Args:
            provided_token (bytes): A submitted token in bytes
            stored_hash (str): A BLAKE2b hash of the stored token

        Returns:
            bool: ``True`` if the submission matches the hash, ``False`` otherwise.

        Raises:
            TypeError: If ``provided_token`` is not ``bytes`` or ``stored_hash`` is not ``str``
        """
        if not isinstance(provided_token, bytes):
            raise TypeError("provided_token must be bytes")
        if not isinstance(stored_hash, str):
            raise TypeError("stored_hash must be a string")
        return hmac.compare_digest(self.hash_token(provided_token), stored_hash)

    @staticmethod
    def generate_id(length: int, symbols: str) -> str:
        """Generates a random cryptographically secure ID string.

        Args:
            length (int): The length of the ID
            symbols (str): The string of allowed possible characters
        Returns:
            str: An ID string.
        """
        return "".join(choice(symbols) for _ in range(length))

    def generate_unique_id(self, attempts: int = 3) -> str:
        """Generates a random unique cryptographically secure ID string.

        Args:
            attempts (int): Number of attempts at generating an ID
        Returns:
            str: An unique ID string.

        Raises:
            RuntimeError: If attempts were unsuccessfully depleted
        """
        ids = (i[0] for i in self.query("SELECT id FROM pastes"))
        for _ in range(attempts):
            new_id = self.generate_id(ID_LENGTH, ID_CHARACTER_SET)
            if new_id not in ids:
                return new_id
        raise RuntimeError("Attempts at generating an ID depleted unsuccessfully")

    def is_permitted(self, user_id: int, permissions: int) -> bool:
        """Checks if a certain user has required permissions.

        Args:
            user_id (int): The integer of the user's ID
            permissions (int): The permissions integer to check

        Returns:
            bool: ``True`` if the user is permitted, ``False`` otherwise.

        Raises:
            TypeError: If ``user_id`` or ``permissions`` is not ``int``
            ValueError: If ``user_id`` is negative or ``permissions`` is outside range
            UserNotFoundError: If a user under ``user_id`` was not found
        """
        if not isinstance(user_id, int):
            raise TypeError("user_id must be int")
        if not isinstance(permissions, int):
            raise TypeError("permissions must be int")
        if user_id < 0:
            raise ValueError("user_id cannot be negative")
        if VALIDATION_MASK < permissions < 0:
            raise ValueError("permissions outside permission integer range")
        actual_permissions = self.query(
            """
            SELECT COALESCE(
                (SELECT scope FROM bots WHERE id = :id),
                (SELECT privileges FROM users WHERE id = :id)
            ) AS result;
            """,
            {"id": user_id}
        )
        return actual_permissions & permissions == actual_permissions

    def register_user(self, username: str, password: str, privileges: int) -> int:
        """Creates a new user.

        Args:
            username (str): New user's login
            password (str): Unhashed new user's password
            privileges (int): Privileges of the new user

        Returns:
            int: New user's ID.

        Raises:
            TypeError: If ``username`` or ``password`` is not a string or ``privileges`` is not int
            ValueError: If ``username`` or ``password`` is empty or invalid
            ConflictError: If ``username`` is already taken
        """
        if not isinstance(username, str):
            raise TypeError("username must be a string")
        if not isinstance(password, str):
            raise TypeError("password must be a string")
        if not isinstance(privileges, int):
            raise TypeError("privileges must be int")
        if not fullmatch(USERNAME_RE, username):
            raise ValueError("username is invalid")
        if not fullmatch(PASSWORD_RE, password):
            raise ValueError("password is invalid")
        if privileges < 0 or privileges & VALIDATION_MASK != privileges:
            raise ValueError("privileges is invalid")
        with self.querying() as sql:
            password_hash = self.hash_password(password, self.salt())
            user_id = self.generator.generate_id()

            sql.query(
                """
                INSERT INTO users (
                    id, username, password, privileges) VALUES (
                    :id, :username, :password, :privileges)
                """,
                {
                    "id": user_id,
                    "username": username,
                    "password": password_hash,
                    "privileges": privileges
                }
            )
            return user_id

    def register_bot(
        self,
        maker_id: int,
        description: str | None,
        expires_at: datetime | None,
        scope: int
    ) -> tuple[str, int]:
        """Creates a new bot.

        Args:
            maker_id (int): User/bot ID that created the bot
            description (str | None): A short description of the bot (<128 characters)
            expires_at (datetime | None): When a token should expire
            scope (int): What privileges should the bot have

        Returns:
            tuple[str, int]: Newly generated bot token,
                newly created bot ID in tuple.
        Raises:
            TypeError: If any of the arguments are of wrong type
            ValueError: If ``maker_id``, ``description``, ``expires_at`` or ``scope`` are invalid
            UserNotFoundError: If ``maker_id`` does not exist
        """
        # abhorrently long validation. honestly, this is not salvageable anymore. God forgive me.
        if not isinstance(maker_id, int):
            raise TypeError("maker_id must be int")
        if not isinstance(description, str | None):
            raise TypeError("description must be string or None")
        if not isinstance(expires_at, datetime | None):
            raise TypeError("expires_at must be datetime or None")
        if not isinstance(scope, int):
            raise TypeError("scope must be int")
        if expires_at < datetime.now():
            raise ValueError("expires_at already expired")
        if scope < 0 or scope & VALIDATION_MASK != scope:
            raise ValueError("scope is invalid")
        if maker_id < 0:
            raise ValueError("maker_id is invalid")
        if len(description) > MAX_BOT_DESCRIPTION:
            raise ValueError("description too long")
        with self.querying() as sql:
            if not sql.query("""
                SELECT EXISTS (
                    SELECT 1 FROM users WHERE id = :id
                    UNION
                    SELECT 1 FROM bots WHERE id = :id
                )
            """):
                raise UserNotFoundError("maker was not found")
            bot_id = self.generator.generate_id()
            bot_token = token_urlsafe(64)
            sql.query(
                """
                INSERT INTO bots (
                    id,
                    token,
                    description,
                    scope,
                    created_by,
                    expires_at
                ) VALUES (
                    :id,
                    :token,
                    :description,
                    :scope,
                    :created_by,
                    :expires_at
                """,
                {
                    "id": bot_id,
                    "token": self.hash_token(bot_token.encode()),
                    "description": description,
                    "scope": scope,
                    "created_by": maker_id,
                    "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S")
                }
            )
            self.logger.info(f"Created bot with id {bot_id}")
            return bot_token, bot_id

    def login(
            self,
            username: str,
            password: str,
            remember: bool = True
    ) -> tuple[int, str | None, str]:
        """Checks password and logs in a user, creating a pair of access & refresh tokens.

        Args:
            username (str):
            password (str):
            remember (bool): If ``True``, will create a refresh token, otherwise only access

        Returns:
            tuple[int, str, str]: A tuple of user ID,
                refresh token (None if ``remember`` is False)
                and access token.

        Raises:
            TypeError: If ``username`` or ``password`` is not a string or ``remember`` is not a bool
            ValueError: If ``username`` or ``password`` is invalid
            CredentialsError: If ``password`` is incorrect
            UserNotFoundError: If no user with ``username`` exists
            RuntimeError: If session cap is reached
        """
        if not isinstance(username, str):
            raise TypeError("username must be string")
        if not isinstance(password, str):
            raise TypeError("password must be string")
        if not isinstance(remember, bool):
            raise TypeError("remember must be bool")
        if not fullmatch(USERNAME_RE, username):
            raise ValueError("invalid username")
        if not fullmatch(PASSWORD_RE, password):
            raise ValueError("invalid password")
        with self.querying() as sql:
            if remember:
                session_count = sql.query(
                    """
                    SELECT COUNT(*)
                    FROM sessions
                    WHERE user_id = (SELECT id FROM users WHERE username = ?)
                    """,
                    (username,)
                )
                if session_count > CONCURRENT_SESSIONS:
                    raise RuntimeError("Session cap reached")
            try:
                user_id, true_password = sql.query(
                """SELECT password FROM users WHERE username = ?""", (username,)
                )
            except IndexError:
                raise UserNotFoundError("user was not found")
            if not self.compare_password(true_password, password):
                raise CredentialsError("incorrect credentials")
            if remember:
                refresh_token = token_urlsafe(32)
                expiration_time = (datetime.now() + timedelta(days=7)).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                session_id = self.generator.generate_id()
                sql.query(
                    """
                    INSERT INTO sessions (
                        id,
                        user_id,
                        token,
                        expires_at
                    ) VALUES (
                        :id,
                        :user_id,
                        :token,
                        :expires_at
                    )
                    """,
                    {
                        "id": session_id,
                        "user_id": user_id,
                        "token": self.hash_token(refresh_token.encode()),
                        "expires_at": expiration_time
                    }
                )
            else:
                refresh_token = None
            access_token = self.paseto.encode(
                self.paseto_key,
                {"uid": user_id},
                exp=300 if remember else 1800
            ).decode("utf-8")
            return user_id, refresh_token, access_token

    def refresh(self, refresh_token: str) -> str:
        """Verifies a refresh token and issues a new access token.

        Args:
            refresh_token (str):

        Returns:
            str: New access token.

        Raises:
            TypeError: If ``refresh_token`` is not a string
            CredentialsError: If ``refresh_token`` is invalid
            ExpirationError: If ``refresh_token`` expired (but not if it was cleaned up beforehand)
        """
        if not isinstance(refresh_token, str):
            raise TypeError("refresh_token must be a string")
        if not refresh_token:
            raise CredentialsError("refresh_token cannot be empty")
        with self.querying() as sql:
            try:
                session_id, user_id, expires_at = sql.query(
                    """SELECT id, user_id, expires_at FROM sessions WHERE token = ?""",
                    (self.hash_token(refresh_token.encode()),)
                )
            except ValueError:
                raise CredentialsError("token is invalid")
            expires_at = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
            if expires_at < datetime.now():
                sql.query("""DELETE FROM sessions WHERE id = ?""", (session_id,))
                raise ExpirationError("token expired")
            sql.query(
                """
                UPDATE TABLE sessions 
                SET last_used_at = datetime('now', 'localtime') 
                WHERE id = ?
                """,
                (session_id,)
            )
            access_token = self.paseto.encode(
                self.paseto_key,
                {"uid": user_id},
                exp=300
            ).decode("utf-8")
            return access_token

    def logout(self, identity: str | int) -> None:
        """Invalidates any session by its refresh token or ID.

        Either one can be passed to destroy related session

        Args:
            identity (str | int): The session ID or token to invalidate.

        Returns:
            Nothing.

        Raises:
            TypeError: If ``identity`` is not a string or int
            ResourceNotFoundError: If ``identity`` is invalid (or was expired/destroyed before)
        """
        match identity:
            case str():
                identifier = self.hash_token(identity.encode())
            case int():
                identifier = identity
            case _:
                raise TypeError("identity must be string or int")
        if not self.query(
                "DELETE FROM sessions WHERE token = ? RETURNING 1",
                (identifier,)
        ):
            raise ResourceNotFoundError("identity is invalid")

    def about_session(
            self,
            identity: str | int
    ) -> dict[str: Any]:
        """Retrieves information about a session by its refresh token or ID.

        Either one can be passed to look up the session.

        Args:
            identity (str | int): The identifying key of the session, ID or token

        Returns:
            dict: A dict of ``user_id`` (integer of session owner),
                ``expires_at`` (datetime object of expiration),
                ``created_at`` (datetime object of session creation time),
                ``last_used_at`` (datetime object of last access token retrieval),
                ``session_id`` (integer of session id) (if token is passed).

        Raises:
            TypeError: If ``identity`` is not a string or int
            ResourceNotFoundError: If no session under ``identity`` exists
        """
        if not isinstance(identity, str | int):
            raise TypeError("identity must be string or int")
        with (self.querying(row=True) as sql):
            if isinstance(identity, str):
                data = sql.query(
                    """
                    SELECT id, user_id, created_at, expires_at, last_used_at
                    FROM sessions
                    WHERE token = ?
                    """,
                    (self.hash_token(identity.encode()),)
                )
                if not data:
                    raise ResourceNotFoundError("token is invalid")
                session_id = self.get_item(data, "id")
            else:
                data = sql.query(
                    """
                    SELECT user_id, created_at, expires_at, last_used_at
                    FROM sessions
                    WHERE id = ?
                    """,
                    (identity,)
                )
                if not data:
                    raise ResourceNotFoundError("session not found")
                session_id = identity
            user_id = self.get_item(data, "user_id")
            created_at = datetime.strptime(
                self.get_item(data, "created_at"),
                "%Y-%m-%d %H:%M:%S"
            )
            expires_at = datetime.strptime(
                self.get_item(data, "expires_at"),
                "%Y-%m-%d %H:%M:%S"
            )
            last_used_at = datetime.strptime(
                self.get_item(data, "last_used_at"),
                "%Y-%m-%d %H:%M:%S"
            )
            if expires_at < datetime.now():
                sql.query("DELETE FROM sessions WHERE id = ?", (session_id,))
                raise ExpirationError("token expired")
            return {
                "user_id", user_id,
                "session_id", session_id,
                "created_at", created_at,
                "expires_at", expires_at,
                "last_used_at", last_used_at
            }

    def verify_user(self, access_token: str) -> int:
        """Verifies an access token and returns owner's ID.

        Args:
            access_token (str): The access token to decode and verify

        Returns:
            int: Token owner's ID.

        Raises:
            TypeError: If ``access_token`` is not a string
            ValueError: If ``access_token`` is empty
            CredentialsError: If ``access_token`` is invalid
            ExpirationError: If ``access_token`` expired
            RuntimeError: If ``access_token`` is suspicious
        """
        if not isinstance(access_token, str):
            raise TypeError("access_token must be string")
        if not access_token:
            raise ValueError("access_token cannot be empty")
        try:
            decoded_token = self.paseto.decode(self.paseto_key, access_token.encode("utf-8"))
        except (VerifyError, DecryptError):
            raise CredentialsError("token is invalid")
        payload = loads(decoded_token.payload.decode("utf-8"))
        exp_str = payload.get("exp")
        if not exp_str:
            self.logger.warning("token is missing an expiration mark. your secret key may be leaked!")
            raise RuntimeError("token is missing an expiration mark.")
        exp_time = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
        if datetime.now().astimezone() > exp_time:
            raise ExpirationError("token expired")
        return payload.get("uid")

    def verify_bot(self, api_token: str) -> int:
        """Verifies an API token of a bot and returns its ID.

        Args:
            api_token (str): The token to look up

        Returns:
            int: Bot's ID.

        Raises:
            TypeError: If ``api_token`` is not a string
            ValueError: If ``api_token`` is empty
            CredentialsError: If ``api_token`` is invalid
            ExpirationError: If ``api_token`` expired (but not if it was cleaned up beforehand)
        """
        if not isinstance(api_token, str):
            raise TypeError("api_token must be string")
        if not api_token:
            raise ValueError("api_token cannot be empty")
        with self.querying() as sql:
            try:
                bot_id, expires_at = sql.query(
                """SELECT id, expires_at FROM bots WHERE token = ?""",
                (self.hash_token(api_token.encode()),)
                )
            except ValueError:
                raise CredentialsError("token is invalid")
            expires_at = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
            if expires_at < datetime.now():
                sql.query("DELETE FROM bots WHERE id = ?", (bot_id,))
                raise ExpirationError("token expired")
            sql.query(
                """
                UPDATE TABLE bots 
                SET last_used_at = datetime('now', 'localtime') 
                WHERE id = ?
                """,
                (bot_id,)
            )
            return bot_id

    def is_user(self, agent_id: int) -> bool:
        """Determines if an agent (user or bot) ID is a user.

        Args:
            agent_id (int): ID of a user or a bot to check

        Returns:
            bool: ``True`` if an agent is a user, ``False`` otherwise.

        Raises:
            TypeError: If ``agent_id`` is not an integer
            ValueError: If ``agent_id`` is negative
            UserNotFoundError: If ``agent_id`` didn't match any of the tables
        """
        if not isinstance(agent_id, int):
            raise TypeError("agent_id must be int")
        if agent_id < 0:
            raise ValueError("agent_id cannot be negative")
        origin = self.query(
            """
            SELECT
                EXISTS (SELECT 1 FROM users WHERE id = :id),
                EXISTS (SELECT 1 FROM bots WHERE id = :id)
            """,
            {"id": agent_id}
        )
        if not any(origin):
            raise UserNotFoundError("agent_id is neither a user or a bot")
        return origin[0]

    def get_id_by_username(self, username: str) -> int | None:
        """Looks up user ID by their username.

        Args:
            username (str):

        Returns:
            User ID if a user is found, ``None`` otherwise

        Raises:
            TypeError: If ``username`` is not a string
            ValueError: If ``username`` is invalid
        """
        if not isinstance(username, str):
            raise TypeError("username must be string")
        if not fullmatch(USERNAME_RE, username):
            raise ValueError("username is invalid")
        user_id = self.query("SELECT id FROM users WHERE username = ?", (username,))
        return None if not user_id else user_id[0]

    def get_user(self, user_id: int, descriptive: bool = False) -> dict[str: Any]:
        """Looks up user data by ID

        Args:
            user_id (int):
            descriptive (bool): If ``True``
                will show what is generally considered private info (privileges).
                If ``False``, would only show username and creation time

        Returns:
            dict: A dict of ``username`` (str),
                ``created_at`` (datetime object),
                ``privileges`` (integer, only if ``descriptive`` is ``True``)

        Raises:
            TypeError: If ``user_id`` is not an integer or ``descriptive`` is not a bool
            ValueError: If ``user_id`` is negative
            UserNotFoundError: If ``user_id`` doesn't belong to a user
                (for bots refer to ``get_bot``)
        """
        if not isinstance(user_id, int):
            raise TypeError("user_id must be int")
        if not isinstance(descriptive, bool):
            raise TypeError("descriptive must be bool")
        if user_id < 0:
            raise ValueError("user_id cannot be negative")
        try:
            if descriptive:
                username, created_at, privileges = self.query(
                    "SELECT username, created_at, privileges FROM users WHERE id = ?",
                    (user_id,)
                )
            else:
                privileges = None  # to shut intellisense up :'(
                username, created_at = self.query(
                    "SELECT username, created_at FROM users WHERE id = ?",
                    (user_id,)
                )
        except ValueError:
            raise UserNotFoundError("user was not found")
        created_at = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
        userdata = {
            "username": username,
            "created_at": created_at
        }
        if descriptive:
            userdata["privileges"] = privileges
        return

    def get_bot(self, bot_id: int) -> dict[str: Any]:
        """Looks up bot data by its ID.

        Args:
            bot_id (int):

        Returns:
            dict: A dict of ``description`` (str, short bot description),
                ``scope`` (int, privileges integer),
                ``created_by`` (int, creator ID),
                ``created_at`` (datetime object),
                ``expires_at`` (datetime object),
                ``last_used_at`` (datetime object),
        Raises:
            TypeError: If ``bot_id`` is not an integer
            ValueError: If ``bot_id`` is negative
            UserNotFoundError: If ``bot_id`` doesn't belong to a bot
        """
        if not isinstance(bot_id, int):
            raise TypeError("bot_id must be int")
        if bot_id < 0:
            raise ValueError("bot_id cannot be negative")
        data = self.query(
            """
            SELECT description, scope, created_by, created_at, last_used_at, expires_at
            FROM bots
            WHERE id = ?
            """,
            (bot_id,),
            row=True
        )
        if not data:
            raise UserNotFoundError("bot was not found")
        return data

