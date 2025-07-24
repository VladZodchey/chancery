"""The main business & auth logic with DB.

This module provides:
- Glue: a class of DB glue to perform authentication and actual paste processing
"""

from __future__ import annotations

import re
from typing import Any, Type

import logging
from datetime import UTC, datetime, timedelta
from json import dumps, loads
from os import path, remove
from re import fullmatch
from secrets import choice, token_urlsafe
from sqlite3 import IntegrityError, OperationalError, Row, connect

from bcrypt import gensalt, hashpw
from pyseto import DecryptError, Key, Paseto, VerifyError

from .constants import (
    CONCURRENT_SESSIONS,
    ID_CHARACTER_SET,
    ID_CHARACTER_RE,
    ID_LENGTH,
    USERNAME_RE,
    PASSWORD_RE,
    VALIDATION_MASK,
)


class Glue:
    """A glue class for database interactions and user/paste business logic."""

    def __init__(
        self,
        paseto_key: bytes,
        pastes_path: str,
        protected_path: str,
        db_path: str,
        authorized: bool,
    ):
        """Creates a new Glue instance with passed configuration.

        Args:
            paseto_key (bytes): A bytes-like secret to generate a PASETO key
            pastes_path (str): Path to where new unprotected pastes should save to
            protected_path (str): Path to where new protected pastes should save to
                If `authorized` is False, will be neglected
            db_path (str): Path to an SQLite3 file to save records to
            authorized (bool): True to enable read protection and user/role models,
                False to only function as pastes processor
        """
        self.logger = logging.getLogger(__name__)
        if not db_path:
            raise TypeError("The path to the DB is empty")
        if not pastes_path:
            self.logger.warning(
                """Warning: the path to pastes is empty. 
                New pastes will be created in the same directory as the process."""
            )
        if not protected_path and authorized:
            self.logger.warning("Warning: the path to protected pastes is empty.")
        self.dbpath = db_path
        self.filepath = pastes_path
        self.protected_filepath = protected_path
        self.authorized = authorized
        self.paseto_key = Key.new(version=4, purpose="local", key=paseto_key)
        self.paseto = Paseto(leeway=60)
        with connect(self.dbpath) as conn:
            cursor = conn.cursor()
            if self.authorized:
                cursor.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password BLOB NOT NULL,
                    privileges INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    uid INTEGER NOT NULL,
                    token TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY (uid) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS api_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    expires_at INTEGER,
                    privileges INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS pastes (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL DEFAULT 'untitled',
                    author TEXT,
                    type TEXT NOT NULL DEFAULT 'txt',
                    protected INTEGER NOT NULL DEFAULT FALSE,
                    meta TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    expires_at TEXT,
                    FOREIGN KEY (author) REFERENCES users (username)
                );
                """)
            else:
                cursor.executescript("""
                    CREATE TABLE IF NOT EXISTS pastes (
                        id TEXT PRIMARY KEY,
                        title TEXT NOT NULL DEFAULT 'untitled',
                        author TEXT,
                        type TEXT NOT NULL DEFAULT 'txt',
                        meta TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL DEFAULT (datetime('now')),
                        expires_at TEXT
                    );
                """)
            conn.commit()
            if self.authorized:
                user_count = self.query("SELECT COUNT(*) FROM users")[0][0]
                if not user_count:
                    self.logger.warning(
                        "No users found. Creating root user admin:admin. Change the password after logging in!"
                    )
                    self.register_user("admin", "admin", VALIDATION_MASK)

    def query(self, query: str, params: tuple = (), out_dict: bool = False) -> list:
        """Performs a thread-safe query.

        Args:
            query (str): The SQL query
            params (tuple): Parameters to pass into the query
            out_dict (bool): True if the result should be returned as a list of dicts,
                False if as a list of tuples
        Returns:
            list: All results of the query.
        """
        with connect(self.dbpath) as conn:
            if out_dict:
                conn.row_factory = Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()
            if out_dict:
                result = [dict(row) for row in result]
            conn.commit()
            return result

    def is_permitted(self, user_id: int, privilege: int) -> bool:
        """Check if the user has the required permissions.

        Args:
            user_id (int): The user ID to check
            privilege (int): Required permission integer
        Returns:
            bool: True if the user has the required permissions, False otherwise.

        Raises:
            ValueError: If privileges or user ID is negative or invalid
            TypeError: If privileges or user ID is not an integer
            KeyError: If user was not found
        """
        if not isinstance(user_id, int):
            raise TypeError("User ID must be an integer")
        if user_id < 0:
            raise ValueError("User ID cannot be negative")
        if not isinstance(privilege, int):
            raise TypeError("Privileges must be an integer")
        if privilege < 0:
            raise TypeError("Privileges cannot be negative")
        if privilege & VALIDATION_MASK != privilege:
            raise ValueError("Privileges integer must be a bitwise OR of individual permissions")
        try:
            real = self.query("SELECT privileges FROM users WHERE id = ?", (user_id,))
            return real[0][0] & privilege == privilege
        except IndexError as e:
            raise KeyError("User not found") from e

    @staticmethod
    def get_item(
            store: dict,
            key: str | int | bool | float,
            default: Any = None,
            types: Type[Any] | tuple = None,
            pop: bool = False
    ) -> Any:
        """Retrieves a value from a dictionary,
            defaulting to a specified value and checking type.

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
            raise TypeError("Store must a dict")
        if not isinstance(key, (int, float, str, bool)):
            raise TypeError("Key must be immutable")
        if not isinstance(pop, bool):
            raise TypeError("Pop must be a bool")
        item = (store.get, store.pop)[int(pop)](key, default)
        if types is None or isinstance(item, types):
            return item
        raise TypeError("Value of wrong type")


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
            raise TypeError("Work factor must be an integer")
        if not 4 <= factor < 32:  # noqa: PLR2004   shut the fuck up
            raise ValueError("Provided work factor is outside the allowed range")
        return gensalt(rounds=factor)

    @staticmethod
    def hash(value: str, salt: bytes) -> bytes:
        """Hashes a password using bcrypt.

        Args:
            value (str): The password to hash. Will be truncated to 32 characters
            salt (bytes): The salt to add
        Returns:
            bytes: Hashed result in bytes.

        Raises:
            TypeError: Provided password is not a string or salt is not bytes
            ValueError: Provided password is empty
        """
        if not isinstance(value, str):
            raise TypeError("Password must be a string")
        if not value:
            raise ValueError("Password cannot be empty")
        if not isinstance(salt, bytes):
            raise TypeError("Salt must be bytes")
        value = value[:32]
        try:
            return hashpw(password=value.encode("utf-8"), salt=salt)
        except Exception as e:
            raise ValueError("Hashing failed") from e

    @staticmethod
    def compare(true: bytes, suggestion: str) -> bool:
        """Compares the true value hash to provided password.

        Args:
            true (bytes): The true value hash
            suggestion (str): The suggested password. Will be truncated to 32 characters
        Returns:
            bool: True if passwords match, False otherwise.

        Raises:
            TypeError: Provided hash is not bytes or suggestion is not a string
            ValueError: Provided suggestion is empty or verification failed
        """
        if not isinstance(suggestion, str):
            raise TypeError("Suggested password is not a string")
        if not suggestion:
            raise ValueError("Suggested password is empty")
        if not isinstance(true, bytes):
            raise TypeError("True password is not bytes")
        suggestion = suggestion[:32]
        try:
            return hashpw(password=suggestion.encode("utf-8"), salt=true) == true
        except Exception as e:
            raise ValueError("Verification failed") from e

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

    def register_user(self, username: str, password: str, privileges: int = 0) -> int:
        """Registers a new user.

        Args:
            username (str): The login. <24 >=4 characters
            password (str): The password. <36 >=4 characters
            privileges (int): An integer of user's permissions.

        Returns:
            int: New user ID.

        Raises:
            ValueError: If some of the arguments exceed the length limit or are invalid,
                or username already exists
            TypeError: If some of the arguments are of wrong type
            RuntimeError: If insertion failed
        """
        if not isinstance(username, str):
            raise TypeError("Username must be a string")
        if not isinstance(password, str):
            raise TypeError("Password must be a string")
        if not fullmatch(USERNAME_RE, username):
            raise ValueError("Username contains bad characters or of incorrect length")
        if not fullmatch(PASSWORD_RE, password):
            raise ValueError("Password contains bad characters or of incorrect length")
        if privileges < 0:
            raise ValueError("Privileges integer cannot be negative")
        if privileges & VALIDATION_MASK != privileges:
            raise ValueError("Privileges integer must be a bitwise OR of individual permissions")
        salt = self.salt()
        hashed = self.hash(password, salt)
        try:
            return self.query(
                """INSERT INTO users (
                    username, 
                    password, 
                    privileges
                ) VALUES (?, ?, ?) RETURNING id""",
                (username, hashed, privileges),
            )[0][0]
        except (IndexError, IntegrityError) as e:
            raise RuntimeError("Insertion of user failed") from e

    def login(
        self, username: str, password: str, remember: bool = True
    ) -> tuple[int, str | None, str]:
        """Logs in a user. Produces access & refresh tokens.

        Args:
            username (str): The login. <24 >=4 characters
            password (str): The password. <36 >=4 characters
            remember (bool): True if the app should generate
                a pair of refresh & access tokens, False if only the access token
        Returns:
            tuple[str, str]: A tuple of User ID, refresh
                (None if user is not remembered) and access tokens.

        Raises:
            TypeError: If some of the arguments are not a string
            ValueError: If credentials are incorrect or invalid
            KeyError: If the user was not found
            RuntimeError: If the user's concurrent session count exceeds limit
        """
        if not isinstance(username, str):
            raise TypeError("Username must be a string")
        if not isinstance(password, str):
            raise TypeError("Password must be a string")
        if not isinstance(remember, bool):
            raise TypeError("Remember_me option must be a bool")
        if not fullmatch(USERNAME_RE, username):
            raise ValueError("Username contains bad characters or of incorrect length")
        if not fullmatch(PASSWORD_RE, password):
            raise ValueError("Password contains bad characters or of incorrect length")
        try:
            uid, true_password = self.query(
                "SELECT id, password FROM users WHERE username = ?", (username,)
            )[0]
            if not self.compare(true_password, password):
                raise ValueError("Incorrect credentials")
            if remember:
                session_count = self.query("SELECT COUNT(*) FROM sessions WHERE uid = ?", (uid,))[0][0]
                if session_count > CONCURRENT_SESSIONS:
                    raise RuntimeError("Concurrent session count exceeds limit")
                refresh_token = token_urlsafe(64)
                access_token = self.paseto.encode(
                    self.paseto_key,
                    payload={
                        "uid": uid,
                    },
                    exp=300,
                ).decode("utf-8")
                expiration_time = (datetime.now(UTC) + timedelta(days=7)).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                self.query(
                    "INSERT INTO sessions (uid, token, expires_at) VALUES (?, ?, ?)",
                    (uid, refresh_token, expiration_time),
                )
                return uid, refresh_token, access_token
            access_token = self.paseto.encode(
                self.paseto_key,
                payload={
                    "uid": uid,
                },
                exp=1800,
            ).decode("utf-8")
            return uid, None, access_token
        except IndexError as e:
            raise KeyError("User was not found") from e

    def refresh_access(self, refresh_token: str) -> str:
        """Produces the access token using the refresh token.

        Args:
            refresh_token (str): The associated refresh token
        Returns:
            str: Newly generated access token
        Raises:
            TypeError: If the refresh token is not a string
            ValueError: If the refresh token is invalid or expired
        """
        if not isinstance(refresh_token, str):
            raise TypeError("Refresh token must be a string")
        try:
            session_id, uid, expires_at = self.query(
                "SELECT id, uid, expires_at FROM sessions WHERE token = ?",
                (refresh_token,),
            )[0]
            if datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=UTC
            ) < datetime.now(UTC):
                self.query("DELETE FROM sessions WHERE id = ?", (session_id,))
                raise ValueError("Refresh token has expired")
            return self.paseto.encode(
                self.paseto_key,
                payload={
                    "uid": uid,
                },
                exp=300,
            ).decode("utf-8")
        except IndexError as e:
            raise ValueError("Refresh token is invalid") from e

    def logout(self, refresh_token: str, user_id: int) -> None:
        """Invalidates the refresh token.

        Args:
            refresh_token (str): The session token to burn
            user_id (int): The ID of a user that requested logout
        Returns:
            Nothing.

        Raises:
            TypeError: If the token is not a string
            ValueError: If the token is already invalid or never existed
            PermissionError: If the user that requests logout
                does not match the session owner
        """
        if not isinstance(refresh_token, str):
            raise TypeError("Refresh token must be a string")
        if not isinstance(user_id, int):
            raise TypeError("User ID must be an integer")
        if user_id < 0:
            raise ValueError("User ID cannot be negative")
        try:
            if (
                int(self.query("SELECT uid FROM sessions WHERE text = ?", (user_id,))[0][0])
                != user_id
            ):
                raise PermissionError("User ID does not match that of session owner")
            self.query("DELETE FROM sessions WHERE text = ?", (refresh_token,))
        except IndexError as e:
            raise ValueError("Token is already invalid or never existed") from e

    def verify(self, access_token: str) -> int | None:
        """Verifies the validity of an access token.

        Args:
            access_token (str): The access token to check
        Returns:
            int: The user ID if token is valid, None otherwise.

        Raises:
            TypeError: If the token is not a string
        """
        if not isinstance(access_token, str):
            raise TypeError("Access token must be a string")
        try:
            decoded = self.paseto.decode(self.paseto_key, access_token.encode("utf-8"))
            payload = loads(decoded.payload.decode("utf-8"))
            exp_str = payload.get("exp")
            if exp_str:
                exp_time = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
                if datetime.now().astimezone() > exp_time:
                    raise ValueError("Token has expired")
                return payload.get("uid")
            raise ValueError("Expiration marking is missing")
        except (VerifyError, ValueError, DecryptError):
            return None

    def update_privileges(self, user_id: int, new_privileges: int) -> None:
        """Updates user's privileges.

        Args:
            user_id (int): User ID to edit. Trusts caller that the user exists
            new_privileges (int): Privileges integer to set
        Returns:
            Nothing.

        Raises:
            ValueError: If privileges or user ID is negative or invalid
            TypeError: If privileges or user ID is not an integer
            KeyError: User was not found
        """
        if not isinstance(user_id, int):
            raise TypeError("User ID must be an integer")
        if not isinstance(new_privileges, int):
            raise TypeError("Privileges level must be an integer")
        if new_privileges & VALIDATION_MASK != new_privileges:
            raise ValueError("Privileges integer must be a bitwise OR of individual permissions")
        if user_id < 0:
            raise ValueError("User ID cannot be negative")
        if new_privileges < 0:
            raise ValueError("Privileges cannot be negative")
        if not self.query(
            "UPDATE users SET privileges = ? WHERE id = ? RETURNING *",
            (new_privileges, user_id),
        ):
            raise KeyError("User was not found")

    def delete_user(self, user_id: int) -> None:
        """Blindly deletes a user. Use cautiously!

        Args:
            user_id (int): The ID of the user to delete
        Returns:
            Nothing.

        Raises:
            TypeError: If user ID is not an integer
            ValueError: If user ID is negative
            KeyError: If user was not found
        """
        if not isinstance(user_id, int):
            raise TypeError("User ID must be an integer")
        if user_id < 0:
            raise ValueError("User ID cannot be negative")
        if not self.query("DELETE FROM users WHERE id = ? RETURNING *", (user_id,)):
            raise KeyError("User was not found")

    def is_protected(self, paste_id: str) -> bool:
        """Checks if a paste is read-protected.

        Args:
            paste_id (str): The ID of a paste to check
        Returns:
            bool: True if the paste is read-protected, False otherwise.

        Raises:
            TypeError: If the paste ID is not a string
            KeyError: If the paste was not found
        """
        if not isinstance(paste_id, str):
            raise TypeError("Paste ID must be a string")
        try:
            return self.query("SELECT protected FROM pastes WHERE id = ?", (paste_id,))[0][0]
        except IndexError as e:
            raise KeyError("Paste was not found") from e

    def read_paste(self, paste_id: str) -> dict:
        """Reads a paste and it's metadata.

        Args:
            paste_id (str): The ID of a paste to read
        Returns:
            dict: A dictionary of paste content, author, filetype, creation time
                and a dict of additional metadata.

        Raises:
            TypeError: If the paste ID is not a string
            ValueError: If the paste ID or user ID is invalid or malicious
            KeyError: If the paste is not found or expired
            PermissionError: If the user is forbidden to access a paste
        """
        if not isinstance(paste_id, str):
            raise TypeError("Paste ID must be a string")
        if not fullmatch(ID_CHARACTER_RE, paste_id):
            raise ValueError("Paste ID is invalid")
        try:
            if self.authorized:
                result = self.query(
                    """SELECT author, type, protected, meta, created_at, expires_at 
                    FROM pastes 
                    WHERE id = ?""",
                    (paste_id,),
                    out_dict=True,
                )[0]
                protected = result.get("protected")
                author = result.get("author")
                filetype = result.get("type")
                created_at = datetime.strptime(result.get("created_at"), "%Y-%m-%d %H:%M:%S")
                expires_at = result.get("expires_at")
                meta = loads(result.get("meta"))
                if expires_at and datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S") < datetime.now(
                    UTC
                ):
                    self.query("DELETE FROM pastes WHERE id = ?", (paste_id,))
                    remove(path.join(self.filepath, paste_id))
                    raise TimeoutError("Paste expired")
                if not protected:
                    with open(path.join(self.filepath, paste_id), encoding="utf-8") as file:
                        content = file.read()
                else:
                    # ... probably should decrypt stuff ...
                    with open(
                        path.join(self.protected_filepath, paste_id), encoding="utf-8"
                    ) as file:
                        content = file.read()
                returnable = {
                    "content": content,
                    "type": filetype,
                    "created_at": created_at,
                    "meta": meta,
                }
                if author:
                    returnable["author"] = author
                if expires_at:
                    returnable["expires_at"] = expires_at
                return returnable
            result = self.query(
                """SELECT author, type, meta, created_at, expires_at 
                FROM pastes 
                WHERE id = ?""",
                (paste_id,),
                out_dict=True,
            )[0]
            author = result.get("author")
            filetype = result.get("type")
            created_at = datetime.strptime(result.get("created_at"), "%Y-%m-%d %H:%M:%S")
            expires_at = result.get("expires_at")
            meta = loads(result.get("meta"))
            if expires_at and datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S") < datetime.now(
                UTC
            ):
                self.query("DELETE FROM pastes WHERE id = ?", (paste_id,))
                remove(path.join(self.filepath, paste_id))
                raise TimeoutError("Paste expired")
            with open(path.join(self.filepath, paste_id), encoding="utf-8") as file:
                content = file.read()
            returnable = {
                "content": content,
                "type": filetype,
                "created_at": created_at,
                "meta": meta,
            }
            if author:
                returnable["author"] = author
            if expires_at:
                returnable["expires_at"] = expires_at
            return returnable
        except (IndexError, FileNotFoundError) as e:
            raise KeyError("The paste was not found") from e

    def read_paste_raw(self, paste_id: str) -> str:
        """Reads a paste content. Will not read protected pastes.

        Args:
            paste_id (str): The ID of a paste to read
        Returns:
            str: The content of the paste.

        Raises:
            TypeError: If the paste ID is not a string
            ValueError: If the paste ID is invalid or malicious
            FileNotFoundError: If the paste was not found
        """
        if not isinstance(paste_id, str):
            raise TypeError("Paste ID must be a string")
        if not fullmatch(ID_CHARACTER_RE, paste_id):
            raise ValueError("Paste ID is invalid")
        try:
            with open(path.join(self.filepath, paste_id), encoding="utf-8") as file:
                return file.read()
        except FileNotFoundError:
            raise FileNotFoundError(
                "Paste was not found"
            ) from None  # sanitizing internal error for logging

    def insert_paste(self, content: str, uid: int | None, meta: dict = None) -> str:
        """Creates a paste with metadata and produces a unique ID.

        Args:
            content (str): The content of the paste. Saved raw
            meta (dict): A dictionary of metadata.
                Author, type, protected and expires_at will be parsed.
            uid (int): The user ID of the poster
        Returns:
            str: The unique ID of a newly created paste.

        Raises:
            TypeError: If content or some metadata keys are of wrong type
            ValueError: If some metadata keys are invalid or not serializable
            KeyError: If the poster's ID doesn't exist
            RuntimeError: If generating a new ID failed
        """
        if not isinstance(content, str):
            raise TypeError("Content must be a string")
        if meta is None:
            meta = {}
        if not isinstance(meta, dict):
            raise TypeError("Metadata must be a dictionary or None")
        if not isinstance(uid, (int, type(None))):
            raise TypeError("User ID must be an integer or None")
        paste_id = self.generate_unique_id()

        info = meta.copy()  # Copying to prevent accidentally overwriting anything

        title = self.get_item(info,"title", "Untitled", str, True)
        expires_at = self.get_item(info, "expires_at", None, (datetime, type(None)), True)
        filetype = self.get_item(info, "filetype", "txt", str, pop=True)
        if expires_at:
            expires_at = datetime.strftime(expires_at, "%Y-%m-%d %H:%M:%S")
        if self.authorized:
            protected = self.get_item(info, "protect", False, bool, pop=True)
            author = None
            if self.get_item(info, "sign", True, bool, True):
                try:
                    author = self.query("SELECT username FROM users WHERE id = ?", (uid,))[0][0]
                except IndexError:
                    raise KeyError("User was not found")
            self.query(
                """INSERT INTO pastes (
                    id,
                    title,
                    author, 
                    type, 
                    protected, 
                    meta, 
                    expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (paste_id, title, author, filetype, protected, dumps(info), expires_at),
            )
            if not protected:
                with open(path.join(self.filepath, paste_id), mode="w", encoding="utf-8") as file:
                    file.write(content)
            else:
                # ... probably should encrypt stuff ...
                with open(
                        path.join(self.protected_filepath, paste_id), mode="w", encoding="utf-8"
                ) as file:
                    file.write(content)
            return paste_id
        author = self.get_item(info, "sign", None, (str, type(None)), True)
        self.query(
            """INSERT INTO pastes (
                id,
                title,
                author,
                type,
                meta,
                expires_at
            ) VALUES (?, ?, ?, ?, ?, ?)""",
            (paste_id, title, author, filetype, dumps(info), expires_at)
        )
        with open(path.join(self.filepath, paste_id), mode="w", encoding="utf-8") as file:
            file.write(content)
        return paste_id

    def cleanup(self) -> None:
        """Attempts to perform a cleanup of expired pastes and refresh tokens.

        Returns:
            Nothing.

        Raises:
            RuntimeError: If performing cleanup failed
        """
        try:
            self.query("DELETE FROM sessions WHERE expires_at < datetime('now')")
            files = self.query(
                "SELECT id, protected FROM pastes WHERE expires_at < datetime('now')"
            )
            if files:
                for file_id, protected in (i[0] for i in files):
                    if protected:
                        remove(path.join(self.protected_filepath, file_id))
                    else:
                        remove(path.join(self.filepath, file_id))
            self.query("DELETE FROM pastes WHERE expires_at < datetime('now')")
        except (OperationalError, FileNotFoundError, PermissionError) as e:
            raise RuntimeError("SQL querying failed") from e

    def delete_paste(self, paste_id: str) -> None:
        """Removes a paste by its ID.

        Args:
            paste_id (str): The paste ID.

        Returns:
            Nothing.

        Raises:
            KeyError: If paste associated with ID doesn't exist
            TypeError: If ``paste_id`` is not a string
            ValueError: If ``paste_id`` is an invalid ID
        """
        if not isinstance(paste_id, str):
            raise TypeError("Paste ID must be a string")
        if not fullmatch(ID_CHARACTER_RE, paste_id):
            raise ValueError("Paste ID is invalid")
        try:
            if self.authorized:
                protected = self.query(
                    "DELETE FROM pastes WHERE id = ? RETURNING protected", (paste_id,)
                )[0][0]
                remove(path.join(self.protected_filepath if protected else self.filepath, paste_id))
            else:
                self.query("DELETE FROM pastes WHERE id = ?", (paste_id,))
                remove(path.join(self.filepath, paste_id))
        except (FileNotFoundError, IndexError):
            raise KeyError("Paste does not exists") from None
