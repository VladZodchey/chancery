"""
Notes:
    [12.07.25] I'm a lazy ass so "privileges" and "permissions" are used interchangeably. Sorry about that.
    [12.07.25] Currently, input validation in DB glue is bloated, but I can't wrap my head around refactoring it without compromising safety.
    [13.07.25] Writing the security kind of stuff for the DB glue gives me the subconscious feeling of me missing some low-hanging vulnerability.
    [14.07.25] The @require_auth decorator feels sus.
    [14.07.25] Apparently the ``pyseto`` library doesn't actually check expiration, so I'll have to do it manually.
Todo:
    - Cleanup route that triggers paste and session expiration checks
    - Limit concurrent sessions (per user) to 5
    - When enabling CORS, add option to allow user registration only to LAN
    - Encrypt read-protected files
    - Implement API endpoints (including rewriting db.read_paste security)
"""
from typing import Optional, Callable
from json import loads, dumps
from string import ascii_letters, digits
from functools import wraps

from sqlite3 import connect, Row, IntegrityError
from bcrypt import hashpw, gensalt
from secrets import token_urlsafe, token_bytes, choice
from datetime import timedelta, datetime, UTC

from pyseto import Key, Paseto
from pyseto.exceptions import VerifyError, DecryptError
from dotenv import load_dotenv
from base64 import b64decode
from os import environ, path, remove

from flask import Flask, request, abort, Response
from http import HTTPStatus
from re import fullmatch

# Base permission integers
NONE = 0        # 0
READ = 1 << 0   # 1
WRITE = 1 << 1  # 2
DELETE = 1 << 2 # 4 and so on...
API = 1 << 3
ADMIN = 1 << 4
VALIDATION_MASK = READ | WRITE | DELETE | API | ADMIN  # 31, biggest allowed permission integer

ID_CHARACTER_SET = ascii_letters + digits
ID_LENGTH = 7


class Glue:
    """A glue class for database interactions and user/paste business logic."""
    def __init__(
            self,
            paseto_key: bytes,
            pastes_path='./pastes',
            protected_path='./protected',
            db_path: str = 'file::memory:?cache=shared'):
        if not db_path:
            raise TypeError('The path to the DB is empty')
        if not pastes_path:
            print('Warning: the path to pastes is empty. New pastes will be created in the same directory as the process.')
        if not protected_path:
            print('Warning: the path to protected pastes is empty, protection will worsen. Chancery is not liable of any leaked information.')
        self.dbpath = db_path
        self.filepath = pastes_path
        self.protected_filepath = protected_path
        self.paseto_key = Key.new(version=4, purpose='local', key=paseto_key)
        self.paseto = Paseto(leeway=60)
        with connect(self.dbpath) as conn:
            cursor = conn.cursor()
            cursor.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password BLOB NOT NULL,
                privileges INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS pastes (
                id TEXT PRIMARY KEY,
                author TEXT,
                type TEXT NOT NULL DEFAULT 'txt',
                protected INTEGER NOT NULL DEFAULT FALSE,
                meta TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT,
                FOREIGN KEY (author) REFERENCES users (username)
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
            """)
            conn.commit()

    def query(self, query: str, params: tuple = (), out_dict: bool = False) -> list:
        """Performs a thread-safe query.

        Args:
            query (str): The SQL query
            params (tuple): Parameters to pass into the query
            out_dict (bool): True if the result should be returned as a list of tuples, False if as a list of dicts
        Returns:
            list: All results of the query.
        """
        with connect(self.dbpath) as conn:
            if out_dict:
                conn.row_factory = Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            result = cursor.fetchall()
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
            raise TypeError('User ID must be an integer')
        if user_id < 0:
            raise ValueError('User ID cannot be negative')
        if not isinstance(privilege, int):
            raise TypeError('Privileges must be an integer')
        if privilege < 0:
            raise TypeError('Privileges cannot be negative')
        if privilege & VALIDATION_MASK != privilege:
            raise ValueError('Privileges integer must be a bitwise OR of individual permissions')
        try:
            real = self.query('SELECT privileges FROM users WHERE id = ?', (user_id,))
            return real[0][0] & privilege == privilege
        except IndexError:
            raise KeyError(f'User not found: {user_id}')

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
            raise TypeError('Work factor must be an integer')
        if not 4 <= factor < 32:
            raise ValueError('Provided work factor is outside the allowed range')
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
            raise TypeError('Password must be a string')
        if not value:
            raise ValueError('Password cannot be empty')
        if not isinstance(salt, bytes):
            raise TypeError("Salt must be bytes")
        value = value[:32]
        try:
            return hashpw(password=value.encode('utf-8'), salt=salt)
        except Exception as e:
            raise ValueError(f'Hashing failed: {e}')

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
            raise TypeError('Suggested password is not a string')
        if not suggestion:
            raise ValueError('Suggested password is empty')
        if not isinstance(true, bytes):
            raise TypeError('True password is not bytes')
        suggestion = suggestion[:32]
        try:
            return hashpw(password=suggestion.encode('utf-8'), salt=true) == true
        except Exception as e:
            raise ValueError(f'Verification failed: {e}')

    @staticmethod
    def generate_id(length: int, symbols: str) -> str:
        """Generates a random cryptographically secure ID string.

        Args:
            length (int): The length of the ID
            symbols (str): The string of allowed possible characters
        Returns:
            str: An ID string.
        """
        return ''.join(choice(symbols) for _ in range(length))

    def generate_unique_id(self, attempts: int = 3) -> str:
        """Generates a random unique cryptographically secure ID string.

        Args:
            attempts (int): Number of attempts at generating an ID
        Returns:
            str: An unique ID string.
        Raises:
            RuntimeError: If attempts were unsuccessfully depleted
        """
        ids = map(lambda i: i[0], self.query("SELECT id FROM pastes"))
        for _ in range(attempts):
            new_id = self.generate_id(ID_LENGTH, ID_CHARACTER_SET)
            if new_id not in ids:
                return new_id
        raise RuntimeError('Attempts at generating an ID depleted unsuccessfully')

    def register_user(self, username: str, password: str, privileges: int = 0) -> int:
        """Registers a new user.

        Args:
            username (str): The login. <24 >=4 characters
            password (str): The password. <36 >=4 characters
            privileges (int): A custom TypedClass of bools of user's permissions.
        Returns:
            int: New user ID.
        Raises:
            ValueError: If some of the arguments exceed the length limit or are invalid, or username already exists
            TypeError: If some of the arguments are of wrong type
            RuntimeError: If insertion failed
        """
        if not isinstance(username, str):
            raise TypeError('Username must be a string')
        if not isinstance(password, str):
            raise TypeError('Password must be a string')
        if not 4 <= len(username) < 24:
            raise ValueError('Username length must be inside [4;24)')
        if not 4 <= len(password) < 36:
            raise ValueError('Password length must be inside [4;36)')
        if set(username) not in set(ID_CHARACTER_SET):
            raise ValueError('Username contains bad characters')
        if set(password) not in set(ID_CHARACTER_SET + '@&$#-_!?~*^%.,'):
            raise ValueError('Password contains bad characters')
        if privileges < 0:
            raise ValueError('Privileges integer cannot be negative')
        if privileges & VALIDATION_MASK != privileges:
            raise ValueError('Privileges integer must be a bitwise OR of individual permissions')
        salt = self.salt()
        hashed = self.hash(password, salt)
        try:
            return self.query(
                "INSERT INTO users (username, password, privileges) VALUES (?, ?, ?) RETURNING id",
                (username, hashed, privileges)
            )[0][0]
        except (IndexError, IntegrityError):
            raise RuntimeError('Insertion of user failed')

    def login(self, username: str, password: str, remember: bool = True) -> tuple[int, str | None, str]:
        """Logs in a user. Produces access & refresh tokens.

        Args:
            username (str): The login. <24 >=4 characters
            password (str): The password. <36 >=4 characters
            remember (bool): True if the app should generate a pair of refresh & access tokens, False if only the access token
        Returns:
            tuple[str, str]: A tuple of User ID, refresh (None if user is not remembered) and access tokens.
        Raises:
            TypeError: If some of the arguments are not a string
            ValueError: If credentials are incorrect or invalid
            KeyError: If the user was not found
        """
        if not isinstance(username, str):
            raise TypeError('Username must be a string')
        if not isinstance(password, str):
            raise TypeError('Password must be a string')
        if not isinstance(remember, bool):
            raise TypeError('Remember me option must be a bool')
        if not 4 <= len(username) < 24:
            raise ValueError('Username length must be inside [4;24)')
        if not 4 <= len(password) < 36:
            raise ValueError('Password length must be inside [4;36)')
        try:
            uid, true_password = self.query(
                "SELECT id, password FROM users WHERE username = ?",
                (username,)
            )[0]
            assert self.compare(true_password, password)
            if remember:
                refresh_token = token_urlsafe(64)
                access_token = self.paseto.encode(
                    self.paseto_key,
                    payload={
                        'uid': uid,
                    },
                    exp=300
                ).decode('utf-8')
                expiration_time = (datetime.now(UTC) + timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
                self.query(
                    "INSERT INTO sessions (uid, token, expires_at) VALUES (?, ?, ?)",
                    (uid, refresh_token, expiration_time)
                )
                return uid, refresh_token, access_token
            else:
                access_token = self.paseto.encode(
                    self.paseto_key,
                    payload={
                        'uid': uid,
                    },
                    exp=1800
                ).decode('utf-8')
                return uid, None, access_token
        except IndexError:
            raise KeyError('User was not found')
        except AssertionError:
            raise ValueError('Incorrect credentials')

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
            raise TypeError('Refresh token must be a string')
        try:
            session_id, uid, expires_at = self.query(
                "SELECT id, uid, expires_at FROM sessions WHERE token = ?",
                (refresh_token,)
            )[0]
            if datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S').replace(tzinfo=UTC) < datetime.now(UTC):
                self.query('DELETE FROM sessions WHERE id = ?', (session_id,))
                raise ValueError('Refresh token has expired')
            access_token = self.paseto.encode(
                self.paseto_key,
                payload={
                    'uid': uid,
                },
                exp=300
            ).decode('utf-8')
            return access_token
        except IndexError:
            raise ValueError('Refresh token is invalid')

    def logout(self, refresh_token: str) -> None:
        """Invalidates the refresh token.

        Args:
            refresh_token (str): The session token to burn
        Returns:
            Nothing.
        Raises:
            TypeError: If the token is not a string
            ValueError: If the token is already invalid
        """
        if not isinstance(refresh_token, str):
            raise TypeError('Refresh token must be a string')
        self.query('DELETE FROM sessions WHERE text = ?', (refresh_token,))  # this is a suspiciously fast exit

    def verify(self, access_token: str) -> Optional[int]:
        """Verifies the validity of an access token.

        Args:
            access_token (str): The access token to check
        Returns:
            int: The user ID if token is valid, None otherwise.
        Raises:
            TypeError: If the token is not a string
        """
        if not isinstance(access_token, str):
            raise TypeError('Access token must be a string')
        try:
            decoded = self.paseto.decode(self.paseto_key, access_token.encode('utf-8'))
            payload = loads(decoded.payload.decode('utf-8'))
            exp_str = payload.get('exp')
            if exp_str:
                exp_time = datetime.fromisoformat(exp_str.replace('Z', '+00:00'))
                if datetime.now().astimezone() > exp_time:
                    raise ValueError("Token has expired")
                else:
                    return payload.get('uid')
            raise ValueError('Expiration marking is missing')
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
            raise TypeError('User ID must be an integer')
        if not isinstance(new_privileges, int):
            raise TypeError('Privileges level must be an integer')
        if new_privileges & VALIDATION_MASK != new_privileges:
            raise ValueError('Privileges integer must be a bitwise OR of individual permissions')
        if user_id < 0:
            raise ValueError('User ID cannot be negative')
        if new_privileges < 0:
            raise ValueError('Privileges cannot be negative')
        if not self.query(
                'UPDATE users SET privileges = ? WHERE id = ? RETURNING *',
                (new_privileges, user_id)
        ):
            raise KeyError('User was not found')

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
            raise TypeError('User ID must be an integer')
        if user_id < 0:
            raise ValueError('User ID cannot be negative')
        if not self.query('DELETE FROM users WHERE id = ? RETURNING *', (user_id,)):
            raise KeyError('User was not found')

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
            raise TypeError('Paste ID must be a string')
        try:
            return self.query("SELECT protected FROM pastes WHERE id = ?", (paste_id,))[0][0]
        except IndexError:
            raise KeyError('Paste was not found')

    def read_paste(self, paste_id: str, user_id: Optional[int] = None) -> dict:
        """Reads a paste and it's metadata.

        Args:
            paste_id (str): The ID of a paste to read
            user_id (int): The ID of a user that reads the paste. If None, read-protected files will not be read
        Returns:
            dict: A dictionary of paste content, author, filetype, creation time and a dict of additional metadata.
        Raises:
            TypeError: If the paste ID is not a string
            ValueError: If the paste ID or user ID is invalid or malicious
            KeyError: If the paste is not found or expired
            PermissionError: If the user is forbidden to access a paste
        """
        if not isinstance(paste_id, str):
            raise TypeError('Paste ID must be a string')
        if not fullmatch(r'^[a-zA-Z0-9]+$', paste_id):
            raise ValueError('Paste ID is invalid')
        try:
            result = self.query(
                "SELECT author, type, protected, meta, created_at, expires_at FROM pastes WHERE id = ?",
                (paste_id,),
                out_dict=True
            )[0]
            if result.get('protected'):
                try:
                    assert self.is_permitted(user_id, READ)
                except (TypeError, KeyError, AssertionError):
                    raise PermissionError("You don't have enough rights to do that.")
            author = result.get('author')
            filetype = result.get('type')
            created_at = datetime.strptime(result.get('created_at'), '%Y-%m-%d %H:%M:%S')
            expires_at = result.get('expires_at')
            meta = loads(result.get('meta'))
            if expires_at and datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S') < datetime.now(UTC):
                self.query("DELETE FROM pastes WHERE id = ?", (paste_id,))
                remove(path.join(self.filepath, paste_id))
                raise TimeoutError('Paste expired')
            if not protected:
                with open(path.join(self.filepath, paste_id), encoding='utf-8') as file:
                    content = file.read()
            else:
                # ... probably should decrypt stuff ...
                with open(path.join(self.protected_filepath, paste_id), encoding='utf-8') as file:
                    content = file.read()
            returnable = {
                'content': content,
                'type': filetype,
                'created_at': created_at,
                'meta': meta
            }
            if author:
                returnable['author'] = author
            if expires_at:
                returnable['expires_at'] = expires_at
            return returnable
        except IndexError | FileNotFoundError:
            raise KeyError('The paste was not found')
        except TimeoutError as e:
            raise KeyError(e)

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
            raise TypeError('Paste ID must be a string')
        if not fullmatch(r'^[a-zA-Z0-9]+$', paste_id):
            raise ValueError('Paste ID is invalid')
        try:
            with open(path.join(self.filepath, paste_id), encoding='utf-8') as file:
                return file.read()
        except FileNotFoundError:
            raise FileNotFoundError('Paste was not found')  # sanitizing internal error for logging

    def insert_paste(self, content: str, meta: dict, uid: int) -> str:
        """Creates a paste with metadata and produces a unique ID.

        Args:
            content (str): The content of the paste. Saved raw
            meta (dict): A dictionary of metadata. Author, type, protected and expires_at will be parsed.
            uid (int): The user ID of the poster
        Returns:
            str: The unique ID of a newly created paste.
        Raises:
            TypeError: If content or some metadata keys are of wrong type
            ValueError: If some metadata keys are invalid or unserializable
            KeyError: If the poster's ID doesn't exist
            RuntimeError: If generating a new ID failed (attempts depleted, normally shouldn't happen)
        """
        if not isinstance(content, str):
            raise TypeError('Content must be a string')
        paste_id = self.generate_unique_id()
        sign_author = meta.get('author')
        author = None
        if sign_author:
            try:
                author = db.query('SELECT username FROM users WHERE id = ?', (uid,))[0][0]
            except IndexError:
                raise KeyError('User was not found')
        filetype = meta.get('type')
        protected = bool(meta.get('protected'))
        expires_at = meta.get('expires_at')
        if expires_at:
            expires_at = datetime.strftime(expires_at, '%Y-%m-%d %H:%M:%S')
        del meta['author']
        del meta['filetype']
        del meta['protected']
        del meta['expires_at']
        self.query(
            'INSERT INTO pastes (author, type, protected, meta, expires_at) VALUES (?, ?, ?, ?, ?)',
            (author, filetype, protected, dumps(meta), expires_at)
        )
        if not protected:
            with open(path.join(self.filepath, paste_id), mode='w', encoding='utf-8') as file:
                file.write(content)
        else:
            # ... probably should encrypt stuff ...
            with open(path.join(self.protected_filepath, paste_id), mode='w', encoding='utf-8') as file:
                file.write(content)
        return paste_id


app = Flask(__name__)


def require_auth(f: Callable) -> Callable:
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            abort(HTTPStatus.UNAUTHORIZED, description='Authentication header is missing')
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            abort(HTTPStatus.UNAUTHORIZED, description='Invalid authentication scheme. Use Bearer token')
        token = parts[1]
        try:
            uid = db.verify(token)
            if not uid:
                abort(HTTPStatus.UNAUTHORIZED, description='Invalid or expired token')
            return f(user_id=uid, *args, **kwargs)
        except TypeError as e:
            abort(HTTPStatus.BAD_REQUEST, description=f'Invalid token format {e}')
    return decorated


def optional_auth(f: Callable) -> Callable:
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return f(user_id=None, *args, **kwargs)
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            abort(HTTPStatus.UNAUTHORIZED, description='Invalid authentication scheme. Use Bearer token')
        token = parts[1]
        try:
            uid = db.verify(token)
            if not uid:
                abort(HTTPStatus.UNAUTHORIZED, description='Invalid or expired token')
            return f(user_id=uid, *args, **kwargs)
        except TypeError as e:
            abort(HTTPStatus.BAD_REQUEST, description=f'Invalid token format {e}')

    return decorated


@app.get('/protected')
@require_auth
def protected(user_id: int):
    return 'Oh noes! You accessed protected data! Whatever shall I do?'


@app.post('/login')
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    remember = data.get('remember')
    if not username or not password:
        abort(HTTPStatus.BAD_REQUEST, description='Credentials are missing')
    try:
        user_id, refresh_token, access_token = db.login(username, password, bool(remember))
        returnable = {
            'user_id': user_id,
            'access_token': access_token,
            'refresh_token': refresh_token
        }
        return Response(dumps(returnable), status=200)
    except TypeError:
        abort(HTTPStatus.BAD_REQUEST, description='Credentials are invalid')
    except ValueError:
        abort(HTTPStatus.BAD_REQUEST, description='Credentials are incorrect')
    except KeyError:
        abort(HTTPStatus.BAD_REQUEST, description='User not found')


@app.post('/refresh')
def refresh():
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    if refresh_token:
        try:
            access_token = db.refresh_access(refresh_token)
            return Response(dumps({'access_token': access_token, 'refresh_token': refresh_token}), 200)
        except (TypeError, ValueError):
            abort(HTTPStatus.UNAUTHORIZED, description='Refresh token is invalid or expired')
    abort(HTTPStatus.BAD_REQUEST, description='Refresh token missing')


@app.post('/register')
@require_auth
def register(user_id):
    if not db.is_permitted(user_id, ADMIN):
        abort(HTTPStatus.UNAUTHORIZED, description="You don't have enough rights to do that.")
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    privileges = data.get('permissions')
    try:
        uid = db.register_user(username, password, privileges)
        print(uid)
        return Response(dumps({'uid': uid}), 200)
    except (TypeError, ValueError) as e:
        abort(HTTPStatus.BAD_REQUEST, description=f'Credentials are invalid: {e}')
    except RuntimeError:
        abort(HTTPStatus.CONFLICT, description='User already exists')


@app.get('/raw')
def fetch_raw():
    paste_id = request.args.get('paste_id')
    if paste_id:
        try:
            return Response(db.read_paste_raw(paste_id), 200)
        except FileNotFoundError:
            abort(HTTPStatus.NOT_FOUND, description='Paste was not found')
        except (ValueError, TypeError):
            abort(HTTPStatus.BAD_REQUEST, description='Paste ID is invalid')
    abort(HTTPStatus.BAD_REQUEST, description='Paste ID missing')


@app.get('/fetch')
@optional_auth
def fetch(user_id):
    paste_id = request.args.get('paste_id')
    if paste_id:
        try:
            return Response(dumps(db.read_paste(paste_id, user_id)))
        except PermissionError:
            abort(HTTPStatus.FORBIDDEN, description='You have no rights to read that.')
        except KeyError:
            abort(HTTPStatus.NOT_FOUND, description='Paste was not found')
        except (TypeError, ValueError):
            abort(HTTPStatus.BAD_REQUEST, description='Paste ID is invalid')
    abort(HTTPStatus.BAD_REQUEST, description='Paste ID missing')


@app.post('/create')
@require_auth
def create(user_id):
    data = request.get_json()
    content = data.get('content')
    del data['content']
    try:
        if db.is_permitted(user_id, WRITE):
            return Response(db.insert_paste(content, data, user_id))
        abort(HTTPStatus.FORBIDDEN, description='You have no rights to write that.')
    except (ValueError, TypeError):
        abort(HTTPStatus.BAD_REQUEST, description='Paste content or metadata is malformed')
    except RuntimeError:
        abort(HTTPStatus.INTERNAL_SERVER_ERROR, description='Server failed generating unique link')
    except KeyError:
        abort(HTTPStatus.UNAUTHORIZED, description='Malformed authentication token')


if __name__ == '__main__':
    load_dotenv()
    pkey = environ.get('PASETO_SECRET')
    if not pkey:
        print('No PASETO secret set. Generating...')
        pkey = token_bytes(32)
    else:
        pkey = b64decode(pkey)
    dbpath = environ.get('DB_PATH')
    if not dbpath:
        print('No DB path set. Loading in memory...')
        db = Glue(paseto_key=pkey)
    else:
        db = Glue(db_path=dbpath, paseto_key=pkey)
    no_users = db.query("SELECT id FROM users")
    if not no_users:
        db.register_user('admin', 'admin', 31)
        print('Created default user admin:admin. Please change the password after logging in.')
    app.run(port=8888, host="0.0.0.0", debug=bool(environ.get('DEBUG')))