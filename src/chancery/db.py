import re
import sqlite3
from contextlib import suppress
from pathlib import Path
from typing import Any, cast

import sqlcipher3 as _sqlcipher3

# this fixes sqlcipher3 typing.
sqlcipher3: Any = cast(Any, _sqlcipher3)

_HEX_KEY = re.compile(r"^[0-9a-fA-F]{64}$")

MIGRATIONS: list[str] = [
    """
    CREATE TABLE pastes (
        id TEXT PRIMARY KEY,
        content BLOB NOT NULL,
        size_bytes INTEGER NOT NULL,
        encrypted INTEGER NOT NULL DEFAULT 0,
        salt BLOB,
        kdf_opslimit INTEGER,
        kdf_memlimit INTEGER,
        burn_after_read INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL,
        expires_at INTEGER
    );
    CREATE INDEX idx_pastes_expires_at ON pastes (expires_at);
    """,
]


def key_sql(key: str) -> str:
    """SQL literal for an encryption key.

    A 64-character hex key is treated as a raw key (``x'...'`` form); anything
    else is treated as a passphrase. The passphrase form is weaker and exists
    only for convenience.
    """
    if _HEX_KEY.fullmatch(key):
        return f'"x\'{key.lower()}\'"'
    return f"'{key.replace(chr(39), chr(39) * 2)}'"


def open_database(path: Path, key: str) -> sqlite3.Connection:
    """Open an SQLCipher database, setting up the encryption key and pragmas."""
    if not key:
        raise ValueError("an encryption key is required to open the database")

    conn = sqlcipher3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlcipher3.Row

    conn.execute(f"PRAGMA key = {key_sql(key)}")

    # Hardening pragma; not supported by every SQLCipher build.
    with suppress(sqlcipher3.DatabaseError):
        conn.execute("PRAGMA cipher_memory_security = ON")

    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Apply pending migrations, tracked via ``PRAGMA user_version``."""
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    for target, ddl in enumerate(MIGRATIONS, start=1):
        if version < target:
            conn.executescript(ddl)
            conn.execute(f"PRAGMA user_version = {target}")
    conn.commit()


def rekey_database(path: Path, old_key: str, new_key: str) -> None:
    """Re-encrypt the database with a new key.

    This relies on SQLCipher's ``PRAGMA rekey``, which writes the re-encrypted
    copy to a temporary file in the same directory and swaps it over the
    original only once the copy is fully written. An interruption therefore
    leaves the original database untouched.
    """
    if not new_key:
        raise ValueError("the new key must not be empty")

    try:
        conn = open_database(path, old_key)
    except sqlcipher3.DatabaseError as exc:
        raise ValueError("could not open the database with the current key") from exc
    try:
        try:
            conn.execute("SELECT count(*) FROM sqlite_master")
        except sqlcipher3.DatabaseError as exc:
            raise ValueError("could not open the database with the current key") from exc
        conn.execute(f"PRAGMA rekey = {key_sql(new_key)}")
        check = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if check != "ok":
            raise RuntimeError(f"integrity check after rekey failed: {check}")
    finally:
        conn.close()

    # A rekey interrupted before the swap leaves a partial temporary file
    # behind; it holds data encrypted with the old key, so drop it.
    leftover = Path(f"{path}-tmp")
    if leftover.exists():
        leftover.unlink(missing_ok=True)
