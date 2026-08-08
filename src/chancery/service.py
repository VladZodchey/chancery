import logging
import re
import sqlite3
import threading
import time

from nacl.exceptions import CryptoError

from . import crypto, ids
from .logging import log_event
from .models import CreatedPaste, Paste

logger = logging.getLogger(__name__)

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def validate_content(content: str) -> None:
    """Raise InvalidContent if the content contains unsafe control characters."""
    if _CONTROL_RE.search(content):
        raise InvalidContent("content must be UTF-8 text without control characters")


class PasteError(Exception):
    """Base class for domain errors."""


class PasteNotFound(PasteError):
    pass


class PasteNeedsPassword(PasteError):
    pass


class InvalidPassword(PasteError):
    pass


class PasteTooLarge(PasteError):
    pass


class InvalidContent(PasteError):
    pass


class InvalidTTL(PasteError):
    pass


class PasteService:
    """The single core of chancery.

    The web app, the raw TCP listener and the admin CLI all funnel through this
    class. All operations are serialized on a single SQLCipher connection
    guarded by a lock; burn-after-read is therefore atomic within one process.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        base_url: str,
        paste_max_size: int,
        max_ttl_seconds: int,
        paste_id_length: int,
        kdf_opslimit: int,
        kdf_memlimit: int,
    ) -> None:
        self._conn = conn
        self._lock = threading.Lock()
        self._base_url = base_url.rstrip("/")
        self._paste_max_size = paste_max_size
        self._max_ttl_seconds = max_ttl_seconds
        self._id_length = paste_id_length
        self._kdf_opslimit = kdf_opslimit
        self._kdf_memlimit = kdf_memlimit

    def close(self) -> None:
        self._conn.close()

    def resolve_url(self, paste_id: str) -> str:
        return f"{self._base_url}/{paste_id}"

    def create(
        self,
        content: str,
        *,
        password: str | None = None,
        burn_after_read: bool = False,
        ttl_seconds: int | None = None,
    ) -> CreatedPaste:
        if not content:
            raise InvalidContent("content must not be empty")
        validate_content(content)

        encoded = content.encode("utf-8")
        if len(encoded) > self._paste_max_size:
            raise PasteTooLarge(f"content is {len(encoded)} bytes, limit is {self._paste_max_size}")

        if ttl_seconds is not None and (ttl_seconds <= 0 or ttl_seconds > self._max_ttl_seconds):
            raise InvalidTTL(f"ttl_seconds must be between 1 and {self._max_ttl_seconds}")

        now = int(time.time())
        expires_at = now + ttl_seconds if ttl_seconds is not None else None

        with self._lock:
            paste_id = self._generate_unique_id()
            if password:
                ciphertext, salt, ops, mem = crypto.encrypt(
                    encoded, password, self._kdf_opslimit, self._kdf_memlimit
                )
                encrypted = 1
                stored = ciphertext
            else:
                encrypted = 0
                stored = encoded
                salt = None
                ops = None
                mem = None

            self._conn.execute(
                "INSERT INTO pastes "
                "(id, content, size_bytes, encrypted, salt, kdf_opslimit, "
                "kdf_memlimit, burn_after_read, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    paste_id,
                    stored,
                    len(encoded),
                    encrypted,
                    salt,
                    ops,
                    mem,
                    int(burn_after_read),
                    now,
                    expires_at,
                ),
            )
            self._conn.commit()

        log_event(
            logger,
            "paste created",
            private={
                "id": paste_id,
                "size": len(encoded),
                "encrypted": bool(password),
                "burn_after_read": burn_after_read,
                "ttl_seconds": ttl_seconds,
            },
        )
        return CreatedPaste(id=paste_id, url=self.resolve_url(paste_id))

    def get(self, paste_id: str, *, password: str | None = None) -> Paste:
        now = int(time.time())
        with self._lock:
            row = self._conn.execute("SELECT * FROM pastes WHERE id = ?", (paste_id,)).fetchone()
            if row is None:
                raise PasteNotFound(paste_id)

            paste = self._row_to_paste(row)
            if paste.is_expired(now):
                self._conn.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
                self._conn.commit()
                log_event(logger, "paste expired, deleted", private={"id": paste_id})
                raise PasteNotFound(paste_id)

            if paste.encrypted:
                if password is None:
                    raise PasteNeedsPassword(paste_id)
                salt = paste.salt
                opslimit = paste.kdf_opslimit
                memlimit = paste.kdf_memlimit
                assert salt is not None and opslimit is not None and memlimit is not None
                try:
                    paste.content = crypto.decrypt(
                        paste.content,
                        password,
                        salt,
                        opslimit,
                        memlimit,
                    )
                except CryptoError:
                    log_event(logger, "invalid password attempt", private={"id": paste_id})
                    raise InvalidPassword(paste_id) from None

            if paste.burn_after_read:
                self._conn.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
                self._conn.commit()
                log_event(
                    logger,
                    "paste read (burn-after-read: deleted)",
                    private={"id": paste_id},
                )
            else:
                log_event(logger, "paste read", private={"id": paste_id})

            return paste

    def delete(self, paste_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM pastes WHERE id = ?", (paste_id,))
            self._conn.commit()
            deleted = cur.rowcount > 0
        if deleted:
            log_event(logger, "paste deleted", private={"id": paste_id})
        return deleted

    def list(self, *, limit: int = 50, offset: int = 0) -> list[Paste]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM pastes ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [self._row_to_paste(row) for row in rows]

    def purge_expired(self, *, now: int | None = None) -> int:
        now = now if now is not None else int(time.time())
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            self._conn.commit()
            removed = cur.rowcount
        if removed:
            logger.info("purged %d expired pastes", removed)
        return removed

    def stats(self) -> dict[str, int]:
        now = int(time.time())
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM pastes").fetchone()[0]
            total_bytes = self._conn.execute(
                "SELECT COALESCE(SUM(size_bytes), 0) FROM pastes"
            ).fetchone()[0]
            encrypted = self._conn.execute(
                "SELECT COUNT(*) FROM pastes WHERE encrypted = 1"
            ).fetchone()[0]
            burn = self._conn.execute(
                "SELECT COUNT(*) FROM pastes WHERE burn_after_read = 1"
            ).fetchone()[0]
            expired = self._conn.execute(
                "SELECT COUNT(*) FROM pastes WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            ).fetchone()[0]
        return {
            "pastes": total,
            "bytes": total_bytes,
            "encrypted": encrypted,
            "burn_after_read": burn,
            "expired": expired,
        }

    def _generate_unique_id(self) -> str:
        while True:
            paste_id = ids.new_id(self._id_length)
            exists = self._conn.execute("SELECT 1 FROM pastes WHERE id = ?", (paste_id,)).fetchone()
            if exists is None:
                return paste_id

    def _row_to_paste(self, row) -> Paste:
        return Paste(
            id=row["id"],
            content=row["content"],
            size_bytes=row["size_bytes"],
            encrypted=bool(row["encrypted"]),
            salt=row["salt"],
            kdf_opslimit=row["kdf_opslimit"],
            kdf_memlimit=row["kdf_memlimit"],
            burn_after_read=bool(row["burn_after_read"]),
            created_at=row["created_at"],
            expires_at=row["expires_at"],
        )
