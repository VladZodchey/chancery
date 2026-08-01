from dataclasses import dataclass

from pydantic import BaseModel


class NewPaste(BaseModel):
    """Payload for creating a paste over the JSON API."""

    content: str
    password: str | None = None
    burn_after_read: bool = False
    ttl_seconds: int | None = None


class CreatedPaste(BaseModel):
    id: str
    url: str


class PasteOut(BaseModel):
    """Public view of a paste as returned by the JSON API."""

    id: str
    url: str
    content: str
    size_bytes: int
    encrypted: bool
    burn_after_read: bool
    created_at: int
    expires_at: int | None


@dataclass
class Paste:
    """A paste row plus its (possibly decrypted) content."""

    id: str
    content: bytes
    size_bytes: int
    encrypted: bool
    salt: bytes | None
    kdf_opslimit: int | None
    kdf_memlimit: int | None
    burn_after_read: bool
    created_at: int
    expires_at: int | None

    @property
    def text(self) -> str:
        return self.content.decode("utf-8")

    def is_expired(self, now: int) -> bool:
        return self.expires_at is not None and self.expires_at < now
