from pathlib import Path

from nacl import bindings
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration, read from ``CHANCERY_*`` environment variables.

    A ``.env`` file in the working directory is also honored.
    """

    model_config = SettingsConfigDict(
        env_prefix="CHANCERY_",
        env_file=".env",
        extra="ignore",
    )

    db_path: Path = Path("chancery.db")
    db_key: SecretStr = SecretStr("")
    db_key_file: Path | None = None

    base_url: str = "http://127.0.0.1:8000"

    expected_host: str | None = None
    forwarded_allow_ips: str = ""
    log_level: str = "INFO"

    rate_limit_enabled: bool = True
    rate_limit: str = "60/minute"

    paste_max_size: int = 1_000_000
    max_ttl_seconds: int = 30 * 24 * 60 * 60
    paste_id_length: int = 10

    tcp_enabled: bool = False
    tcp_host: str = "127.0.0.1"
    tcp_port: int = 9999
    tcp_connect_timeout: float = 60.0
    tcp_crawler_filter: bool = True

    kdf_opslimit: int = bindings.crypto_pwhash_argon2id_OPSLIMIT_MODERATE
    kdf_memlimit: int = bindings.crypto_pwhash_argon2id_MEMLIMIT_MODERATE

    def require_key(self) -> str:
        if self.db_key_file is not None:
            path = self.db_key_file
            try:
                key = path.read_text(encoding="utf-8")
            except OSError as exc:
                raise RuntimeError(f"CHANCERY_DB_KEY_FILE {path} could not be read: {exc}") from exc
            key = key.strip()
            if not key:
                raise RuntimeError(f"CHANCERY_DB_KEY_FILE {path} is empty")
            return key
        key = self.db_key.get_secret_value()
        if not key:
            raise RuntimeError(
                "CHANCERY_DB_KEY is not set; refusing to run with an unencrypted database"
            )
        return key
