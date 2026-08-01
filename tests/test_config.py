import pytest

from chancery.config import Settings


def test_require_key_from_file(tmp_path):
    key_file = tmp_path / "db.key"
    key_file.write_text("deadbeef" * 4 + "\n")
    settings = Settings(db_key_file=key_file)
    assert settings.require_key() == "deadbeef" * 4


def test_require_key_from_file_strips_whitespace(tmp_path):
    key_file = tmp_path / "db.key"
    key_file.write_text("  abc123  \n")
    settings = Settings(db_key_file=key_file)
    assert settings.require_key() == "abc123"


def test_require_key_file_missing(tmp_path):
    settings = Settings(db_key_file=tmp_path / "nope.key")
    with pytest.raises(RuntimeError, match="could not be read"):
        settings.require_key()


def test_require_key_file_empty(tmp_path):
    key_file = tmp_path / "db.key"
    key_file.write_text("\n")
    settings = Settings(db_key_file=key_file)
    with pytest.raises(RuntimeError, match="is empty"):
        settings.require_key()


def test_require_key_file_takes_precedence(tmp_path):
    key_file = tmp_path / "db.key"
    key_file.write_text("from-file")
    settings = Settings(db_key_file=key_file, db_key="from-env")
    assert settings.require_key() == "from-file"


def test_require_key_env_fallback():
    assert Settings(db_key="env-key").require_key() == "env-key"


def test_require_key_neither_set_raises():
    with pytest.raises(RuntimeError, match="CHANCERY_DB_KEY is not set"):
        Settings().require_key()
