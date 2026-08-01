from typing import Any, cast

import pytest
import sqlcipher3 as _sqlcipher3

from chancery.db import key_sql, open_database, rekey_database

sqlcipher3: Any = cast(Any, _sqlcipher3)


def _create(path, key, n=10):
    conn = open_database(path, key)
    conn.execute("CREATE TABLE t(a INTEGER PRIMARY KEY, b TEXT)")
    conn.executemany("INSERT INTO t VALUES (?, ?)", ((i, f"v{i}") for i in range(n)))
    conn.execute("PRAGMA user_version = 3")
    conn.commit()
    conn.close()


def _read(path, key):
    conn = open_database(path, key)
    try:
        rows = [tuple(r) for r in conn.execute("SELECT a, b FROM t ORDER BY a")]
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        return rows, version, integrity
    finally:
        conn.close()


def test_rekey_preserves_data(tmp_path):
    path = tmp_path / "t.db"
    _create(path, "old-pass")
    rekey_database(path, "old-pass", "new-pass")

    rows, version, integrity = _read(path, "new-pass")
    assert rows == [(i, f"v{i}") for i in range(10)]
    assert version == 3
    assert integrity == "ok"


def test_old_key_no_longer_works(tmp_path):
    path = tmp_path / "t.db"
    _create(path, "old-pass")
    rekey_database(path, "old-pass", "new-pass")

    with pytest.raises(sqlcipher3.DatabaseError):
        conn = open_database(path, "old-pass")
        conn.execute("SELECT count(*) FROM t")


def test_rekey_hex_to_passphrase(tmp_path):
    path = tmp_path / "t.db"
    _create(path, "ab" * 32)
    rekey_database(path, "ab" * 32, "passphrase")

    rows, _, integrity = _read(path, "passphrase")
    assert len(rows) == 10
    assert integrity == "ok"


def test_rekey_wrong_old_key(tmp_path):
    path = tmp_path / "t.db"
    _create(path, "old-pass")
    with pytest.raises(ValueError):
        rekey_database(path, "wrong-pass", "new-pass")


def test_rekey_empty_new_key(tmp_path):
    path = tmp_path / "t.db"
    _create(path, "old-pass")
    with pytest.raises(ValueError):
        rekey_database(path, "old-pass", "")


def test_rekey_no_leftover_temp_file(tmp_path):
    path = tmp_path / "t.db"
    _create(path, "old-pass")
    rekey_database(path, "old-pass", "new-pass")
    assert not list(tmp_path.glob("*.tmp"))


def test_key_sql_forms():
    assert key_sql("ab" * 32) == f'"x\'{"ab" * 32}\'"'
    assert key_sql("pass'word") == "'pass''word'"
