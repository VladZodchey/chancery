import time

import pytest

from chancery.service import (
    InvalidContent,
    InvalidPassword,
    InvalidTTL,
    PasteNeedsPassword,
    PasteNotFound,
    PasteTooLarge,
)


def test_create_and_get_plain(service):
    result = service.create("hello world")
    assert result.url == "http://testserver/" + result.id
    paste = service.get(result.id)
    assert paste.text == "hello world"
    assert paste.size_bytes == 11


def test_id_format_and_uniqueness(service):
    ids = [service.create(f"paste {i}").id for i in range(200)]
    assert len(set(ids)) == 200
    assert all(len(i) == 10 for i in ids)
    assert all(i.isalnum() for i in ids)


def test_rejects_nul_bytes(service):
    with pytest.raises(InvalidContent):
        service.create("before\x00after")


def test_rejects_too_large(service):
    with pytest.raises(PasteTooLarge):
        service.create("x" * 1025)


def test_invalid_ttl(service):
    with pytest.raises(InvalidTTL):
        service.create("x", ttl_seconds=0)
    with pytest.raises(InvalidTTL):
        service.create("x", ttl_seconds=-5)
    with pytest.raises(InvalidTTL):
        service.create("x", ttl_seconds=86401)


def test_expiry(service):
    result = service.create("temp", ttl_seconds=60)
    service._conn.execute(
        "UPDATE pastes SET expires_at = ? WHERE id = ?",
        (int(time.time()) - 10, result.id),
    )
    service._conn.commit()
    with pytest.raises(PasteNotFound):
        service.get(result.id)


def test_purge_expired(service):
    keep = service.create("keep")
    gone = service.create("gone", ttl_seconds=60)
    service._conn.execute(
        "UPDATE pastes SET expires_at = ? WHERE id = ?",
        (int(time.time()) - 10, gone.id),
    )
    service._conn.commit()
    assert service.purge_expired(now=int(time.time())) == 1
    assert service.get(keep.id).text == "keep"
    with pytest.raises(PasteNotFound):
        service.get(gone.id)


def test_burn_after_read(service):
    result = service.create("secret", burn_after_read=True)
    assert service.get(result.id).text == "secret"
    with pytest.raises(PasteNotFound):
        service.get(result.id)


def test_password_roundtrip(service):
    result = service.create("classified", password="hunter2")
    with pytest.raises(PasteNeedsPassword):
        service.get(result.id)
    with pytest.raises(InvalidPassword):
        service.get(result.id, password="wrong")
    assert service.get(result.id, password="hunter2").text == "classified"
    row = service._conn.execute(
        "SELECT encrypted, content FROM pastes WHERE id = ?", (result.id,)
    ).fetchone()
    assert row["encrypted"] == 1
    assert row["content"] != b"classified"


def test_burn_with_password(service):
    result = service.create("top secret", password="pw", burn_after_read=True)
    with pytest.raises(PasteNeedsPassword):
        service.get(result.id)
    with pytest.raises(InvalidPassword):
        service.get(result.id, password="nope")
    assert service.get(result.id, password="pw").text == "top secret"
    with pytest.raises(PasteNotFound):
        service.get(result.id)


def test_delete(service):
    result = service.create("delete me")
    assert service.delete(result.id) is True
    with pytest.raises(PasteNotFound):
        service.get(result.id)
    assert service.delete(result.id) is False


def test_stats_and_list(service):
    a = service.create("a", password="x")
    b = service.create("b", burn_after_read=True)
    result = service.stats()
    assert result["pastes"] == 2
    assert result["encrypted"] == 1
    assert result["burn_after_read"] == 1
    pastes = service.list()
    assert len(pastes) == 2
    assert [p.id for p in pastes] == [b.id, a.id]  # newest first
