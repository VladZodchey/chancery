import logging

import pytest

from chancery.service import InvalidPassword, PasteNotFound


def _messages(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records]


def test_info_events_logged_without_paste_id(service, caplog):
    with caplog.at_level(logging.INFO, logger="chancery"):
        result = service.create("hello")
        service.get(result.id)
    messages = _messages(caplog)
    assert any("paste created" in m for m in messages)
    assert any("paste read" in m for m in messages)
    assert all(result.id not in m for m in messages)


def test_debug_logs_paste_id_and_flags(service, caplog):
    with caplog.at_level(logging.DEBUG, logger="chancery"):
        result = service.create("hello", burn_after_read=True, ttl_seconds=60)
    text = " ".join(_messages(caplog))
    assert result.id in text
    assert "burn_after_read=True" in text
    assert "ttl_seconds=60" in text


def test_burn_read_logged_without_paste_id_at_info(service, caplog):
    result = service.create("one shot", burn_after_read=True)
    with caplog.at_level(logging.INFO, logger="chancery"):
        assert service.get(result.id).text == "one shot"
    messages = _messages(caplog)
    assert any("burn-after-read: deleted" in m for m in messages)
    assert all(result.id not in m for m in messages)


def test_expired_read_logged_without_paste_id(service, caplog, monkeypatch):
    result = service.create("doomed", ttl_seconds=1)

    class _FakeClock:
        @staticmethod
        def time() -> int:
            return 10**11

    monkeypatch.setattr("chancery.service.time", _FakeClock)
    with caplog.at_level(logging.INFO, logger="chancery"), pytest.raises(PasteNotFound):
        service.get(result.id)
    messages = _messages(caplog)
    assert any("paste expired, deleted" in m for m in messages)
    assert all(result.id not in m for m in messages)


def test_delete_logged_without_paste_id(service, caplog):
    result = service.create("bye")
    with caplog.at_level(logging.INFO, logger="chancery"):
        assert service.delete(result.id) is True
    messages = _messages(caplog)
    assert any("paste deleted" in m for m in messages)
    assert all(result.id not in m for m in messages)


def test_purge_logged(service, caplog):
    service.create("doomed", ttl_seconds=1)
    with caplog.at_level(logging.INFO, logger="chancery"):
        assert service.purge_expired(now=10**11) == 1
    assert any("purged 1 expired pastes" in m for m in _messages(caplog))


def test_wrong_password_logged_without_paste_id(service, caplog):
    result = service.create("secret", password="right")
    with caplog.at_level(logging.INFO, logger="chancery"), pytest.raises(InvalidPassword):
        service.get(result.id, password="wrong")
    messages = _messages(caplog)
    assert any("invalid password attempt" in m for m in messages)
    assert all(result.id not in m for m in messages)


def test_content_and_password_never_logged_even_at_debug(service, caplog):
    with caplog.at_level(logging.DEBUG, logger="chancery"):
        result = service.create("SUPER-SECRET-CONTENT", password="SUPER-SECRET-PASSWORD")
    text = " ".join(_messages(caplog))
    assert "SUPER-SECRET-CONTENT" not in text
    assert "SUPER-SECRET-PASSWORD" not in text
    assert result.id in text
