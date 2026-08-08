import asyncio

from chancery.tcp import handle_client


async def _start(settings, service):
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, settings, service),
        "127.0.0.1",
        0,
    )
    port = server.sockets[0].getsockname()[1]
    return server, port


async def _send(port, payload: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(payload)
    await writer.drain()
    writer.write_eof()
    await writer.drain()
    data = await reader.read()
    writer.close()
    await writer.wait_closed()
    return data


async def test_tcp_creates_paste(settings, service):
    server, port = await _start(settings, service)
    async with server:
        data = await _send(port, b"hello via tcp")
    line = data.decode().strip()
    assert line.startswith("http://testserver/")
    paste_id = line.rsplit("/", 1)[1]
    assert service.get(paste_id).text == "hello via tcp"


async def test_tcp_rejects_binary(settings, service):
    server, port = await _start(settings, service)
    async with server:
        data = await _send(port, b"\xff\xfe\x00binary")
    assert data.decode().startswith("error: only UTF-8")


async def test_tcp_rejects_escape_sequences(settings, service):
    server, port = await _start(settings, service)
    async with server:
        data = await _send(port, b"\x1b]0;;hidden\x07abuse report")
    assert data.decode().startswith("error: only UTF-8")


async def test_tcp_rejects_too_large(settings, service):
    server, port = await _start(settings, service)
    async with server:
        data = await _send(port, b"x" * 2000)
    assert data.decode().startswith("error: paste too large")


async def test_tcp_empty_paste_rejected(settings, service):
    server, port = await _start(settings, service)
    async with server:
        data = await _send(port, b"")
    assert data.decode().startswith("error: empty pastes are not allowed")
    assert service.stats()["pastes"] == 0


async def test_tcp_rejects_http_request(settings, service):
    server, port = await _start(settings, service)
    async with server:
        data = await _send(
            port,
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bot\r\n\r\n",
        )
    assert data.decode().startswith("error:")
    assert service.stats()["pastes"] == 0


async def test_tcp_crawler_filter_disabled_stores_http_request(settings, service):
    settings.tcp_crawler_filter = False
    server, port = await _start(settings, service)
    async with server:
        data = await _send(port, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    paste_id = data.decode().strip().rsplit("/", 1)[1]
    assert service.get(paste_id).text.startswith("GET / HTTP/1.1")
