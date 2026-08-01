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


async def test_tcp_rejects_too_large(settings, service):
    server, port = await _start(settings, service)
    async with server:
        data = await _send(port, b"x" * 2000)
    assert data.decode().startswith("error: paste too large")


async def test_tcp_empty_paste(settings, service):
    server, port = await _start(settings, service)
    async with server:
        data = await _send(port, b"")
    paste_id = data.decode().strip().rsplit("/", 1)[1]
    assert service.get(paste_id).text == ""
