import asyncio
import logging

from .config import Settings
from .service import InvalidContent, PasteService, PasteTooLarge

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 64 * 1024


class TooLargeError(Exception):
    def __init__(self, max_size: int) -> None:
        super().__init__(f"paste too large (max {max_size} bytes)")
        self.max_size = max_size


async def run_tcp_server(settings: Settings, service: PasteService) -> None:
    """Serve termbin-style pastes until cancelled.

    Expected to run as a background task owned by the FastAPI lifespan.
    """
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, settings, service),
        settings.tcp_host,
        settings.tcp_port,
    )
    logger.info("tcp listening on %s:%d", settings.tcp_host, settings.tcp_port)
    async with server:
        await server.serve_forever()


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, settings: Settings, service: PasteService) -> None:
    peer = writer.get_extra_info("peername")
    try:
        data = await asyncio.wait_for(
            _read_all(reader, settings.paste_max_size),
            timeout=settings.tcp_connect_timeout,
        )
    except TimeoutError:
        logger.warning("tcp connection timed out, peer=%s", peer)
        await _error(writer, "connection timed out")
        return
    except TooLargeError as exc:
        logger.warning("tcp paste too large, peer=%s", peer)
        await _error(writer, str(exc))
        return
    except (ConnectionError, asyncio.IncompleteReadError):
        return

    try:
        text = data.decode("utf-8")
        if "\x00" in text:
            raise InvalidContent("NUL byte")
    except (UnicodeDecodeError, InvalidContent):
        logger.warning("tcp rejected non-UTF-8 paste, peer=%s", peer)
        await _error(writer, "only UTF-8 text is supported")
        return

    try:
        result = await asyncio.to_thread(service.create, text)
    except PasteTooLarge as exc:
        logger.warning("tcp paste too large, peer=%s", peer)
        await _error(writer, str(exc))
        return
    except Exception:
        logger.exception("tcp create failed, peer=%s", peer)
        await _error(writer, "internal error")
        return

    await _write_line(writer, result.url)


async def _read_all(reader: asyncio.StreamReader, max_size: int) -> bytes:
    chunks = bytearray()
    while True:
        chunk = await reader.read(_CHUNK_SIZE)
        if not chunk:
            break
        chunks.extend(chunk)
        if len(chunks) > max_size:
            raise TooLargeError(max_size)
    return bytes(chunks)


async def _write_line(writer: asyncio.StreamWriter, line: str) -> None:
    try:
        writer.write((line + "\r\n").encode("utf-8"))
        await writer.drain()
    except ConnectionError:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


async def _error(writer: asyncio.StreamWriter, message: str) -> None:
    await _write_line(writer, f"error: {message}")
