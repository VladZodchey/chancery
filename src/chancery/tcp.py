import asyncio
import logging
import re
from contextlib import suppress

from .config import Settings
from .service import InvalidContent, PasteService, PasteTooLarge, validate_content

logger = logging.getLogger(__name__)

_CHUNK_SIZE = 64 * 1024
_IDLE_TIMEOUT = 1.0

# Termbin-style paste servers are a favorite target of web crawlers that
# mistake the port for an HTTP server and blast a GET request at it; the whole
# header then gets stored as a paste. Detect an HTTP request line and refuse.
_HTTP_REQUEST_RE = re.compile(
    r"^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE|PRI) "
    r"\S+ HTTP/\d+(?:\.\d+)?"
)


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


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    settings: Settings,
    service: PasteService,
) -> None:
    peer = writer.get_extra_info("peername")
    try:
        data = await _read_all(reader, settings.paste_max_size, settings.tcp_connect_timeout)
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
        validate_content(text)
    except (UnicodeDecodeError, InvalidContent):
        logger.warning("tcp rejected non-UTF-8 paste, peer=%s", peer)
        await _error(writer, "only UTF-8 text without control characters is supported")
        return

    if not text:
        logger.warning("tcp rejected empty paste, peer=%s", peer)
        await _error(writer, "empty pastes are not allowed")
        return

    if settings.tcp_crawler_filter:
        first_line = text.splitlines()[0]
        if _HTTP_REQUEST_RE.match(first_line):
            logger.warning("tcp rejected HTTP request, peer=%s", peer)
            await _error(
                writer,
                "this is a paste server, not an HTTP server; "
                "send the paste text and close the connection",
            )
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


async def _read_all(
    reader: asyncio.StreamReader, max_size: int, first_byte_timeout: float
) -> bytes:
    chunks = bytearray()
    while True:
        timeout = first_byte_timeout if not chunks else _IDLE_TIMEOUT
        try:
            chunk = await asyncio.wait_for(reader.read(_CHUNK_SIZE), timeout=timeout)
        except TimeoutError:
            if chunks:
                break
            raise
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

        with suppress(ConnectionError):
            await writer.wait_closed()


async def _error(writer: asyncio.StreamWriter, message: str) -> None:
    await _write_line(writer, f"error: {message}")
