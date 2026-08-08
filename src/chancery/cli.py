import sys
from pathlib import Path
from typing import Any

import typer
import uvicorn

from .config import Settings
from .db import init_schema, open_database, rekey_database
from .logging import setup_logging
from .service import (
    InvalidContent,
    InvalidPassword,
    PasteNeedsPassword,
    PasteService,
)

cli = typer.Typer(no_args_is_help=True, add_completion=False)
admin = typer.Typer(
    no_args_is_help=True,
    help="Admin actions against the local DB (requires filesystem access to the encrypted DB).",
)
cli.add_typer(admin, name="admin")


def _settings(db_path: Path | None, db_key: str | None) -> Settings:
    overrides: dict[str, Any] = {}
    if db_path is not None:
        overrides["db_path"] = db_path
    if db_key is not None:
        overrides["db_key"] = db_key
    return Settings(**overrides)


def _open_service(settings: Settings) -> PasteService:
    conn = open_database(settings.db_path, settings.require_key())
    init_schema(conn)
    return PasteService(
        conn,
        base_url=settings.base_url,
        paste_max_size=settings.paste_max_size,
        max_ttl_seconds=settings.max_ttl_seconds,
        paste_id_length=settings.paste_id_length,
        kdf_opslimit=settings.kdf_opslimit,
        kdf_memlimit=settings.kdf_memlimit,
    )


@cli.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port"),
    reload: bool = typer.Option(
        False, help="Reload on code changes. Reads config from CHANCERY_* env vars."
    ),
    log_level: str = typer.Option(
        None,
        "--log-level",
        help="Log level (DEBUG/INFO/WARNING/ERROR). Defaults to $CHANCERY_LOG_LEVEL.",
    ),
) -> None:
    """Start the HTTP server (and the TCP listener if CHANCERY_TCP_ENABLED)."""
    level = log_level or Settings().log_level
    if level.lower() not in {"critical", "error", "warning", "info", "debug", "trace"}:
        level = "info"
    setup_logging(level)
    uvicorn.run(
        "chancery.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level=level.lower(),
    )


@cli.command()
def healthcheck(url: str = typer.Option("http://127.0.0.1:8000/health")) -> None:
    """Hit the health endpoint."""
    import httpx

    r = httpx.get(url, timeout=5.0)
    typer.echo(r.json())


@admin.command()
def init_db(
    db_path: Path | None = typer.Option(
        None,
        "--db-path",
        "-d",
        help="Path to the encrypted database (defaults to $CHANCERY_DB_PATH).",
    ),
    db_key: str | None = typer.Option(
        None, "--db-key", "-k", help="Database encryption key (defaults to $CHANCERY_DB_KEY)."
    ),
) -> None:
    """Create the database and schema if missing."""
    settings = _settings(db_path, db_key)
    conn = open_database(settings.db_path, settings.require_key())
    try:
        init_schema(conn)
    finally:
        conn.close()
    typer.echo(f"initialized {settings.db_path}")


@admin.command()
def rekey(
    new_key: str | None = typer.Option(
        None,
        "--new-key",
        "-n",
        help="New database key. Prompts (hidden) if omitted.",
    ),
    db_path: Path | None = typer.Option(
        None,
        "--db-path",
        "-d",
        help="Path to the encrypted database (defaults to $CHANCERY_DB_PATH).",
    ),
    db_key: str | None = typer.Option(
        None,
        "--db-key",
        "-k",
        help="Current database encryption key (defaults to $CHANCERY_DB_KEY).",
    ),
) -> None:
    """Re-encrypt the database with a new key.

    Safe against interruption: the re-encrypted copy is written to a temporary
    file in the same directory and swapped over the original only once complete.
    """
    if new_key is None:
        new_key = typer.prompt("New key", hide_input=True, confirmation_prompt=True)
    if not new_key:
        typer.echo("error: the new key must not be empty", err=True)
        raise typer.Exit(code=1)
    settings = _settings(db_path, db_key)
    try:
        rekey_database(settings.db_path, settings.require_key(), new_key)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"re-encrypted {settings.db_path}")


@admin.command()
def create(
    content: Path | None = typer.Argument(None, help="File to paste; if omitted, read from stdin."),
    password: str | None = typer.Option(
        None, "--password", "-p", help="Encrypt the paste with this password."
    ),
    burn: bool = typer.Option(False, "--burn", help="Delete the paste after the first read."),
    ttl: int | None = typer.Option(None, "--ttl", help="Expire after this many seconds."),
    db_path: Path | None = typer.Option(
        None,
        "--db-path",
        "-d",
        help="Path to the encrypted database (defaults to $CHANCERY_DB_PATH).",
    ),
    db_key: str | None = typer.Option(
        None, "--db-key", "-k", help="Database encryption key (defaults to $CHANCERY_DB_KEY)."
    ),
) -> None:
    """Create a paste and print its URL."""
    if content is None:
        try:
            text = sys.stdin.buffer.read().decode("utf-8")
        except UnicodeDecodeError:
            typer.echo("error: only UTF-8 text is supported", err=True)
            raise typer.Exit(code=1) from None
    else:
        text = content.read_text(encoding="utf-8")

    service = _open_service(_settings(db_path, db_key))
    try:
        result = service.create(text, password=password, burn_after_read=burn, ttl_seconds=ttl)
        typer.echo(result.url)
    except InvalidContent as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        service.close()


@admin.command()
def show(
    paste_id: str = typer.Argument(..., help="Paste id to display."),
    db_path: Path | None = typer.Option(
        None,
        "--db-path",
        "-d",
        help="Path to the encrypted database (defaults to $CHANCERY_DB_PATH).",
    ),
    db_key: str | None = typer.Option(
        None, "--db-key", "-k", help="Database encryption key (defaults to $CHANCERY_DB_KEY)."
    ),
) -> None:
    """Print a paste's content."""
    service = _open_service(_settings(db_path, db_key))
    try:
        try:
            paste = service.get(paste_id)
        except PasteNeedsPassword:
            password = typer.prompt("Password", hide_input=True)
            try:
                paste = service.get(paste_id, password=password)
            except InvalidPassword:
                typer.echo("error: wrong password", err=True)
                raise typer.Exit(code=1) from InvalidPassword
        typer.echo(paste.text)
    finally:
        service.close()


@admin.command()
def delete(
    paste_id: str = typer.Argument(...),
    db_path: Path | None = typer.Option(
        None,
        "--db-path",
        "-d",
        help="Path to the encrypted database (defaults to $CHANCERY_DB_PATH).",
    ),
    db_key: str | None = typer.Option(
        None, "--db-key", "-k", help="Database encryption key (defaults to $CHANCERY_DB_KEY)."
    ),
) -> None:
    """Delete a paste."""
    service = _open_service(_settings(db_path, db_key))
    try:
        if not service.delete(paste_id):
            typer.echo("not found", err=True)
            raise typer.Exit(code=1)
        typer.echo("deleted")
    finally:
        service.close()


@admin.command("list")
def list_pastes(
    limit: int = typer.Option(50, "--limit"),
    offset: int = typer.Option(0, "--offset"),
    db_path: Path | None = typer.Option(
        None,
        "--db-path",
        "-d",
        help="Path to the encrypted database (defaults to $CHANCERY_DB_PATH).",
    ),
    db_key: str | None = typer.Option(
        None, "--db-key", "-k", help="Database encryption key (defaults to $CHANCERY_DB_KEY)."
    ),
) -> None:
    """List pastes, newest first."""
    service = _open_service(_settings(db_path, db_key))
    try:
        for paste in service.list(limit=limit, offset=offset):
            flags = "".join(
                [
                    "E" if paste.encrypted else "",
                    "B" if paste.burn_after_read else "",
                ]
            )
            typer.echo(f"{paste.id}  {paste.created_at}  {paste.size_bytes:>10} bytes  {flags}")
    finally:
        service.close()


@admin.command()
def stats(
    db_path: Path | None = typer.Option(
        None,
        "--db-path",
        "-d",
        help="Path to the encrypted database (defaults to $CHANCERY_DB_PATH).",
    ),
    db_key: str | None = typer.Option(
        None, "--db-key", "-k", help="Database encryption key (defaults to $CHANCERY_DB_KEY)."
    ),
) -> None:
    """Show aggregate database statistics."""
    service = _open_service(_settings(db_path, db_key))
    try:
        for key, value in service.stats().items():
            typer.echo(f"{key}: {value}")
    finally:
        service.close()


@admin.command()
def purge_expired(
    db_path: Path | None = typer.Option(
        None,
        "--db-path",
        "-d",
        help="Path to the encrypted database (defaults to $CHANCERY_DB_PATH).",
    ),
    db_key: str | None = typer.Option(
        None, "--db-key", "-k", help="Database encryption key (defaults to $CHANCERY_DB_KEY)."
    ),
) -> None:
    """Delete pastes past their expiry."""
    service = _open_service(_settings(db_path, db_key))
    try:
        removed = service.purge_expired()
        typer.echo(f"removed {removed} expired pastes")
    finally:
        service.close()


def main() -> None:
    setup_logging(Settings().log_level)
    cli()
