import typer
import uvicorn

cli = typer.Typer(no_args_is_help=True, add_completion=False)


@cli.command()
def serve(
    host: str = "127.0.0.1",
    port: int = 8000,
    reload: bool = False,
) -> None:
    """Start chancery and attach logs to tty."""
    uvicorn.run("chancery.app:app", host=host, port=port, reload=reload)


@cli.command()
def healthcheck(url: str = "http://127.0.0.1:8000/health") -> None:
    """Hit the health endpoint."""
    import httpx

    r = httpx.get(url, timeout=5.0)
    typer.echo(r.json())


def main() -> None:
    cli()
