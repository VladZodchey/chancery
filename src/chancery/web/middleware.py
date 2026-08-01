"""Host validation and trusted-proxy handling.

Security model: chancery is meant to sit behind a reverse proxy (Nginx,
Caddy, ...). ``expected_host`` rejects any request whose Host does not match,
which defeats Host-header poisoning and DNS-rebinding style tricks. Forwarded
headers (X-Forwarded-For/Proto/Host) are only honored when the direct peer is
one of the configured trusted proxies; otherwise they are stripped so a remote
client cannot spoof its address or scheme.
"""

import ipaddress
import logging
from urllib.parse import urlsplit

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

_PROXY_HEADERS = frozenset(
    {"x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-port"}
)


def _hostname(value: str) -> str:
    parsed = urlsplit("//" + value)
    return (parsed.hostname or value).lower()


class ProxySecurityMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        expected_host: str | None = None,
        forwarded_allow_ips: str = "",
    ) -> None:
        self.app = app
        self._expected_hosts = (
            frozenset(h.strip().lower() for h in expected_host.split(",") if h.strip())
            if expected_host
            else frozenset()
        )
        self._trusted_networks = [
            ipaddress.ip_network(cidr.strip())
            for cidr in forwarded_allow_ips.split(",")
            if cidr.strip()
        ]

    def _is_trusted_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return False
        return any(addr in net for net in self._trusted_networks)

    def _is_trusted_peer(self, scope: Scope) -> bool:
        client = scope.get("client")
        if not client:
            return False
        return self._is_trusted_ip(client[0])

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        if self._is_trusted_peer(scope):
            self._apply_forwarded(scope, headers)
        else:
            self._strip_proxy_headers(scope)

        hostname = _hostname(Headers(scope=scope).get("host") or "")
        if self._expected_hosts and hostname not in self._expected_hosts:
            logger.warning("rejected request from=%s host=%r", scope.get("client", (None,))[0], hostname)
            await self._reject(send)
            return

        await self.app(scope, receive, send)

    def _strip_proxy_headers(self, scope: Scope) -> None:
        scope["headers"] = [
            (k, v)
            for k, v in scope["headers"]
            if k.decode("latin-1").lower() not in _PROXY_HEADERS
        ]

    def _apply_forwarded(self, scope: Scope, headers: Headers) -> None:
        original_host = headers.get("host") or "localhost"

        kept: list[tuple[bytes, bytes]] = []
        for key, value in scope["headers"]:
            name = key.decode("latin-1").lower()
            if name not in _PROXY_HEADERS and name != "host":
                kept.append((key, value))

        forwarded_for = headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = next(
                (
                    ip.strip()
                    for ip in reversed(forwarded_for.split(","))
                    if not self._is_trusted_ip(ip)
                ),
                None,
            )
            if client_ip is not None:
                scope["client"] = (client_ip, 0)

        forwarded_proto = headers.get("x-forwarded-proto")
        if forwarded_proto:
            scope["scheme"] = forwarded_proto.split(",")[0].strip()

        forwarded_host = headers.get("x-forwarded-host")
        host = forwarded_host.split(",")[0].strip() if forwarded_host else original_host
        kept.append((b"host", host.encode("latin-1")))
        scope["headers"] = kept

    async def _reject(self, send: Send) -> None:
        body = b"invalid host header\n"
        await send(
            {
                "type": "http.response.start",
                "status": 400,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
