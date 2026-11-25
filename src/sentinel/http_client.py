"""The sole network boundary for passive collection."""

from __future__ import annotations

import ssl
import time
import http.client
import socket
from collections.abc import Callable
from urllib.parse import urljoin, urlsplit

from sentinel.models import Observation, TargetScope
from sentinel.scope import ScopeError, resolve_public_address, validate_url


class PassiveHttpClient:
    """A small, policy-bound client with no support for arbitrary methods or bodies."""

    def __init__(self, scope: TargetScope, *, sleeper: Callable[[float], None] = time.sleep) -> None:
        self._scope = scope
        self._sleeper = sleeper
        self._requests = 0
        self._last_request = 0.0

    def _take_budget(self) -> None:
        if self._requests >= self._scope.limits.max_requests:
            raise ScopeError("request budget exhausted")
        interval = 1 / self._scope.limits.requests_per_second
        wait = interval - (time.monotonic() - self._last_request)
        if wait > 0:
            self._sleeper(wait)
        self._requests += 1
        self._last_request = time.monotonic()

    def get(self, url: str) -> Observation:
        current_url = validate_url(url, self._scope)
        redirects = 0
        while True:
            self._take_budget()
            parsed = urlsplit(current_url)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            address = resolve_public_address(host, port)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            connection: http.client.HTTPConnection
            if parsed.scheme == "https":
                connection = _PinnedHTTPSConnection(host, port, address, self._scope.limits.timeout_seconds)
            else:
                connection = http.client.HTTPConnection(address, port, timeout=self._scope.limits.timeout_seconds)
            try:
                connection.request("GET", path, headers={
                    "Host": host,
                    "User-Agent": "SENTINEL/0.1 passive-audit",
                    "Accept": "text/html,*/*;q=0.8",
                    "Connection": "close",
                })
                response = connection.getresponse()
                status = response.status
                headers = {key.lower(): value for key, value in response.getheaders()}
                raw = response.read(self._scope.limits.max_response_bytes + 1)
            except (OSError, http.client.HTTPException) as exc:
                raise ScopeError(f"HTTP collection failed: {exc}") from exc
            finally:
                connection.close()
            if status in {301, 302, 303, 307, 308} and "location" in headers:
                if redirects >= 5:
                    raise ScopeError("redirect limit exceeded")
                current_url = validate_url(urljoin(current_url, headers["location"]), self._scope)
                redirects += 1
                continue
            if len(raw) > self._scope.limits.max_response_bytes:
                raise ScopeError("response exceeds configured body-size limit")
            content_type = headers.get("content-type", "")
            charset = _charset_from_content_type(content_type)
            body = raw.decode(charset, errors="replace")
            return Observation(
                target_url=url,
                final_url=current_url,
                status_code=status,
                headers=headers,
                body_sample=body,
                content_type=content_type,
            )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a vetted IP while retaining hostname-based TLS verification/SNI."""

    def __init__(self, host: str, port: int, address: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection((self._address, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def _charset_from_content_type(content_type: str) -> str:
    for parameter in content_type.split(";")[1:]:
        key, separator, value = parameter.strip().partition("=")
        if separator and key.lower() == "charset" and value:
            return value.strip("\"'")
    return "utf-8"


