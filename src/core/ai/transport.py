"""Injectable HTTP transport for AI provider backends.

The transport is a one-method Protocol so backends never reach for a
concrete HTTP client directly — they accept an ``HTTPTransport`` and
call ``post_json(...)``. Tests inject a mock transport that returns
canned responses; production wires :class:`UrllibTransport`, which
uses only the Python stdlib so no new dependency is added.

Why a separate module:
- Backends stay focused on request shape + response parsing.
- Tests can verify "what would have been sent" without monkey-
  patching ``urllib.request``.
- Future backends (Anthropic-specific, Gemini-specific) reuse the
  same transport without duplicating HTTP plumbing.

Security notes:
- ``UrllibTransport`` rejects any URL whose scheme is not ``http``
  or ``https``. ``file://`` / ``ftp://`` / unknown schemes raise
  ``ValueError`` before reaching the network layer — guards against
  the bandit B310 footgun where ``urllib.request.urlopen`` accepts
  arbitrary schemes including local files.
- The transport sets a request timeout and never follows protocol
  downgrades; bad responses surface as :class:`HTTPResponse` with
  the actual status code so callers can decide how to react.
- The transport does NOT pin certificates or override the default
  TLS context — operators relying on private CAs configure the
  Python TLS trust store the same way they would for any other
  HTTPS client.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Dict, Protocol


@dataclass(frozen=True)
class HTTPResponse:
    """Minimal HTTP response shape returned by every transport.

    ``body`` is always the raw response body as text (UTF-8). Use
    :meth:`json` to parse it; the parse error surfaces as a
    ``ValueError`` so the backend can wrap it in a structured
    ``ProviderResponse(error=...)`` without crashing.
    """

    status_code: int
    body: str
    headers: Mapping[str, str] = field(default_factory=dict)

    def json(self) -> Any:
        """Parse :attr:`body` as JSON. Raises ``ValueError`` on bad input."""
        try:
            return json.loads(self.body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"response body is not valid JSON: {exc}") from exc


class HTTPTransport(Protocol):
    """Single-method transport contract.

    Backends call ``post_json(url, headers=..., body=..., timeout=...)``;
    the transport is responsible for serialising ``body`` to JSON,
    issuing the request, and returning a :class:`HTTPResponse`. A
    transport must NEVER raise for non-2xx status codes — those
    surface in :attr:`HTTPResponse.status_code` so the backend can
    decide whether to retry, fall back, or report.
    """

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: Mapping[str, Any],
        timeout: int,
    ) -> HTTPResponse:
        ...


class UrllibTransport:
    """Stdlib-only ``HTTPTransport`` implementation.

    Production default. No new third-party dependency. Rejects any
    URL whose scheme is not ``http`` / ``https`` so misconfigured
    ``api_base`` values (``file:///etc/passwd``, ``ftp://...``) cannot
    be coerced into local-file reads — see ``B310`` in bandit.
    """

    _ALLOWED_SCHEMES = ("http://", "https://")

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: Mapping[str, Any],
        timeout: int,
    ) -> HTTPResponse:
        # Reject non-HTTP(S) schemes BEFORE building the Request
        # object so urllib never gets a chance to dispatch a
        # file:// / ftp:// / unknown-scheme handler.
        lowered = (url or "").lower()
        if not lowered.startswith(self._ALLOWED_SCHEMES):
            raise ValueError(
                f"UrllibTransport rejects non-HTTP(S) URL: {url!r} "
                "(only http:// and https:// are permitted)"
            )

        encoded_body = json.dumps(dict(body)).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=encoded_body,
            headers={
                "Content-Type": "application/json",
                **dict(headers),
            },
            method="POST",
        )
        try:
            # nosec B310: scheme already restricted to http/https above.
            with urllib.request.urlopen(request, timeout=timeout) as resp:  # nosec B310
                status = resp.getcode()
                raw = resp.read()
                response_headers: Dict[str, str] = {
                    str(k): str(v) for k, v in resp.headers.items()
                }
        except urllib.error.HTTPError as exc:
            # HTTPError IS a Response — read its body and surface as
            # a normal HTTPResponse with the upstream status. Never
            # raise for non-2xx; the caller decides how to react.
            try:
                raw = exc.read()
            except Exception:  # noqa: BLE001
                raw = b""
            response_headers = (
                {str(k): str(v) for k, v in exc.headers.items()}
                if exc.headers is not None
                else {}
            )
            status = int(exc.code)

        return HTTPResponse(
            status_code=int(status),
            body=raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw),
            headers=response_headers,
        )


__all__ = ["HTTPResponse", "HTTPTransport", "UrllibTransport"]
