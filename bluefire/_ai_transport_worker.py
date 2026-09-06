"""Private, stdlib-only HTTP worker. Request material travels over stdin only."""

from __future__ import annotations

import base64
import http.client
import json
import math
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any

MAX_BYTES = 1_048_576
MAX_WIRE_BYTES = 2 * MAX_BYTES


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _failure(code: str = "transport_failed", *, retryable: bool = False) -> dict[str, Any]:
    return {"ok": False, "code": code, "retryable": retryable}


def perform_request(document: dict[str, Any]) -> dict[str, Any]:
    """The supervisor and worker enforce the same absolute request deadline."""
    try:
        body = base64.b64decode(document["body"], validate=True)
        if len(body) > MAX_BYTES:
            return _failure("request_too_large")
        request = urllib.request.Request(
            document["url"], data=body, headers=document["headers"], method="POST"
        )
        # Keep TLS verification defaults; never follow redirects or implicitly
        # route explicit endpoints through ambient proxy settings.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirectHandler())
        with opener.open(request, timeout=document["timeout_seconds"]) as response:  # nosec B310
            status = int(getattr(response, "status", 200))
            if not 200 <= status <= 299:
                return _failure("endpoint_rejected", retryable=status == 429 or status >= 500)
            if response.headers.get_content_type() != "application/json":
                return _failure("response_content_type")
            payload = response.read(MAX_BYTES + 1)
            if not isinstance(payload, bytes) or len(payload) > MAX_BYTES:
                return _failure("response_too_large")
            return {"ok": True, "body": base64.b64encode(payload).decode("ascii")}
    except urllib.error.HTTPError as exc:
        try:
            code = (
                "authentication_failed"
                if exc.code in {401, 403}
                else "rate_limited" if exc.code == 429 else "endpoint_rejected"
            )
            return _failure(code, retryable=exc.code == 429 or 500 <= exc.code <= 599)
        finally:
            exc.close()
    except (urllib.error.URLError, TimeoutError, OSError):
        return _failure(retryable=True)
    except (http.client.HTTPException, ValueError, TypeError, KeyError):
        return _failure()


def _enforce_deadline() -> None:
    # The deadline is non-secret process metadata. Supplying it before stdin
    # lets the worker bound startup/input reads as well as DNS and slow bodies,
    # even if its parent or supervising daemon thread disappears.
    try:
        if len(sys.argv) != 2:
            raise ValueError
        deadline = float(sys.argv[1])
        remaining = deadline - time.monotonic()
        if not math.isfinite(deadline) or not 0 < remaining <= 300:
            raise ValueError
    except (ValueError, OverflowError):
        os._exit(124)

    def expire() -> None:
        delay = deadline - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        # This isolated process owns only this request. OS exit closes every
        # socket and pipe without serializing request material or traceback.
        os._exit(124)

    threading.Thread(target=expire, name="bluefire-ai-worker-deadline", daemon=True).start()


def main() -> None:
    _enforce_deadline()
    try:
        payload = sys.stdin.buffer.read(MAX_WIRE_BYTES + 1)
        if len(payload) > MAX_WIRE_BYTES:
            result = _failure("request_too_large")
        else:
            document = json.loads(payload)
            result = perform_request(document) if isinstance(document, dict) else _failure()
    except BaseException:
        # Never serialize tracebacks, endpoint bodies, URLs, or credential data.
        result = _failure()
    sys.stdout.buffer.write(json.dumps(result, separators=(",", ":")).encode("ascii"))
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
