"""Supervise one HTTP request through startup, DNS, headers, and body receipt."""

from __future__ import annotations

import base64
import json
import math
import os
import subprocess  # nosec B404
import sys
import threading
import time
from pathlib import Path
from typing import Mapping

from .ai_wire import AIProviderTransportError

_MAX_BYTES = 1_048_576
_MAX_WIRE_BYTES = 2 * _MAX_BYTES
_MAX_TIMEOUT_SECONDS = 300.0
_WORKER = Path(__file__).with_name("_ai_transport_worker.py")
_CODES = {
    "transport_failed",
    "authentication_failed",
    "rate_limited",
    "endpoint_rejected",
    "response_content_type",
    "response_too_large",
    "request_too_large",
}


def _worker_environment() -> dict[str, str]:
    # Python's absolute executable and worker path need no user PATH/HOME,
    # proxy configuration, credentials, or Python startup customization.
    environment = {"LANG": "C.UTF-8"}
    if os.name == "nt":
        for name in ("SystemRoot", "WINDIR"):
            if os.environ.get(name):
                environment[name] = os.environ[name]
    return environment


def _write_request(descriptor: int, payload: bytes) -> None:
    try:
        with os.fdopen(descriptor, "wb", buffering=0) as stream:
            remaining = memoryview(payload)
            while remaining:
                written = stream.write(remaining)
                if not written:
                    return
                remaining = remaining[written:]
    except (OSError, ValueError):
        # A deadline/cancellation closes the child's pipe. No request material
        # or exception message is logged from this short-lived writer.
        pass


def _reap_worker(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            process.terminate()
        except OSError:
            pass
        try:
            process.wait(timeout=0.15)
        except subprocess.TimeoutExpired:
            process.kill()
    try:
        # communicate finishes any Windows pipe-reader thread as well as wait.
        process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=2)
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


class UrllibAIJSONTransport:
    """One worker per request, with a whole-request deadline and no retry here.

    The optional event cancels this transport call only. The synchronous setup
    endpoint does not currently expose browser cancellation or a durable job.
    """

    def __init__(self, *, cancel_event: threading.Event | None = None) -> None:
        self.cancel_event = cancel_event

    def post(
        self, url: str, *, headers: Mapping[str, str], body: bytes, timeout_seconds: float
    ) -> bytes:
        deadline = time.monotonic() + timeout_seconds
        if not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= _MAX_TIMEOUT_SECONDS:
            raise AIProviderTransportError("Provider timeout is invalid", retryable=False)
        if len(body) > _MAX_BYTES:
            raise AIProviderTransportError("Provider request exceeded 1 MiB", retryable=False)
        payload = json.dumps(
            {
                "url": url,
                "headers": dict(headers),
                "body": base64.b64encode(body).decode("ascii"),
                "timeout_seconds": timeout_seconds,
            },
            separators=(",", ":"),
        ).encode("ascii")
        if len(payload) > _MAX_WIRE_BYTES:
            raise AIProviderTransportError(
                "Provider request exceeded its byte limit", retryable=False
            )
        process: subprocess.Popen[bytes] | None = None
        writer: threading.Thread | None = None
        read_descriptor, write_descriptor = os.pipe()
        try:
            self._check_deadline(deadline)
            # The base interpreter avoids Windows venv redirector descendants;
            # this stdlib-only worker must remain the single supervised child.
            process = subprocess.Popen(  # nosec B603
                [
                    getattr(sys, "_base_executable", sys.executable),
                    "-I",
                    "-B",
                    str(_WORKER),
                    str(deadline),
                ],
                stdin=read_descriptor,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=_WORKER.parent,
                env=_worker_environment(),
                close_fds=True,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
            )
            os.close(read_descriptor)
            read_descriptor = -1
            # communicate(input=...) can block on Windows stdin before its
            # timeout begins. Keep the writer supervised and join it after the
            # worker exits; its only reader is this child, so kill releases it.
            writer = threading.Thread(
                target=_write_request,
                args=(write_descriptor, payload),
                name="bluefire-ai-request-writer",
            )
            writer.start()
            write_descriptor = -1
            while True:
                self._check_deadline(deadline)
                try:
                    output, _ = process.communicate(timeout=min(0.05, deadline - time.monotonic()))
                    self._check_deadline(deadline)
                    break
                except subprocess.TimeoutExpired:
                    continue
            if process.returncode == 124:
                raise AIProviderTransportError(
                    "Provider request deadline expired", retryable=True, code="request_timed_out"
                )
            if process.returncode != 0 or len(output) > _MAX_WIRE_BYTES:
                raise AIProviderTransportError("Provider worker failed", retryable=False)
            return self._decode_result(output)
        except AIProviderTransportError:
            raise
        except (OSError, ValueError, subprocess.SubprocessError):
            raise AIProviderTransportError(
                "Provider worker could not complete", retryable=True
            ) from None
        finally:
            try:
                if process is not None:
                    _reap_worker(process)
            finally:
                for descriptor in (read_descriptor, write_descriptor):
                    if descriptor >= 0:
                        os.close(descriptor)
                if writer is not None and writer.ident is not None:
                    writer.join(timeout=2)
                    if writer.is_alive():
                        raise AIProviderTransportError(
                            "Provider writer could not be reaped", retryable=False
                        )

    def _check_deadline(self, deadline: float) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise AIProviderTransportError(
                "Provider request was cancelled", retryable=False, code="request_cancelled"
            )
        if time.monotonic() >= deadline:
            raise AIProviderTransportError(
                "Provider request deadline expired", retryable=True, code="request_timed_out"
            )

    @staticmethod
    def _decode_result(payload: bytes) -> bytes:
        try:
            result = json.loads(payload)
            if not isinstance(result, dict):
                raise ValueError
            if result.get("ok") is True and set(result) == {"ok", "body"}:
                body = base64.b64decode(result["body"], validate=True)
                if len(body) > _MAX_BYTES:
                    raise ValueError
                return body
            if set(result) != {"ok", "code", "retryable"} or result["ok"] is not False:
                raise ValueError
            if result["code"] not in _CODES or type(result["retryable"]) is not bool:
                raise ValueError
        except (ValueError, TypeError, KeyError):
            raise AIProviderTransportError(
                "Provider worker response was invalid", retryable=False
            ) from None
        raise AIProviderTransportError(
            "Provider endpoint request failed", retryable=result["retryable"], code=result["code"]
        )


class ManagedAIJSONTransport:
    """Own in-flight setup requests for one service and cancel them at shutdown."""

    def __init__(self) -> None:
        self._cancel_event = threading.Event()
        self._condition = threading.Condition()
        self._active_requests = 0

    def post(
        self, url: str, *, headers: Mapping[str, str], body: bytes, timeout_seconds: float
    ) -> bytes:
        with self._condition:
            if self._cancel_event.is_set():
                raise AIProviderTransportError(
                    "Provider request was cancelled", retryable=False, code="request_cancelled"
                )
            self._active_requests += 1
        try:
            return UrllibAIJSONTransport(cancel_event=self._cancel_event).post(
                url, headers=headers, body=body, timeout_seconds=timeout_seconds
            )
        finally:
            with self._condition:
                self._active_requests -= 1
                self._condition.notify_all()

    def close(self) -> None:
        self._cancel_event.set()
        with self._condition:
            # Transport cleanup normally finishes immediately after cancellation.
            # Keep service shutdown bounded even if OS-level cleanup fails.
            if not self._condition.wait_for(lambda: self._active_requests == 0, timeout=5):
                raise AIProviderTransportError(
                    "Provider requests could not be reaped", retryable=False
                )
