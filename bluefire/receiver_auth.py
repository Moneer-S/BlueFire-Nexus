"""Exact cryptographic bindings for one managed loopback receiver task.

The managed runner derives a short-lived task key from enrollment material and
passes it only through fixed, scrubbed child-process environment names.  The
receiver independently derives the same key, then authenticates an ephemeral
listener session before the Rust runner transmits artifact bytes.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Mapping

from .util import canonical_json_bytes

RECEIVER_TASK_ID_ENV = "BLUEFIRE_RECEIVER_TASK_ID"
RECEIVER_TASK_KEY_ENV = "BLUEFIRE_RECEIVER_TASK_KEY"

TASK_KEY_DOMAIN = b"bluefire.loopback-receiver.task.v1\0"
CHALLENGE_AUTH_DOMAIN = b"bluefire.loopback-receiver.challenge.v1\0"
REQUEST_AUTH_DOMAIN = b"bluefire.loopback-receiver.request.v1\0"
RESPONSE_AUTH_DOMAIN = b"bluefire.loopback-receiver.response.v1\0"

CHALLENGE_SCHEMA_VERSION = "bluefire.loopback-receiver-challenge.v1"
RESULT_SCHEMA_VERSION = "bluefire.loopback-receiver-result.v2"
DISPOSABLE_PEER_CHALLENGE_SCHEMA_VERSION = "bluefire.loopback-receiver-challenge.v2"
DISPOSABLE_PEER_RESULT_SCHEMA_VERSION = "bluefire.loopback-receiver-result.v3"

_TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_HEX_32 = re.compile(r"^[0-9a-f]{64}$")
_AUTHENTICATION = re.compile(r"^sha256:[0-9a-f]{64}$")
_KEY_BYTES = 32


class ReceiverAuthenticationError(ValueError):
    """A deliberately secret-free receiver authentication refusal."""


def validate_receiver_task_id(task_id: object) -> str:
    if not isinstance(task_id, str) or _TASK_ID.fullmatch(task_id) is None:
        raise ReceiverAuthenticationError("receiver task identity is invalid")
    return task_id


def derive_receiver_task_key(enrollment_key: bytes, task_id: object) -> bytes:
    """Derive the exact receiver key for one authenticated transport task."""

    checked_task_id = validate_receiver_task_id(task_id)
    if type(enrollment_key) is not bytes or len(enrollment_key) != _KEY_BYTES:
        raise ReceiverAuthenticationError("receiver enrollment key is invalid")
    return hmac.new(
        enrollment_key,
        TASK_KEY_DOMAIN + checked_task_id.encode("ascii"),
        hashlib.sha256,
    ).digest()


def challenge_document(
    *,
    task_id: object,
    session_id: object,
    nonce: object,
    host: object,
    port: object,
    sha256: object,
    content_length: object,
) -> dict[str, Any]:
    checked_task_id = validate_receiver_task_id(task_id)
    checked_session = _hex_identity(session_id, "receiver session identity")
    checked_nonce = _hex_identity(nonce, "receiver challenge nonce")
    checked_host = _host(host)
    checked_port = _port(port)
    return {
        "schema_version": CHALLENGE_SCHEMA_VERSION,
        "task_id": checked_task_id,
        "session_id": checked_session,
        "nonce": checked_nonce,
        "host": checked_host,
        "port": checked_port,
        "sha256": _hex_identity(sha256, "artifact digest"),
        "content_length": _content_length(content_length),
    }


def disposable_peer_challenge_document(
    *,
    task_id: object,
    session_id: object,
    nonce: object,
    host: object,
    port: object,
    sha256: object,
    content_length: object,
    receiver_process_id: object,
) -> dict[str, Any]:
    """Build the exact authenticated challenge for one disposable peer process."""

    document = challenge_document(
        task_id=task_id,
        session_id=session_id,
        nonce=nonce,
        host=host,
        port=port,
        sha256=sha256,
        content_length=content_length,
    )
    document.update(
        {
            "schema_version": DISPOSABLE_PEER_CHALLENGE_SCHEMA_VERSION,
            "receiver_process_id": _process_id(receiver_process_id),
            "receiver_mode": "disposable_peer",
            "accepted_artifact_limit": 1,
            "storage_mode": "memory_only",
            "exit_after_accept": True,
        }
    )
    return document


def disposable_peer_result_document(
    *,
    task_id: object,
    session_id: object,
    bytes_received: object,
    sha256: object,
    receiver_process_id: object,
) -> dict[str, Any]:
    """Build the exact authenticated acknowledgement for a disposable peer."""

    return {
        "schema_version": DISPOSABLE_PEER_RESULT_SCHEMA_VERSION,
        "accepted": True,
        "task_id": validate_receiver_task_id(task_id),
        "session_id": _hex_identity(session_id, "receiver session identity"),
        "bytes_received": _content_length(bytes_received),
        "sha256": _hex_identity(sha256, "artifact digest"),
        "stored": False,
        "receiver_process_id": _process_id(receiver_process_id),
        "receiver_mode": "disposable_peer",
        "terminal_disposition": "exit_after_response",
    }


def request_document(
    *,
    task_id: object,
    session_id: object,
    nonce: object,
    host: object,
    port: object,
    sha256: object,
    content_length: object,
) -> dict[str, Any]:
    checked_length = _content_length(content_length)
    return {
        "schema_version": "bluefire.loopback-receiver-request.v1",
        "method": "POST",
        "path": "/bluefire/v1/artifact",
        "task_id": validate_receiver_task_id(task_id),
        "session_id": _hex_identity(session_id, "receiver session identity"),
        "nonce": _hex_identity(nonce, "receiver challenge nonce"),
        "host": _host(host),
        "port": _port(port),
        "sha256": _hex_identity(sha256, "artifact digest"),
        "content_length": checked_length,
    }


def challenge_authentication(task_key: bytes, document: Mapping[str, Any]) -> str:
    return _authentication(task_key, CHALLENGE_AUTH_DOMAIN + canonical_json_bytes(dict(document)))


def request_authentication(task_key: bytes, document: Mapping[str, Any]) -> str:
    return _authentication(task_key, REQUEST_AUTH_DOMAIN + canonical_json_bytes(dict(document)))


def response_authentication(
    task_key: bytes,
    request_auth: object,
    response_body: bytes,
) -> str:
    checked_request_auth = _authentication_value(request_auth)
    if type(response_body) is not bytes:
        raise ReceiverAuthenticationError("receiver response body is invalid")
    return _authentication(
        task_key,
        RESPONSE_AUTH_DOMAIN + checked_request_auth.encode("ascii") + b"\0" + response_body,
    )


def verify_authentication(actual: object, expected: str) -> bool:
    try:
        checked_actual = _authentication_value(actual)
        checked_expected = _authentication_value(expected)
    except ReceiverAuthenticationError:
        return False
    return hmac.compare_digest(checked_actual, checked_expected)


def _authentication(task_key: bytes, message: bytes) -> str:
    if type(task_key) is not bytes or len(task_key) != _KEY_BYTES:
        raise ReceiverAuthenticationError("receiver task key is invalid")
    return "sha256:" + hmac.new(task_key, message, hashlib.sha256).hexdigest()


def _authentication_value(value: object) -> str:
    if not isinstance(value, str) or _AUTHENTICATION.fullmatch(value) is None:
        raise ReceiverAuthenticationError("receiver authentication value is invalid")
    return value


def _hex_identity(value: object, context: str) -> str:
    if not isinstance(value, str) or _HEX_32.fullmatch(value) is None:
        raise ReceiverAuthenticationError(f"{context} is invalid")
    return value


def _host(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 64 or not value.isascii():
        raise ReceiverAuthenticationError("receiver host is invalid")
    return value


def _port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ReceiverAuthenticationError("receiver port is invalid")
    return value


def _content_length(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 64 * 1024 * 1024:
        raise ReceiverAuthenticationError("receiver content length is invalid")
    return value


def _process_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2**32 - 1:
        raise ReceiverAuthenticationError("receiver process identity is invalid")
    return value


__all__ = [
    "CHALLENGE_AUTH_DOMAIN",
    "CHALLENGE_SCHEMA_VERSION",
    "DISPOSABLE_PEER_CHALLENGE_SCHEMA_VERSION",
    "DISPOSABLE_PEER_RESULT_SCHEMA_VERSION",
    "RECEIVER_TASK_ID_ENV",
    "RECEIVER_TASK_KEY_ENV",
    "REQUEST_AUTH_DOMAIN",
    "RESPONSE_AUTH_DOMAIN",
    "RESULT_SCHEMA_VERSION",
    "TASK_KEY_DOMAIN",
    "ReceiverAuthenticationError",
    "challenge_authentication",
    "challenge_document",
    "derive_receiver_task_key",
    "disposable_peer_challenge_document",
    "disposable_peer_result_document",
    "request_authentication",
    "request_document",
    "response_authentication",
    "validate_receiver_task_id",
    "verify_authentication",
]
