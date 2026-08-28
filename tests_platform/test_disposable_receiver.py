import hashlib
import io
import json
import os
import secrets
import socket
import threading
from pathlib import Path
from typing import Any

import pytest

import bluefire.cli as cli_module
import bluefire.receiver as receiver_module
from bluefire.receiver import LoopbackArtifactReceiver, ReceiverConfig, run_loopback_receiver
from bluefire.receiver_auth import (
    ReceiverAuthenticationError,
    challenge_authentication,
    derive_receiver_task_key,
    disposable_peer_challenge_document,
    request_authentication,
    request_document,
    response_authentication,
    verify_authentication,
)

TASK_ID = "execute-" + "d" * 64


@pytest.fixture
def enrollment_key() -> bytes:
    return secrets.token_bytes(32)


def _authority(receiver: LoopbackArtifactReceiver) -> str:
    return f"{receiver.host}:{receiver.port}"


def _read_response(connection: socket.socket) -> tuple[int, dict[str, str], dict[str, Any]]:
    response = bytearray()
    while True:
        chunk = connection.recv(64 * 1024)
        if not chunk:
            break
        response.extend(chunk)
    head, body = bytes(response).split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    status = int(lines[0].split(b" ")[1])
    headers = {
        name.decode("ascii").casefold(): value.decode("ascii").strip()
        for name, value in (line.split(b":", 1) for line in lines[1:])
    }
    return status, headers, json.loads(body)


def _exchange(
    receiver: LoopbackArtifactReceiver, request: bytes
) -> tuple[int, dict[str, str], dict[str, Any]]:
    with socket.create_connection((receiver.host, receiver.port), timeout=2.0) as connection:
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        return _read_response(connection)


def _serve_in_thread(
    receiver: LoopbackArtifactReceiver,
) -> tuple[threading.Thread, list[dict[str, object]]]:
    summaries: list[dict[str, object]] = []

    def serve() -> None:
        summaries.append(dict(receiver.serve()))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread, summaries


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"host": "::1"}, "host must be exactly 127.0.0.1"),
        (
            {"max_requests": 2, "max_connections": 4},
            "must accept exactly one artifact",
        ),
        ({"max_connections": 7}, "connection budget must be exactly 8"),
        ({"storage_dir": Path("receiver-owned")}, "must use memory-only storage"),
        ({"request_timeout_seconds": 5.01}, "must not exceed 5 seconds"),
        ({"idle_timeout_seconds": 240.01}, "must not exceed 240 seconds"),
    ],
)
def test_disposable_peer_configuration_fails_closed(
    overrides: dict[str, object], message: str, enrollment_key: bytes
) -> None:
    arguments: dict[str, Any] = {
        "authentication_key": enrollment_key,
        "port": 0,
        "max_connections": 8,
        "idle_timeout_seconds": 240.0,
        "disposable_peer": True,
    }
    arguments.update(overrides)

    with pytest.raises(ValueError, match=message):
        ReceiverConfig(**arguments)


def test_disposable_peer_wire_documents_bind_process_and_terminal_lifecycle(
    enrollment_key: bytes,
) -> None:
    body = b"opaque disposable peer artifact"
    digest = hashlib.sha256(body).hexdigest()
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=enrollment_key,
            port=0,
            max_connections=8,
            idle_timeout_seconds=2.0,
            disposable_peer=True,
        )
    )
    thread, summaries = _serve_in_thread(receiver)

    refusal_status, _, refusal = _exchange(
        receiver,
        (
            "GET /unreviewed HTTP/1.1\r\n"
            f"Host: {_authority(receiver)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii"),
    )
    assert refusal_status == 404
    assert refusal == {"accepted": False, "error": "path_not_found"}

    challenge_request = (
        "GET /bluefire/v1/challenge HTTP/1.1\r\n"
        f"Host: {_authority(receiver)}\r\n"
        f"X-BlueFire-Task-ID: {TASK_ID}\r\n"
        f"X-BlueFire-SHA256: {digest}\r\n"
        f"X-BlueFire-Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    challenge_status, challenge_headers, challenge = _exchange(receiver, challenge_request)
    task_key = derive_receiver_task_key(enrollment_key, TASK_ID)

    assert challenge_status == 200
    assert challenge == {
        "schema_version": "bluefire.loopback-receiver-challenge.v2",
        "task_id": TASK_ID,
        "session_id": challenge["session_id"],
        "nonce": challenge["nonce"],
        "host": "127.0.0.1",
        "port": receiver.port,
        "sha256": digest,
        "content_length": len(body),
        "receiver_process_id": os.getpid(),
        "receiver_mode": "disposable_peer",
        "accepted_artifact_limit": 1,
        "storage_mode": "memory_only",
        "exit_after_accept": True,
    }
    challenge_auth = challenge_headers["x-bluefire-authentication"]
    assert verify_authentication(
        challenge_auth,
        challenge_authentication(task_key, challenge),
    )
    tampered_challenge = dict(challenge)
    tampered_challenge["exit_after_accept"] = False
    assert not verify_authentication(
        challenge_auth,
        challenge_authentication(task_key, tampered_challenge),
    )

    request_document_value = request_document(
        task_id=TASK_ID,
        session_id=challenge["session_id"],
        nonce=challenge["nonce"],
        host=receiver.host,
        port=receiver.port,
        sha256=digest,
        content_length=len(body),
    )
    request_auth = request_authentication(task_key, request_document_value)
    artifact_request = (
        "POST /bluefire/v1/artifact HTTP/1.1\r\n"
        f"Host: {_authority(receiver)}\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"X-BlueFire-SHA256: {digest}\r\n"
        f"X-BlueFire-Task-ID: {TASK_ID}\r\n"
        f"X-BlueFire-Session-ID: {challenge['session_id']}\r\n"
        f"X-BlueFire-Nonce: {challenge['nonce']}\r\n"
        f"X-BlueFire-Authentication: {request_auth}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    result_status, result_headers, result = _exchange(receiver, artifact_request)
    thread.join(timeout=3.0)

    assert result_status == 200
    assert result == {
        "schema_version": "bluefire.loopback-receiver-result.v3",
        "accepted": True,
        "task_id": TASK_ID,
        "session_id": challenge["session_id"],
        "bytes_received": len(body),
        "sha256": digest,
        "stored": False,
        "receiver_process_id": os.getpid(),
        "receiver_mode": "disposable_peer",
        "terminal_disposition": "exit_after_response",
    }
    result_body = json.dumps(result, separators=(",", ":"), sort_keys=True).encode("utf-8")
    result_auth = result_headers["x-bluefire-authentication"]
    assert verify_authentication(
        result_auth,
        response_authentication(task_key, request_auth, result_body),
    )
    tampered_result = dict(result)
    tampered_result["terminal_disposition"] = "remain_available"
    tampered_body = json.dumps(tampered_result, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    assert not verify_authentication(
        result_auth,
        response_authentication(task_key, request_auth, tampered_body),
    )
    assert not thread.is_alive()
    assert summaries == [
        {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_requests",
            "connections_handled": 3,
            "challenges_issued": 1,
            "requests_accepted": 1,
            "requests_refused": 1,
        }
    ]
    with pytest.raises(OSError):
        socket.create_connection((receiver.host, receiver.port), timeout=0.2)


def test_disposable_peer_readiness_is_exact_and_path_free(enrollment_key: bytes) -> None:
    ready = io.StringIO()

    summary = run_loopback_receiver(
        ReceiverConfig(
            authentication_key=enrollment_key,
            port=0,
            max_connections=8,
            idle_timeout_seconds=0.01,
            disposable_peer=True,
        ),
        ready_stream=ready,
    )
    record = json.loads(ready.getvalue())

    assert record == {
        "schema_version": "bluefire.loopback-receiver-ready.v2",
        "mode": "disposable_peer",
        "process_id": os.getpid(),
        "host": "127.0.0.1",
        "port": record["port"],
        "max_requests": 1,
        "max_connections": 8,
        "storage": "memory_only",
    }
    assert isinstance(record["port"], int) and record["port"] > 0
    assert enrollment_key.hex() not in ready.getvalue()
    assert summary["reason"] == "idle_timeout"


def test_disposable_peer_absolute_lifetime_does_not_reset_after_connections(
    monkeypatch: pytest.MonkeyPatch,
    enrollment_key: bytes,
) -> None:
    monkeypatch.setattr(
        receiver_module,
        "DISPOSABLE_PEER_LIFETIME_TIMEOUT_SECONDS",
        0.05,
    )
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=enrollment_key,
            port=0,
            max_connections=8,
            idle_timeout_seconds=1.0,
            disposable_peer=True,
        )
    )
    thread, summaries = _serve_in_thread(receiver)

    status, _, _ = _exchange(
        receiver,
        (
            "GET /unreviewed HTTP/1.1\r\n"
            f"Host: {_authority(receiver)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii"),
    )
    assert status == 404
    thread.join(timeout=1.0)

    assert not thread.is_alive()
    assert summaries[0]["reason"] == "lifecycle_timeout"


def test_disposable_peer_absolute_lifetime_interrupts_a_stalled_request(
    monkeypatch: pytest.MonkeyPatch,
    enrollment_key: bytes,
) -> None:
    monkeypatch.setattr(
        receiver_module,
        "DISPOSABLE_PEER_LIFETIME_TIMEOUT_SECONDS",
        0.2,
    )
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=enrollment_key,
            port=0,
            max_connections=8,
            idle_timeout_seconds=1.0,
            disposable_peer=True,
        )
    )
    thread, summaries = _serve_in_thread(receiver)

    with socket.create_connection((receiver.host, receiver.port), timeout=1.0) as connection:
        connection.settimeout(1.0)
        connection.sendall(b"GET /bluefire/v1/challenge HTTP/1.1\r\n")
        status, _, body = _read_response(connection)

    thread.join(timeout=1.0)

    assert status == 408
    assert body == {"accepted": False, "error": "request_timeout"}
    assert not thread.is_alive()
    assert summaries[0]["reason"] == "lifecycle_timeout"


def test_disposable_peer_process_identity_matches_the_runner_u32_contract() -> None:
    arguments = {
        "task_id": TASK_ID,
        "session_id": "1" * 64,
        "nonce": "2" * 64,
        "host": "127.0.0.1",
        "port": 4317,
        "sha256": "3" * 64,
        "content_length": 1,
    }

    with pytest.raises(ReceiverAuthenticationError, match="process identity"):
        disposable_peer_challenge_document(
            **arguments,
            receiver_process_id=2**32,
        )


def test_cli_disposable_peer_selects_locked_defaults(
    monkeypatch: pytest.MonkeyPatch,
    enrollment_key: bytes,
) -> None:
    seen: list[ReceiverConfig] = []

    class ActiveEnrollment:
        def hmac_key(self) -> bytes:
            return enrollment_key

    monkeypatch.setattr(cli_module, "managed_product_root", lambda: Path("managed-product"))
    monkeypatch.setattr(
        cli_module,
        "load_local_enrollment",
        lambda _root, *, require_active=True: ActiveEnrollment(),
    )
    monkeypatch.setattr(
        cli_module,
        "run_loopback_receiver",
        lambda config: seen.append(config) or {"reason": "max_requests"},
    )

    result = cli_module._execute(
        cli_module._parser().parse_args(["receiver", "--port", "0", "--disposable-peer"])
    )

    assert result == {"reason": "max_requests"}
    assert len(seen) == 1
    config = seen[0]
    assert config.disposable_peer is True
    assert config.host == "127.0.0.1"
    assert config.max_requests == 1
    assert config.max_connections == 8
    assert config.idle_timeout_seconds == 240.0
    assert config.storage_dir is None
