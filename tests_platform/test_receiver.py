import hashlib
import json
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from bluefire.receiver import LoopbackArtifactReceiver, ReceiverConfig


def _request(
    body: bytes,
    *,
    method: str = "POST",
    path: str = "/bluefire/v1/artifact",
    digest: str | None = None,
    content_length: int | None = None,
) -> bytes:
    digest = digest or hashlib.sha256(body).hexdigest()
    content_length = len(body) if content_length is None else content_length
    head = (
        f"{method} {path} HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"X-BlueFire-SHA256: {digest}\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    return head + body


def _exchange(receiver: LoopbackArtifactReceiver, request: bytes) -> tuple[int, dict[str, Any]]:
    with socket.create_connection((receiver.host, receiver.port), timeout=2.0) as connection:
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        return _read_response(connection)


def _read_response(connection: socket.socket) -> tuple[int, dict[str, Any]]:
    response = bytearray()
    while True:
        chunk = connection.recv(64 * 1024)
        if not chunk:
            break
        response.extend(chunk)
    head, body = bytes(response).split(b"\r\n\r\n", 1)
    status = int(head.split(b"\r\n", 1)[0].split(b" ")[1])
    return status, json.loads(body)


def _serve_in_thread(
    receiver: LoopbackArtifactReceiver,
) -> tuple[threading.Thread, list[dict[str, object]]]:
    summaries: list[dict[str, object]] = []

    def serve() -> None:
        summaries.append(dict(receiver.serve()))

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return thread, summaries


def test_real_socket_accepts_only_digest_bound_artifact_in_memory() -> None:
    body = b"opaque synthetic artifact\x00\xff"
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(port=0, max_requests=1, idle_timeout_seconds=2.0)
    )
    thread, summaries = _serve_in_thread(receiver)

    status, response = _exchange(receiver, _request(body))
    thread.join(timeout=3.0)

    assert not thread.is_alive()
    assert status == 200
    assert response == {
        "accepted": True,
        "bytes_received": len(body),
        "schema_version": "bluefire.loopback-receiver-result.v1",
        "sha256": hashlib.sha256(body).hexdigest(),
        "stored": False,
    }
    assert summaries == [
        {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_requests",
            "connections_handled": 1,
            "requests_accepted": 1,
            "requests_refused": 0,
        }
    ]


def test_real_socket_refusal_cap_stops_without_writing(tmp_path: Path) -> None:
    storage = tmp_path / "receiver-owned"
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=2.0,
            storage_dir=storage,
        )
    )
    thread, summaries = _serve_in_thread(receiver)

    wrong_path_status, wrong_path = _exchange(receiver, _request(b"one", path="/other"))
    wrong_digest_status, wrong_digest = _exchange(receiver, _request(b"two", digest="0" * 64))
    thread.join(timeout=3.0)

    assert not thread.is_alive()
    assert (wrong_path_status, wrong_path) == (
        404,
        {"accepted": False, "error": "path_not_found"},
    )
    assert (wrong_digest_status, wrong_digest) == (
        422,
        {"accepted": False, "error": "sha256_mismatch"},
    )
    assert [path.name for path in storage.iterdir()] == [".bluefire-receiver-owner"]
    assert summaries[0]["requests_accepted"] == 0
    assert summaries[0]["requests_refused"] == 2
    assert summaries[0]["connections_handled"] == 2
    assert summaries[0]["reason"] == "max_connections"


def test_malformed_request_does_not_consume_the_accepted_artifact_slot() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=2.0,
        )
    )
    thread, summaries = _serve_in_thread(receiver)

    refused_status, _ = _exchange(receiver, b"BROKEN\r\n\r\n")
    accepted_status, accepted = _exchange(receiver, _request(b"valid"))
    thread.join(timeout=3.0)

    assert not thread.is_alive()
    assert refused_status == 400
    assert accepted_status == 200
    assert accepted["accepted"] is True
    assert summaries[0] == {
        "schema_version": "bluefire.loopback-receiver-summary.v1",
        "reason": "max_requests",
        "connections_handled": 2,
        "requests_accepted": 1,
        "requests_refused": 1,
    }


def test_connection_cap_cannot_be_lower_than_the_accepted_artifact_limit() -> None:
    with pytest.raises(ValueError, match="between max_requests"):
        ReceiverConfig(max_requests=2, max_connections=1)


def test_real_socket_refuses_every_method_except_post() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            port=0,
            max_requests=1,
            max_connections=1,
            idle_timeout_seconds=2.0,
        )
    )
    thread, _ = _serve_in_thread(receiver)

    status, response = _exchange(receiver, _request(b"", method="GET"))
    thread.join(timeout=3.0)

    assert status == 405
    assert response == {"accepted": False, "error": "method_not_allowed"}


def test_explicit_receiver_owned_storage_uses_content_addressed_name(tmp_path: Path) -> None:
    body = b"store this opaque body"
    digest = hashlib.sha256(body).hexdigest()
    storage = tmp_path / "receiver-owned"
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            port=0,
            max_requests=1,
            idle_timeout_seconds=2.0,
            storage_dir=storage,
        )
    )
    thread, _ = _serve_in_thread(receiver)

    status, response = _exchange(receiver, _request(body))
    thread.join(timeout=3.0)

    assert status == 201
    assert response["stored"] is True
    assert (storage / f"sha256-{digest}.bin").read_bytes() == body


def test_storage_refuses_to_claim_an_existing_unmarked_directory(tmp_path: Path) -> None:
    storage = tmp_path / "not-receiver-owned"
    storage.mkdir()
    (storage / "existing.txt").write_text("unrelated", encoding="utf-8")

    with pytest.raises(ValueError, match="must be empty"):
        LoopbackArtifactReceiver(ReceiverConfig(port=0, storage_dir=storage))

    assert (storage / "existing.txt").read_text(encoding="utf-8") == "unrelated"


@pytest.mark.parametrize("host", ["localhost", "0.0.0.0", "192.0.2.1"])
def test_receiver_rejects_hostname_wildcard_and_non_loopback_bind(host: str) -> None:
    with pytest.raises(ValueError, match="literal loopback"):
        ReceiverConfig(host=host)


def test_body_bound_is_enforced_before_reading_declared_body() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            port=0,
            max_requests=1,
            max_connections=1,
            max_body_bytes=4,
            idle_timeout_seconds=2.0,
        )
    )
    thread, _ = _serve_in_thread(receiver)

    status, response = _exchange(receiver, _request(b"", content_length=5))
    thread.join(timeout=3.0)

    assert status == 413
    assert response == {"accepted": False, "error": "body_too_large"}


def test_receiver_stops_cleanly_after_bounded_idle_timeout() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(port=0, max_requests=1, idle_timeout_seconds=0.05)
    )

    summary = receiver.serve()

    assert summary["reason"] == "idle_timeout"
    assert summary["connections_handled"] == 0


def test_receiver_enforces_one_aggregate_request_deadline_for_slow_clients() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            port=0,
            max_requests=1,
            max_connections=1,
            request_timeout_seconds=0.2,
            idle_timeout_seconds=1.0,
        )
    )
    thread, summaries = _serve_in_thread(receiver)

    started = time.monotonic()
    with socket.create_connection((receiver.host, receiver.port), timeout=1.0) as connection:
        connection.settimeout(1.0)
        connection.sendall(b"P")
        time.sleep(0.08)
        connection.sendall(b"O")
        time.sleep(0.08)
        connection.sendall(b"S")
        response = _read_response(connection)

    thread.join(timeout=1.0)
    assert not thread.is_alive()
    assert time.monotonic() - started < 0.8
    status, payload = response
    assert status == 408
    assert payload == {"accepted": False, "error": "request_timeout"}
    assert summaries == [
        {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_connections",
            "connections_handled": 1,
            "requests_accepted": 0,
            "requests_refused": 1,
        }
    ]


def test_receiver_stops_cleanly_on_explicit_stop() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(port=0, max_requests=1, idle_timeout_seconds=2.0)
    )
    thread, summaries = _serve_in_thread(receiver)

    receiver.stop()
    thread.join(timeout=1.0)

    assert not thread.is_alive()
    assert summaries[0]["reason"] == "explicit_stop"
