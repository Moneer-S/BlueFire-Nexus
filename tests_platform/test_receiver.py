import hashlib
import io
import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest

import bluefire.receiver as receiver_module
from bluefire.receiver import LoopbackArtifactReceiver, ReceiverConfig, run_loopback_receiver
from bluefire.receiver_auth import (
    challenge_authentication,
    derive_receiver_task_key,
    request_authentication,
    request_document,
    response_authentication,
    verify_authentication,
)

ENROLLMENT_KEY = bytes(range(32))
TASK_ID = "execute-" + "1" * 64


def _request(
    receiver: LoopbackArtifactReceiver,
    body: bytes,
    *,
    task_id: str = TASK_ID,
    enrollment_key: bytes = ENROLLMENT_KEY,
    session_id: str | None = None,
    nonce: str | None = None,
    method: str = "POST",
    path: str = "/bluefire/v1/artifact",
    digest: str | None = None,
    content_length: int | None = None,
    authentication: str | None = None,
) -> bytes:
    digest = digest or hashlib.sha256(body).hexdigest()
    content_length = len(body) if content_length is None else content_length
    if session_id is None or nonce is None:
        session_id, nonce = _challenge(
            receiver,
            task_id=task_id,
            enrollment_key=enrollment_key,
            digest=digest,
            content_length=content_length,
        )
    document = request_document(
        task_id=task_id,
        session_id=session_id,
        nonce=nonce,
        host=receiver.host,
        port=receiver.port,
        sha256=digest,
        content_length=content_length,
    )
    task_key = derive_receiver_task_key(enrollment_key, task_id)
    authentication = authentication or request_authentication(task_key, document)
    authority = _authority(receiver)
    head = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "Content-Type: application/octet-stream\r\n"
        f"X-BlueFire-SHA256: {digest}\r\n"
        f"X-BlueFire-Task-ID: {task_id}\r\n"
        f"X-BlueFire-Session-ID: {session_id}\r\n"
        f"X-BlueFire-Nonce: {nonce}\r\n"
        f"X-BlueFire-Authentication: {authentication}\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")
    return head + body


def _authority(receiver: LoopbackArtifactReceiver) -> str:
    host = receiver.host
    rendered = f"[{host}]" if ":" in host else host
    return f"{rendered}:{receiver.port}"


def _challenge(
    receiver: LoopbackArtifactReceiver,
    *,
    task_id: str = TASK_ID,
    enrollment_key: bytes = ENROLLMENT_KEY,
    digest: str | None = None,
    content_length: int = 0,
) -> tuple[str, str]:
    digest = digest or hashlib.sha256(b"").hexdigest()
    request = (
        "GET /bluefire/v1/challenge HTTP/1.1\r\n"
        f"Host: {_authority(receiver)}\r\n"
        f"X-BlueFire-Task-ID: {task_id}\r\n"
        f"X-BlueFire-SHA256: {digest}\r\n"
        f"X-BlueFire-Content-Length: {content_length}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    status, headers, body = _exchange(receiver, request)
    assert status == 200
    task_key = derive_receiver_task_key(enrollment_key, task_id)
    assert verify_authentication(
        headers.get("x-bluefire-authentication"),
        challenge_authentication(task_key, body),
    )
    return str(body["session_id"]), str(body["nonce"])


def _exchange(
    receiver: LoopbackArtifactReceiver, request: bytes
) -> tuple[int, dict[str, str], dict[str, Any]]:
    with socket.create_connection((receiver.host, receiver.port), timeout=2.0) as connection:
        connection.sendall(request)
        connection.shutdown(socket.SHUT_WR)
        return _read_response(connection)


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
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            idle_timeout_seconds=2.0,
        )
    )
    thread, summaries = _serve_in_thread(receiver)

    session_id, nonce = _challenge(
        receiver,
        digest=hashlib.sha256(body).hexdigest(),
        content_length=len(body),
    )
    task_key = derive_receiver_task_key(ENROLLMENT_KEY, TASK_ID)
    raw_request = _request(receiver, body, session_id=session_id, nonce=nonce)
    request_auth = next(
        line.split(b":", 1)[1].strip().decode("ascii")
        for line in raw_request.split(b"\r\n")
        if line.lower().startswith(b"x-bluefire-authentication:")
    )
    status, headers, response = _exchange(receiver, raw_request)
    thread.join(timeout=3.0)

    assert not thread.is_alive()
    assert status == 200
    assert response == {
        "accepted": True,
        "bytes_received": len(body),
        "schema_version": "bluefire.loopback-receiver-result.v2",
        "session_id": session_id,
        "sha256": hashlib.sha256(body).hexdigest(),
        "stored": False,
        "task_id": TASK_ID,
    }
    response_body = json.dumps(response, separators=(",", ":"), sort_keys=True).encode("utf-8")
    assert verify_authentication(
        headers.get("x-bluefire-authentication"),
        response_authentication(task_key, request_auth, response_body),
    )
    assert summaries == [
        {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_requests",
            "connections_handled": 2,
            "challenges_issued": 1,
            "requests_accepted": 1,
            "requests_refused": 0,
        }
    ]


def test_real_socket_refusal_cap_stops_without_writing(tmp_path: Path) -> None:
    storage = tmp_path / "receiver-owned"
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=3,
            idle_timeout_seconds=2.0,
            storage_dir=storage,
        )
    )
    thread, summaries = _serve_in_thread(receiver)

    wrong_path_status, _, wrong_path = _exchange(
        receiver,
        b"POST /other HTTP/1.1\r\nHost: "
        + _authority(receiver).encode("ascii")
        + b"\r\nContent-Length: 0\r\n\r\n",
    )
    wrong_digest_status, _, wrong_digest = _exchange(
        receiver, _request(receiver, b"two", digest="0" * 64)
    )
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
    assert summaries[0]["connections_handled"] == 3
    assert summaries[0]["challenges_issued"] == 1
    assert summaries[0]["reason"] == "max_connections"


def test_malformed_request_does_not_consume_the_accepted_artifact_slot() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=3,
            idle_timeout_seconds=2.0,
        )
    )
    thread, summaries = _serve_in_thread(receiver)

    refused_status, _, _ = _exchange(receiver, b"BROKEN\r\n\r\n")
    accepted_status, _, accepted = _exchange(receiver, _request(receiver, b"valid"))
    thread.join(timeout=3.0)

    assert not thread.is_alive()
    assert refused_status == 400
    assert accepted_status == 200
    assert accepted["accepted"] is True
    assert summaries[0] == {
        "schema_version": "bluefire.loopback-receiver-summary.v1",
        "reason": "max_requests",
        "connections_handled": 3,
        "challenges_issued": 1,
        "requests_accepted": 1,
        "requests_refused": 1,
    }


def test_connection_cap_reserves_challenge_and_artifact_for_each_acceptance() -> None:
    with pytest.raises(ValueError, match="between twice max_requests"):
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            max_requests=2,
            max_connections=3,
        )


def test_real_socket_refuses_every_method_except_post() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=2.0,
        )
    )
    thread, _ = _serve_in_thread(receiver)

    status, _, response = _exchange(
        receiver,
        (
            "GET /bluefire/v1/artifact HTTP/1.1\r\n"
            f"Host: {_authority(receiver)}\r\nConnection: close\r\n\r\n"
        ).encode("ascii"),
    )
    receiver.stop()
    thread.join(timeout=3.0)

    assert status == 405
    assert response == {"accepted": False, "error": "method_not_allowed"}


def test_explicit_receiver_owned_storage_uses_content_addressed_name(tmp_path: Path) -> None:
    body = b"store this opaque body"
    digest = hashlib.sha256(body).hexdigest()
    storage = tmp_path / "receiver-owned"
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            idle_timeout_seconds=2.0,
            storage_dir=storage,
        )
    )
    thread, _ = _serve_in_thread(receiver)

    status, _, response = _exchange(receiver, _request(receiver, body))
    thread.join(timeout=3.0)

    assert status == 201
    assert response["stored"] is True
    assert (storage / f"sha256-{digest}.bin").read_bytes() == body


def test_storage_refuses_to_claim_an_existing_unmarked_directory(tmp_path: Path) -> None:
    storage = tmp_path / "not-receiver-owned"
    storage.mkdir()
    (storage / "existing.txt").write_text("unrelated", encoding="utf-8")

    with pytest.raises(ValueError, match="must be empty"):
        LoopbackArtifactReceiver(
            ReceiverConfig(authentication_key=ENROLLMENT_KEY, port=0, storage_dir=storage)
        )

    assert (storage / "existing.txt").read_text(encoding="utf-8") == "unrelated"


def test_storage_startup_bounds_unmarked_scan_and_does_not_enumerate_reused_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unmarked = tmp_path / "unmarked"
    unmarked.mkdir()
    (unmarked / "foreign.txt").write_bytes(b"foreign")
    original_names = receiver_module._PinnedPrivateDirectory.names
    observed_bounds: list[int | None] = []

    def record_bounded_names(directory: Any, *, maximum: int | None = None) -> tuple[str, ...]:
        observed_bounds.append(maximum)
        return original_names(directory, maximum=maximum)

    monkeypatch.setattr(
        receiver_module._PinnedPrivateDirectory,
        "names",
        record_bounded_names,
    )
    with pytest.raises(ValueError, match="must be empty"):
        LoopbackArtifactReceiver(
            ReceiverConfig(authentication_key=ENROLLMENT_KEY, port=0, storage_dir=unmarked)
        )
    assert observed_bounds == [1]

    marked = tmp_path / "marked"
    first = LoopbackArtifactReceiver(
        ReceiverConfig(authentication_key=ENROLLMENT_KEY, port=0, storage_dir=marked)
    )
    first.close()
    (marked / f"sha256-{'0' * 64}.bin").write_bytes(b"prior artifact")
    observed_bounds.clear()
    second = LoopbackArtifactReceiver(
        ReceiverConfig(authentication_key=ENROLLMENT_KEY, port=0, storage_dir=marked)
    )
    second.close()
    assert observed_bounds == []


def test_receiver_owned_storage_accepts_an_empty_artifact(tmp_path: Path) -> None:
    storage = tmp_path / "receiver-owned"
    digest = hashlib.sha256(b"").hexdigest()
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=1.0,
            storage_dir=storage,
        )
    )
    thread, _ = _serve_in_thread(receiver)

    status, _, response = _exchange(receiver, _request(receiver, b""))
    thread.join(timeout=3.0)

    assert status == 201
    assert response["stored"] is True
    assert (storage / f"sha256-{digest}.bin").read_bytes() == b""


def test_storage_root_swap_cannot_redirect_artifact_into_a_victim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = tmp_path / "receiver-owned"
    parked = tmp_path / "parked-receiver-owned"
    victim = tmp_path / "victim"
    victim.mkdir()
    sentinel = victim / "sentinel.txt"
    sentinel.write_bytes(b"must survive")
    body = b"root swap must fail closed"
    digest = hashlib.sha256(body).hexdigest()
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=1.0,
            storage_dir=storage,
        )
    )
    original_create = receiver_module._PinnedPrivateDirectory.create
    state = {"swapped": False, "blocked": False}

    def swap_root_before_artifact_create(
        directory: Any,
        name: str,
        payload: bytes,
        *,
        maximum: int,
    ) -> None:
        if name.startswith("sha256-") and not any(state.values()):
            try:
                storage.rename(parked)
            except OSError:
                state["blocked"] = True
            else:
                try:
                    storage.symlink_to(victim, target_is_directory=True)
                except OSError:
                    parked.rename(storage)
                    state["blocked"] = True
                else:
                    state["swapped"] = True
        original_create(directory, name, payload, maximum=maximum)

    monkeypatch.setattr(
        receiver_module._PinnedPrivateDirectory,
        "create",
        swap_root_before_artifact_create,
    )
    thread, _ = _serve_in_thread(receiver)
    try:
        status, _, response = _exchange(receiver, _request(receiver, body))
        thread.join(timeout=3.0)

        assert not thread.is_alive()
        assert state["swapped"] or state["blocked"]
        if state["swapped"]:
            assert status == 500
            assert response == {"accepted": False, "error": "storage_failed"}
        else:
            assert status == 201
            assert response["stored"] is True
        assert sentinel.read_bytes() == b"must survive"
        assert not (victim / f"sha256-{digest}.bin").exists()
    finally:
        receiver.stop()
        thread.join(timeout=1.0)
        if state["swapped"]:
            storage.unlink()
            parked.rename(storage)


def test_existing_hardlink_is_never_overwritten_or_unlinked_on_storage_failure(
    tmp_path: Path,
) -> None:
    storage = tmp_path / "receiver-owned"
    body = b"new artifact"
    digest = hashlib.sha256(body).hexdigest()
    victim = tmp_path / "victim.bin"
    victim_payload = b"victim must survive"
    victim.write_bytes(victim_payload)
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=1.0,
            storage_dir=storage,
        )
    )
    target = storage / f"sha256-{digest}.bin"
    try:
        os.link(victim, target)
    except OSError as exc:
        receiver.close()
        pytest.skip(f"hardlinks are unavailable on this test filesystem: {exc}")
    thread, _ = _serve_in_thread(receiver)

    status, _, response = _exchange(receiver, _request(receiver, body))
    thread.join(timeout=3.0)

    assert not thread.is_alive()
    assert status == 500
    assert response == {"accepted": False, "error": "storage_failed"}
    assert victim.read_bytes() == victim_payload
    assert target.read_bytes() == victim_payload
    assert target.samefile(victim)
    assert not any(path.name.startswith(".t-") for path in storage.iterdir())


def test_storage_cleanup_never_unlinks_a_racing_same_content_victim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = tmp_path / "receiver-owned"
    body = b"same content cannot substitute identity"
    digest = hashlib.sha256(body).hexdigest()
    victim = tmp_path / "victim.bin"
    victim.write_bytes(body)
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=1.0,
            storage_dir=storage,
        )
    )
    original_promote = receiver_module._PinnedPrivateDirectory.promote
    swapped_alias: Path | None = None
    original_temporary: Path | None = None

    def swap_temporary_before_promotion(
        directory: Any,
        source: str,
        destination: str,
        *,
        maximum: int,
        expected: bytes,
        permissions_already_private: bool = False,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        nonlocal swapped_alias, original_temporary
        if destination.startswith("sha256-") and swapped_alias is None:
            swapped_alias = storage / source
            original_temporary = storage / f"{source}.original"
            swapped_alias.replace(original_temporary)
            os.link(victim, swapped_alias)
        original_promote(
            directory,
            source,
            destination,
            maximum=maximum,
            expected=expected,
            permissions_already_private=permissions_already_private,
            expected_identity=expected_identity,
        )

    monkeypatch.setattr(
        receiver_module._PinnedPrivateDirectory,
        "promote",
        swap_temporary_before_promotion,
    )
    thread, _ = _serve_in_thread(receiver)

    status, _, response = _exchange(receiver, _request(receiver, body))
    thread.join(timeout=3.0)

    assert not thread.is_alive()
    assert status == 500
    assert response == {"accepted": False, "error": "storage_failed"}
    assert swapped_alias is not None
    assert original_temporary is not None
    assert victim.read_bytes() == body
    assert swapped_alias.read_bytes() == body
    assert swapped_alias.samefile(victim)
    assert original_temporary.read_bytes() == body
    assert not (storage / f"sha256-{digest}.bin").exists()


def test_storage_promotion_rejects_a_same_content_single_link_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = tmp_path / "receiver-owned"
    body = b"same bytes do not substitute exact temporary identity"
    digest = hashlib.sha256(body).hexdigest()
    replacement = tmp_path / "single-link-replacement.bin"
    replacement.write_bytes(body)
    replacement_identity = replacement.stat().st_dev, replacement.stat().st_ino
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=1.0,
            storage_dir=storage,
        )
    )
    original_promote = receiver_module._PinnedPrivateDirectory.promote
    swapped_source: Path | None = None
    original_temporary: Path | None = None
    original_identity: tuple[int, int] | None = None

    def swap_single_link_before_promotion(
        directory: Any,
        source: str,
        destination: str,
        *,
        maximum: int,
        expected: bytes,
        permissions_already_private: bool = False,
        expected_identity: tuple[int, int] | None = None,
    ) -> None:
        nonlocal swapped_source, original_temporary, original_identity
        if destination.startswith("sha256-") and swapped_source is None:
            swapped_source = storage / source
            original_identity = (
                swapped_source.stat().st_dev,
                swapped_source.stat().st_ino,
            )
            original_temporary = storage / f"{source}.original"
            swapped_source.replace(original_temporary)
            replacement.replace(swapped_source)
            assert swapped_source.stat().st_nlink == 1
        original_promote(
            directory,
            source,
            destination,
            maximum=maximum,
            expected=expected,
            permissions_already_private=permissions_already_private,
            expected_identity=expected_identity,
        )

    monkeypatch.setattr(
        receiver_module._PinnedPrivateDirectory,
        "promote",
        swap_single_link_before_promotion,
    )
    thread, _ = _serve_in_thread(receiver)

    status, _, response = _exchange(receiver, _request(receiver, body))
    thread.join(timeout=3.0)

    assert not thread.is_alive()
    assert status == 500
    assert response == {"accepted": False, "error": "storage_failed"}
    assert swapped_source is not None
    assert original_temporary is not None
    assert original_identity is not None
    assert (swapped_source.stat().st_dev, swapped_source.stat().st_ino) == replacement_identity
    assert replacement_identity != original_identity
    assert swapped_source.read_bytes() == body
    assert original_temporary.read_bytes() == body
    assert not (storage / f"sha256-{digest}.bin").exists()


def test_receiver_close_releases_the_pinned_storage_directory(tmp_path: Path) -> None:
    storage = tmp_path / "receiver-owned"
    renamed = tmp_path / "receiver-owned-after-close"
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(authentication_key=ENROLLMENT_KEY, port=0, storage_dir=storage)
    )

    receiver.close()
    storage.rename(renamed)

    assert (renamed / ".bluefire-receiver-owner").is_file()


@pytest.mark.parametrize("host", ["localhost", "0.0.0.0", "192.0.2.1"])
def test_receiver_rejects_hostname_wildcard_and_non_loopback_bind(host: str) -> None:
    with pytest.raises(ValueError, match="literal loopback"):
        ReceiverConfig(authentication_key=ENROLLMENT_KEY, host=host)


def test_body_bound_is_enforced_before_reading_declared_body() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            max_body_bytes=4,
            idle_timeout_seconds=2.0,
        )
    )
    thread, summaries = _serve_in_thread(receiver)
    request = (
        "GET /bluefire/v1/challenge HTTP/1.1\r\n"
        f"Host: {_authority(receiver)}\r\n"
        f"X-BlueFire-Task-ID: {TASK_ID}\r\n"
        f"X-BlueFire-SHA256: {hashlib.sha256(b'').hexdigest()}\r\n"
        "X-BlueFire-Content-Length: 5\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")

    status, _, response = _exchange(receiver, request)
    receiver.stop()
    thread.join(timeout=3.0)

    assert status == 413
    assert response == {"accepted": False, "error": "body_too_large"}
    assert summaries[0]["challenges_issued"] == 0


def test_receiver_stops_cleanly_after_bounded_idle_timeout() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            idle_timeout_seconds=0.05,
        )
    )

    summary = receiver.serve()

    assert summary["reason"] == "idle_timeout"
    assert summary["connections_handled"] == 0


def test_receiver_enforces_one_aggregate_request_deadline_for_slow_clients() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
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
    second_status, _, _ = _exchange(receiver, b"BROKEN\r\n\r\n")

    thread.join(timeout=1.0)
    assert not thread.is_alive()
    assert time.monotonic() - started < 0.8
    status, _, payload = response
    assert status == 408
    assert second_status == 400
    assert payload == {"accepted": False, "error": "request_timeout"}
    assert summaries == [
        {
            "schema_version": "bluefire.loopback-receiver-summary.v1",
            "reason": "max_connections",
            "connections_handled": 2,
            "challenges_issued": 0,
            "requests_accepted": 0,
            "requests_refused": 2,
        }
    ]


def test_receiver_stops_cleanly_on_explicit_stop() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            idle_timeout_seconds=2.0,
        )
    )
    thread, summaries = _serve_in_thread(receiver)

    receiver.stop()
    thread.join(timeout=1.0)

    assert not thread.is_alive()
    assert summaries[0]["reason"] == "explicit_stop"


def test_foreign_task_key_cannot_authenticate_artifact() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=0.2,
        )
    )
    thread, summaries = _serve_in_thread(receiver)
    refused_body = b"must remain refused"
    session_id, nonce = _challenge(
        receiver,
        digest=hashlib.sha256(refused_body).hexdigest(),
        content_length=len(refused_body),
    )

    status, _, response = _exchange(
        receiver,
        _request(
            receiver,
            refused_body,
            session_id=session_id,
            nonce=nonce,
            enrollment_key=b"x" * 32,
        ),
    )
    thread.join(timeout=1.0)

    assert status == 401
    assert response == {"accepted": False, "error": "receiver_authentication_failed"}
    assert summaries[0]["requests_accepted"] == 0
    assert summaries[0]["requests_refused"] == 1


def test_challenge_is_exact_session_task_and_one_time() -> None:
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=2,
            max_connections=4,
            idle_timeout_seconds=0.2,
        )
    )
    thread, summaries = _serve_in_thread(receiver)
    one_time_body = b"one time"
    session_id, nonce = _challenge(
        receiver,
        digest=hashlib.sha256(one_time_body).hexdigest(),
        content_length=len(one_time_body),
    )
    request = _request(receiver, one_time_body, session_id=session_id, nonce=nonce)

    accepted_status, _, accepted = _exchange(receiver, request)
    replay_status, _, replay = _exchange(receiver, request)
    receiver.stop()
    thread.join(timeout=1.0)

    assert accepted_status == 200
    assert accepted["accepted"] is True
    assert replay_status == 401
    assert replay == {"accepted": False, "error": "receiver_authentication_failed"}
    assert summaries[0]["requests_accepted"] == 1
    assert summaries[0]["requests_refused"] == 1


def test_authenticated_challenge_cannot_be_relayed_to_another_listener() -> None:
    first = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=0.2,
        )
    )
    second = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=0.2,
        )
    )
    first_thread, _ = _serve_in_thread(first)
    second_thread, second_summaries = _serve_in_thread(second)
    relay_body = b"relay refused"
    session_id, nonce = _challenge(
        first,
        digest=hashlib.sha256(relay_body).hexdigest(),
        content_length=len(relay_body),
    )

    status, _, response = _exchange(
        second,
        _request(second, relay_body, session_id=session_id, nonce=nonce),
    )
    first.stop()
    first_thread.join(timeout=1.0)
    second_thread.join(timeout=1.0)

    assert status == 401
    assert response == {"accepted": False, "error": "receiver_authentication_failed"}
    assert second_summaries[0]["requests_accepted"] == 0


def test_challenge_cannot_authorize_another_digest_or_length() -> None:
    original = b"original"
    replacement = b"replacement"
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=0.2,
        )
    )
    thread, summaries = _serve_in_thread(receiver)
    session_id, nonce = _challenge(
        receiver,
        digest=hashlib.sha256(original).hexdigest(),
        content_length=len(original),
    )

    status, _, response = _exchange(
        receiver,
        _request(receiver, replacement, session_id=session_id, nonce=nonce),
    )
    thread.join(timeout=1.0)

    assert status == 401
    assert response == {"accepted": False, "error": "receiver_authentication_failed"}
    assert summaries[0]["requests_accepted"] == 0


def test_challenge_cannot_be_used_for_another_session_or_task() -> None:
    body = b"bound session"
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=3,
            idle_timeout_seconds=0.2,
        )
    )
    thread, summaries = _serve_in_thread(receiver)
    session_id, nonce = _challenge(
        receiver,
        digest=hashlib.sha256(body).hexdigest(),
        content_length=len(body),
    )

    session_status, _, _ = _exchange(
        receiver,
        _request(receiver, body, session_id="f" * 64, nonce=nonce),
    )
    other_task = "execute-" + "2" * 64
    task_status, _, _ = _exchange(
        receiver,
        _request(
            receiver,
            body,
            task_id=other_task,
            session_id=session_id,
            nonce=nonce,
        ),
    )
    thread.join(timeout=1.0)

    assert session_status == 401
    assert task_status == 401
    assert summaries[0]["requests_accepted"] == 0


def test_expired_challenge_is_refused() -> None:
    body = b"expires"
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            request_timeout_seconds=0.05,
            idle_timeout_seconds=4.0,
        )
    )
    thread, summaries = _serve_in_thread(receiver)
    session_id, nonce = _challenge(
        receiver,
        digest=hashlib.sha256(body).hexdigest(),
        content_length=len(body),
    )
    time.sleep(2.05)

    status, _, response = _exchange(
        receiver,
        _request(receiver, body, session_id=session_id, nonce=nonce),
    )
    thread.join(timeout=1.0)

    assert status == 401
    assert response == {"accepted": False, "error": "receiver_authentication_failed"}
    assert summaries[0]["requests_accepted"] == 0


def test_authenticated_request_detects_tampered_body() -> None:
    original = b"same"
    tampered = b"evil"
    digest = hashlib.sha256(original).hexdigest()
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            idle_timeout_seconds=0.2,
        )
    )
    thread, _ = _serve_in_thread(receiver)
    session_id, nonce = _challenge(
        receiver,
        digest=digest,
        content_length=len(original),
    )

    status, _, response = _exchange(
        receiver,
        _request(
            receiver,
            tampered,
            digest=digest,
            session_id=session_id,
            nonce=nonce,
        ),
    )
    thread.join(timeout=1.0)

    assert status == 422
    assert response == {"accepted": False, "error": "sha256_mismatch"}


def test_duplicate_or_control_character_headers_are_refused() -> None:
    body = b"strict headers"
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=3,
            idle_timeout_seconds=0.2,
        )
    )
    thread, summaries = _serve_in_thread(receiver)
    session_id, nonce = _challenge(
        receiver,
        digest=hashlib.sha256(body).hexdigest(),
        content_length=len(body),
    )
    request = _request(receiver, body, session_id=session_id, nonce=nonce)
    duplicate = request.replace(
        f"Content-Length: {len(body)}\r\n".encode("ascii"),
        f"Content-Length: {len(body)}\r\nContent-Length: {len(body)}\r\n".encode("ascii"),
    )

    duplicate_status, _, _ = _exchange(receiver, duplicate)
    control_status, _, _ = _exchange(
        receiver,
        (
            "GET /bluefire/v1/challenge HTTP/1.1\r\n"
            f"Host: {_authority(receiver)}\r\n"
            f"X-BlueFire-Task-ID: {TASK_ID}\r\n"
            f"X-BlueFire-SHA256: {hashlib.sha256(b'').hexdigest()}\r\n"
            "X-BlueFire-Content-Length: 0\r\n"
            "Connection: close\x00\r\n\r\n"
        ).encode("ascii"),
    )
    thread.join(timeout=1.0)

    assert duplicate_status == 400
    assert control_status == 400
    assert summaries[0]["requests_accepted"] == 0


def test_authenticated_body_trickle_cannot_reset_request_deadline() -> None:
    body = b"slow"
    receiver = LoopbackArtifactReceiver(
        ReceiverConfig(
            authentication_key=ENROLLMENT_KEY,
            port=0,
            max_requests=1,
            max_connections=2,
            request_timeout_seconds=0.15,
            idle_timeout_seconds=1.0,
        )
    )
    thread, summaries = _serve_in_thread(receiver)
    session_id, nonce = _challenge(
        receiver,
        digest=hashlib.sha256(body).hexdigest(),
        content_length=len(body),
    )
    request = _request(receiver, body, session_id=session_id, nonce=nonce)
    body_offset = request.index(b"\r\n\r\n") + 4

    started = time.monotonic()
    with socket.create_connection((receiver.host, receiver.port), timeout=1.0) as connection:
        connection.settimeout(1.0)
        connection.sendall(request[: body_offset + 1])
        time.sleep(0.2)
        status, _, response = _read_response(connection)
    thread.join(timeout=1.0)

    assert time.monotonic() - started < 0.8
    assert status == 408
    assert response == {"accepted": False, "error": "request_timeout"}
    assert summaries[0]["requests_accepted"] == 0


def test_receiver_readiness_and_summary_never_leak_key_or_storage_path(tmp_path: Path) -> None:
    secret = b"sensitive receiver material!!".ljust(32, b"!")
    storage = tmp_path / "private-receiver-storage"
    ready = io.StringIO()

    summary = run_loopback_receiver(
        ReceiverConfig(
            authentication_key=secret,
            port=0,
            idle_timeout_seconds=0.01,
            storage_dir=storage,
        ),
        ready_stream=ready,
    )

    rendered = ready.getvalue() + json.dumps(summary, sort_keys=True)
    assert secret.hex() not in rendered
    assert str(storage) not in rendered
    assert summary["reason"] == "idle_timeout"


def test_receiver_configuration_repr_never_contains_authentication_key() -> None:
    secret = b"sensitive receiver material!!".ljust(32, b"!")
    config = ReceiverConfig(authentication_key=secret)

    assert secret.hex() not in repr(config)
    assert "authentication_key" not in repr(config)
