from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

import bluefire.linux_exec_supervisor_docker as cleanup_module
from bluefire.engine_docker_proxy import DockerDaemonExchange
from bluefire.engine_docker_transport import LinuxDockerDaemonEndpoint
from bluefire.linux_exec_supervisor_docker import (
    ControllerOwnedDockerCleanupCancellation,
    FixedDockerExecCleanup,
    LinuxExecSupervisorDockerError,
    SupervisorDockerContainerIdentity,
)
from bluefire.util import content_hash
from tests_platform.test_engine_docker_control import policy_v2

CONTAINER = "a" * 64
DAEMON = content_hash("daemon")
DEADLINE = 10_000_000_000
POLICY = content_hash("policy")
EXECUTION = content_hash("execution identity")
PROFILE = content_hash("profile")
IMAGE_CONFIG = content_hash("image config")
IMAGE_REFERENCE = "ghcr.io/usestrix/strix-sandbox@" + content_hash("image")
ATTEMPT = "engine-attempt-" + "1" * 32
LABELS = tuple(
    sorted(
        {
            "bluefire.engine.attempt": ATTEMPT,
            "bluefire.engine.image-identity": content_hash("image identity"),
            "strix-run-id": ATTEMPT,
            "strix-run-type": "bluefire",
        }.items()
    )
)
IDENTITY = SupervisorDockerContainerIdentity(
    container_id=CONTAINER,
    container_name="strix-sandbox-owned",
    image_config_digest=IMAGE_CONFIG,
    image_reference=IMAGE_REFERENCE,
    required_labels=LABELS,
    policy_digest=POLICY,
    execution_identity_digest=EXECUTION,
    profile_digest=PROFILE,
)


def test_identity_accepts_exact_v2_policy_labels_without_circular_digest() -> None:
    policy = policy_v2()
    identity = SupervisorDockerContainerIdentity(
        container_id=CONTAINER,
        container_name=policy.container_name,
        image_config_digest=policy.image_config_digest,
        image_reference=policy.image_reference,
        required_labels=policy.required_labels,
        policy_digest=policy.policy_digest,
        execution_identity_digest=policy.execution_identity_digest,
        profile_digest=policy.image_runtime_profile_digest,
    )
    assert identity.required_labels == policy.required_labels
    assert identity.policy_digest == policy.policy_digest
    assert dict(identity.required_labels)["bluefire.engine.attempt"] == policy.attempt_id
    assert "bluefire.engine.policy-digest" not in dict(identity.required_labels)


def test_identity_rejects_mismatched_attempt_ownership_labels() -> None:
    changed = dict(LABELS)
    changed["strix-run-id"] = "engine-attempt-" + "2" * 32
    with pytest.raises(LinuxExecSupervisorDockerError, match="container_labels_unbound"):
        replace(IDENTITY, required_labels=tuple(sorted(changed.items())))


def test_identity_rejects_missing_or_invalid_image_identity_label() -> None:
    missing = dict(LABELS)
    del missing["bluefire.engine.image-identity"]
    with pytest.raises(LinuxExecSupervisorDockerError, match="container_labels_invalid"):
        replace(IDENTITY, required_labels=tuple(sorted(missing.items())))
    invalid = dict(LABELS)
    invalid["bluefire.engine.image-identity"] = "unbound"
    with pytest.raises(LinuxExecSupervisorDockerError, match="container_labels_unbound"):
        replace(IDENTITY, required_labels=tuple(sorted(invalid.items())))


def _endpoint() -> LinuxDockerDaemonEndpoint:
    return LinuxDockerDaemonEndpoint(
        socket_path="/run/docker.sock",
        daemon_instance_digest=DAEMON,
        socket_device=1,
        socket_inode=2,
        peer_uid=0,
        peer_gid=0,
        peer_pid=10,
    )


def _raw(status: int, body: object | bytes = b"") -> bytes:
    if not isinstance(body, bytes):
        body = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    reason = {200: "OK", 204: "No Content", 404: "Not Found", 409: "Conflict"}[status]
    if status == 204:
        assert body == b""
        return f"HTTP/1.1 {status} {reason}\r\n\r\n".encode()
    return (
        f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(body)}\r\n"
        "Content-Type: application/json\r\n\r\n"
    ).encode() + body


def _inspect(*, running: bool) -> bytes:
    return _raw(
        200,
        {
            "Id": CONTAINER,
            "Image": IMAGE_CONFIG,
            "Name": "/strix-sandbox-owned",
            "Config": {"Image": IMAGE_REFERENCE, "Labels": dict(LABELS)},
            "State": {"Running": running},
        },
    )


def _absent() -> bytes:
    return _raw(404, {"message": f"No such container: {CONTAINER}"})


def _cancellation(*, cancelled: bool = False) -> ControllerOwnedDockerCleanupCancellation:
    signal = ControllerOwnedDockerCleanupCancellation()
    if cancelled:
        signal.cancel()
    return signal


class _Transport:
    def __init__(self, responses: list[bytes]) -> None:
        self.responses = responses
        self.requests: list[bytes] = []
        self.deadlines: list[int] = []

    def exchange(
        self,
        raw_request: bytes,
        *,
        deadline_monotonic_ns: int,
        cancellation,
        response_byte_limit: int | None = None,
    ) -> DockerDaemonExchange:
        assert response_byte_limit == 256 * 1024
        assert cancellation.is_cancelled() is False
        self.requests.append(raw_request)
        self.deadlines.append(deadline_monotonic_ns)
        response = self.responses.pop(0)
        return DockerDaemonExchange(
            request_digest="sha256:" + hashlib.sha256(raw_request).hexdigest(),
            daemon_instance_digest=DAEMON,
            raw_response=response,
        )


def _cleanup(transport: _Transport) -> FixedDockerExecCleanup:
    return FixedDockerExecCleanup._for_test(
        _endpoint(),
        stop_timeout_seconds=5,
        transport=transport,
    )


def _targets(transport: _Transport) -> list[str]:
    return [request.split(b" ", 2)[1].decode() for request in transport.requests]


def test_running_container_uses_only_fixed_inspect_stop_remove_absence_grammar(
    monkeypatch,
) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 1)
    transport = _Transport([_inspect(running=True), _raw(204), _raw(204), _absent()])
    result = _cleanup(transport).cleanup(
        IDENTITY, deadline_monotonic_ns=DEADLINE, cancellation=_cancellation()
    )

    assert _targets(transport) == [
        f"/v1.43/containers/{CONTAINER}/json",
        f"/v1.43/containers/{CONTAINER}/stop?t=5",
        f"/v1.43/containers/{CONTAINER}?force=1&v=1",
        f"/v1.43/containers/{CONTAINER}/json",
    ]
    assert [request.split(b" ", 1)[0] for request in transport.requests] == [
        b"GET",
        b"POST",
        b"DELETE",
        b"GET",
    ]
    assert all(deadline == DEADLINE for deadline in transport.deadlines)
    assert result.absent_verified is True
    assert result.cleanup_uncertain is False
    assert result.stop_sent is True
    assert result.remove_sent is True
    assert result.container_identity_digest == IDENTITY.identity_digest
    assert result.test_provider is True
    assert result.live_daemon_proof is False
    assert len(result.request_digests) == len(result.response_digests) == 4


def test_stopped_container_skips_stop_but_still_removes_and_verifies_absence(
    monkeypatch,
) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 1)
    transport = _Transport([_inspect(running=False), _raw(204), _absent()])
    result = _cleanup(transport).cleanup(
        IDENTITY, deadline_monotonic_ns=DEADLINE, cancellation=_cancellation()
    )
    assert [request.split(b" ", 1)[0] for request in transport.requests] == [
        b"GET",
        b"DELETE",
        b"GET",
    ]
    assert result.stop_sent is False
    assert result.remove_sent is True


def test_already_absent_returns_independent_inventory_proof_without_effect(
    monkeypatch,
) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 1)
    transport = _Transport([_absent()])
    result = _cleanup(transport).cleanup(
        IDENTITY, deadline_monotonic_ns=DEADLINE, cancellation=_cancellation()
    )
    assert len(transport.requests) == 1
    assert result.stop_sent is False
    assert result.remove_sent is False
    assert result.final_inventory_digest.startswith("sha256:")


def test_inspect_must_bind_exact_container_and_running_state(monkeypatch) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 1)
    wrong = _raw(
        200,
        {
            "Id": "b" * 64,
            "Image": IMAGE_CONFIG,
            "Name": "/strix-sandbox-owned",
            "Config": {"Image": IMAGE_REFERENCE, "Labels": dict(LABELS)},
            "State": {"Running": True},
        },
    )
    with pytest.raises(LinuxExecSupervisorDockerError, match="inspect_identity") as raised:
        _cleanup(_Transport([wrong])).cleanup(
            IDENTITY, deadline_monotonic_ns=DEADLINE, cancellation=_cancellation()
        )
    assert raised.value.cleanup_uncertain is True
    assert raised.value.effect_may_have_occurred is False


def test_destructive_cleanup_requires_exact_reviewed_labels(monkeypatch) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 1)
    changed_labels = dict(LABELS)
    changed_labels["bluefire.engine.image-identity"] = content_hash("changed")
    wrong = _raw(
        200,
        {
            "Id": CONTAINER,
            "Image": IMAGE_CONFIG,
            "Name": "/strix-sandbox-owned",
            "Config": {"Image": IMAGE_REFERENCE, "Labels": changed_labels},
            "State": {"Running": True},
        },
    )
    transport = _Transport([wrong])
    with pytest.raises(LinuxExecSupervisorDockerError, match="inspect_identity"):
        _cleanup(transport).cleanup(
            IDENTITY, deadline_monotonic_ns=DEADLINE, cancellation=_cancellation()
        )
    assert len(transport.requests) == 1
    assert transport.requests[0].startswith(b"GET ")


def test_404_requires_exact_docker_absence_contract(monkeypatch) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 1)
    for body in ({}, {"message": "page not found"}, {"message": "No such container"}):
        with pytest.raises(LinuxExecSupervisorDockerError, match="absence_unqualified"):
            _cleanup(_Transport([_raw(404, body)])).cleanup(
                IDENTITY,
                deadline_monotonic_ns=DEADLINE,
                cancellation=_cancellation(),
            )


def test_exchange_must_bind_exact_request_and_daemon(monkeypatch) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 1)

    class WrongDaemon(_Transport):
        def exchange(self, *args, **kwargs):
            return replace(
                super().exchange(*args, **kwargs),
                daemon_instance_digest=content_hash("another daemon"),
            )

    with pytest.raises(LinuxExecSupervisorDockerError, match="exchange_binding"):
        _cleanup(WrongDaemon([_absent()])).cleanup(
            IDENTITY, deadline_monotonic_ns=DEADLINE, cancellation=_cancellation()
        )

    class WrongRequest(_Transport):
        def exchange(self, *args, **kwargs):
            return replace(
                super().exchange(*args, **kwargs),
                request_digest=content_hash("another request"),
            )

    with pytest.raises(LinuxExecSupervisorDockerError, match="exchange_binding"):
        _cleanup(WrongRequest([_absent()])).cleanup(
            IDENTITY, deadline_monotonic_ns=DEADLINE, cancellation=_cancellation()
        )


def test_effect_response_failure_is_cleanup_uncertain(monkeypatch) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 1)
    transport = _Transport([_inspect(running=True), _raw(409, {})])
    with pytest.raises(LinuxExecSupervisorDockerError, match="stop_refused") as raised:
        _cleanup(transport).cleanup(
            IDENTITY, deadline_monotonic_ns=DEADLINE, cancellation=_cancellation()
        )
    assert raised.value.cleanup_uncertain is True
    assert raised.value.effect_may_have_occurred is True


def test_cancel_and_elapsed_deadline_send_nothing(monkeypatch) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 50)
    for cancellation, deadline, code in (
        (_cancellation(cancelled=True), 100, "cancelled"),
        (_cancellation(), 50, "deadline_elapsed"),
    ):
        transport = _Transport([])
        with pytest.raises(LinuxExecSupervisorDockerError, match=code) as raised:
            _cleanup(transport).cleanup(
                IDENTITY,
                deadline_monotonic_ns=deadline,
                cancellation=cancellation,
            )
        assert transport.requests == []
        assert raised.value.cleanup_uncertain is True


@pytest.mark.parametrize("version", ["", "1.43", "v1.23", "v1.44", "v1.100", "v1.4x", "v2.43"])
def test_api_version_is_a_bounded_segment_not_a_path(version: str) -> None:
    with pytest.raises(LinuxExecSupervisorDockerError, match="api_version_invalid") as raised:
        FixedDockerExecCleanup._for_test(_endpoint(), api_version=version, transport=_Transport([]))
    assert raised.value.cleanup_uncertain is False


@pytest.mark.parametrize("container", ["", "A" * 64, "a" * 63, "a" * 65, "../json"])
def test_container_identity_cannot_inject_a_request_target(monkeypatch, container: str) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 1)
    transport = _Transport([])
    with pytest.raises(
        LinuxExecSupervisorDockerError, match="container_identity_invalid"
    ) as raised:
        replace(IDENTITY, container_id=container)
    assert transport.requests == []
    assert raised.value.cleanup_uncertain is False


def test_response_framing_is_strict_and_bounded(monkeypatch) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 1)
    malformed = b"HTTP/1.1 404 Not Found\nContent-Length: 0\n\n"
    with pytest.raises(LinuxExecSupervisorDockerError, match="response_framing"):
        _cleanup(_Transport([malformed])).cleanup(
            IDENTITY, deadline_monotonic_ns=DEADLINE, cancellation=_cancellation()
        )


def test_deadline_is_rechecked_after_transport_before_absence_publication(
    monkeypatch,
) -> None:
    clock = {"value": 1}
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: clock["value"])

    class CrossingTransport(_Transport):
        def exchange(self, *args, **kwargs):
            result = super().exchange(*args, **kwargs)
            clock["value"] = DEADLINE
            return result

    transport = CrossingTransport([_absent()])
    with pytest.raises(LinuxExecSupervisorDockerError, match="deadline_elapsed"):
        _cleanup(transport).cleanup(
            IDENTITY, deadline_monotonic_ns=DEADLINE, cancellation=_cancellation()
        )


def test_absence_polling_has_a_hard_request_bound(monkeypatch) -> None:
    monkeypatch.setattr(cleanup_module.time, "monotonic_ns", lambda: 1)
    monkeypatch.setattr(cleanup_module.time, "sleep", lambda _seconds: None)
    transport = _Transport(
        [_inspect(running=False), _raw(204)] + [_inspect(running=False) for _ in range(64)]
    )
    with pytest.raises(LinuxExecSupervisorDockerError, match="absence_unverified") as raised:
        _cleanup(transport).cleanup(
            IDENTITY, deadline_monotonic_ns=DEADLINE, cancellation=_cancellation()
        )
    assert len(transport.requests) == 66
    assert raised.value.cleanup_uncertain is True
    assert raised.value.effect_may_have_occurred is True
