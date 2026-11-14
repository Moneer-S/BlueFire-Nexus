"""Fixed Docker cleanup grammar for the external exec lifetime supervisor.

This module is intentionally not a general Docker client.  Its public surface
accepts an already-admitted daemon endpoint, an exact container identity, an
absolute deadline, and a cancellation signal.  It constructs the only Docker
requests it can emit: inspect, bounded stop, force-remove, and a final inspect
that must establish daemon-reported absence.  Callers cannot provide methods,
paths, headers, bodies, or raw request bytes.

The successful result is suitable as one input to the supervisor's durable
terminal receipt.  Any failure leaves cleanup uncertain because absence was
not independently established; a caller must retain that state and reconcile
instead of publishing success.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from threading import Event
from typing import Any, Mapping, Protocol

from .engine_docker_proxy import DockerDaemonExchange, DockerProxyCancellation
from .engine_docker_transport import (
    DockerDaemonTransportError,
    LinuxDockerDaemonEndpoint,
    LinuxUnixDockerDaemonTransport,
)
from .util import content_hash

_CONTAINER = re.compile(r"[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"engine-attempt-[0-9a-f]{32}\Z")
_API_VERSION = re.compile(r"v1\.([0-9]{2})\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTAINER_NAME = re.compile(r"strix-sandbox-[a-z0-9][a-z0-9_.-]{0,62}\Z")
_LABEL_KEY = re.compile(r"[a-z0-9][a-z0-9_.-]{0,127}\Z")
_MAX_RESPONSE_BYTES = 256 * 1024
_MAX_INSPECT_ATTEMPTS = 64
_SUPPORTED_API_VERSION = "v1.43"
_CONSTRUCTION_TOKEN = object()
_RESULT_TOKEN = object()


class LinuxExecSupervisorDockerError(RuntimeError):
    """A bounded cleanup failure that never includes endpoint or response data."""

    def __init__(
        self,
        code: str,
        *,
        cleanup_uncertain: bool = True,
        effect_may_have_occurred: bool = False,
    ) -> None:
        super().__init__(f"exec supervisor Docker cleanup {code}")
        self.code = code
        self.cleanup_uncertain = cleanup_uncertain
        self.effect_may_have_occurred = effect_may_have_occurred


class _Transport(Protocol):
    def exchange(
        self,
        raw_request: bytes,
        *,
        deadline_monotonic_ns: int,
        cancellation: DockerProxyCancellation,
        response_byte_limit: int | None = None,
    ) -> DockerDaemonExchange: ...


class ControllerOwnedDockerCleanupCancellation:
    """A cleanup-specific signal, separate from operation cancellation."""

    def __init__(self) -> None:
        self._event = Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()


@dataclass(frozen=True, slots=True)
class SupervisorDockerContainerIdentity:
    """Immutable reviewed identity that must match before destructive cleanup."""

    container_id: str
    container_name: str
    image_config_digest: str
    image_reference: str
    required_labels: tuple[tuple[str, str], ...]
    policy_digest: str
    execution_identity_digest: str
    profile_digest: str

    def __post_init__(self) -> None:
        if (
            _CONTAINER.fullmatch(self.container_id) is None
            or _CONTAINER_NAME.fullmatch(self.container_name) is None
            or _DIGEST.fullmatch(self.image_config_digest) is None
            or _DIGEST.fullmatch(self.policy_digest) is None
            or _DIGEST.fullmatch(self.execution_identity_digest) is None
            or _DIGEST.fullmatch(self.profile_digest) is None
            or not isinstance(self.image_reference, str)
            or not 1 <= len(self.image_reference) <= 327
            or any(
                ord(character) < 0x21 or ord(character) == 0x7F
                for character in self.image_reference
            )
            or "@sha256:" not in self.image_reference
        ):
            raise LinuxExecSupervisorDockerError(
                "container_identity_invalid", cleanup_uncertain=False
            )
        labels: list[tuple[str, str]] = []
        if not isinstance(self.required_labels, tuple) or not 4 <= len(self.required_labels) <= 32:
            raise LinuxExecSupervisorDockerError(
                "container_labels_invalid", cleanup_uncertain=False
            )
        for item in self.required_labels:
            if (
                not isinstance(item, tuple)
                or len(item) != 2
                or not isinstance(item[0], str)
                or _LABEL_KEY.fullmatch(item[0]) is None
                or not isinstance(item[1], str)
                or not item[1]
                or len(item[1]) > 200
                or any(ord(character) < 0x20 or ord(character) == 0x7F for character in item[1])
            ):
                raise LinuxExecSupervisorDockerError(
                    "container_labels_invalid", cleanup_uncertain=False
                )
            labels.append(item)
        if tuple(sorted(set(labels))) != self.required_labels:
            raise LinuxExecSupervisorDockerError(
                "container_labels_invalid", cleanup_uncertain=False
            )
        admitted = dict(labels)
        attempt = admitted.get("bluefire.engine.attempt")
        image_identity = admitted.get("bluefire.engine.image-identity")
        if (
            not isinstance(attempt, str)
            or _ATTEMPT.fullmatch(attempt) is None
            or admitted.get("strix-run-id") != attempt
            or admitted.get("strix-run-type") != "bluefire"
            or not isinstance(image_identity, str)
            or _DIGEST.fullmatch(image_identity) is None
        ):
            raise LinuxExecSupervisorDockerError(
                "container_labels_unbound", cleanup_uncertain=False
            )
        # Policy, execution, and profile digests remain controller-bound fields
        # of this identity. Policy digest cannot itself be a required Docker
        # label because the policy digest includes the admitted label set.

    @property
    def identity_digest(self) -> str:
        return content_hash(
            {
                "schema_version": "bluefire.exec-supervisor-container-identity.v1",
                "container_id": self.container_id,
                "container_name": self.container_name,
                "image_config_digest": self.image_config_digest,
                "image_reference": self.image_reference,
                "required_labels": dict(self.required_labels),
                "policy_digest": self.policy_digest,
                "execution_identity_digest": self.execution_identity_digest,
                "profile_digest": self.profile_digest,
            }
        )


@dataclass(frozen=True, slots=True, init=False)
class SupervisorDockerCleanupResult:
    """Verified absence after the fixed cleanup sequence."""

    container_id: str
    container_identity_digest: str
    daemon_instance_digest: str
    request_digests: tuple[str, ...]
    response_digests: tuple[str, ...]
    final_inventory_digest: str
    stop_sent: bool
    remove_sent: bool
    test_provider: bool
    live_daemon_proof: bool
    absent_verified: bool = True
    cleanup_uncertain: bool = False

    def __init__(
        self,
        *,
        container_id: str,
        container_identity_digest: str,
        daemon_instance_digest: str,
        request_digests: tuple[str, ...],
        response_digests: tuple[str, ...],
        final_inventory_digest: str,
        stop_sent: bool,
        remove_sent: bool,
        test_provider: bool,
        live_daemon_proof: bool,
        _token: object,
    ) -> None:
        if _token is not _RESULT_TOKEN:
            raise LinuxExecSupervisorDockerError("result_construction_refused")
        object.__setattr__(self, "container_id", container_id)
        object.__setattr__(self, "container_identity_digest", container_identity_digest)
        object.__setattr__(self, "daemon_instance_digest", daemon_instance_digest)
        object.__setattr__(self, "request_digests", request_digests)
        object.__setattr__(self, "response_digests", response_digests)
        object.__setattr__(self, "final_inventory_digest", final_inventory_digest)
        object.__setattr__(self, "stop_sent", stop_sent)
        object.__setattr__(self, "remove_sent", remove_sent)
        object.__setattr__(self, "test_provider", test_provider)
        object.__setattr__(self, "live_daemon_proof", live_daemon_proof)
        object.__setattr__(self, "absent_verified", True)
        object.__setattr__(self, "cleanup_uncertain", False)
        self.__post_init__()

    def __post_init__(self) -> None:
        if _CONTAINER.fullmatch(self.container_id) is None:
            raise LinuxExecSupervisorDockerError("result_identity_invalid")
        if _DIGEST.fullmatch(self.container_identity_digest) is None:
            raise LinuxExecSupervisorDockerError("result_identity_invalid")
        if _DIGEST.fullmatch(self.daemon_instance_digest) is None:
            raise LinuxExecSupervisorDockerError("result_daemon_invalid")
        if (
            not isinstance(self.request_digests, tuple)
            or not 1 <= len(self.request_digests) <= _MAX_INSPECT_ATTEMPTS + 3
            or len(self.request_digests) != len(self.response_digests)
            or any(_DIGEST.fullmatch(item) is None for item in self.request_digests)
            or any(_DIGEST.fullmatch(item) is None for item in self.response_digests)
            or _DIGEST.fullmatch(self.final_inventory_digest) is None
            or type(self.stop_sent) is not bool
            or type(self.remove_sent) is not bool
            or type(self.test_provider) is not bool
            or type(self.live_daemon_proof) is not bool
            or self.live_daemon_proof is self.test_provider
            or self.absent_verified is not True
            or self.cleanup_uncertain is not False
        ):
            raise LinuxExecSupervisorDockerError("result_invalid")


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    headers: Mapping[str, str]
    body: bytes
    digest: str


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _parse_response(raw: bytes) -> _Response:
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_RESPONSE_BYTES:
        raise LinuxExecSupervisorDockerError("response_bound")
    marker = raw.find(b"\r\n\r\n")
    if marker < 0 or marker > 32 * 1024:
        raise LinuxExecSupervisorDockerError("response_framing")
    head, body = raw[:marker], raw[marker + 4 :]
    lines = head.split(b"\r\n")
    if not lines or not re.fullmatch(rb"HTTP/1\.1 [1-5][0-9]{2}(?: [\x20-\x7e]{0,64})?", lines[0]):
        raise LinuxExecSupervisorDockerError("response_framing")
    status = int(lines[0].split(b" ", 2)[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            raise LinuxExecSupervisorDockerError("response_framing")
        raw_name, raw_value = line.split(b":", 1)
        try:
            name = raw_name.decode("ascii").lower()
            value = raw_value.decode("ascii").strip(" \t")
        except UnicodeDecodeError as exc:
            raise LinuxExecSupervisorDockerError("response_framing") from exc
        if (
            not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]{1,64}", name)
            or name in headers
            or not value
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise LinuxExecSupervisorDockerError("response_framing")
        headers[name] = value
    if set(headers) & {"connection", "trailer", "transfer-encoding", "upgrade"}:
        raise LinuxExecSupervisorDockerError("response_framing")
    length = headers.get("content-length")
    if status == 204:
        if body or length not in {None, "0"}:
            raise LinuxExecSupervisorDockerError("response_framing")
    else:
        if (
            length is None
            or not length.isdigit()
            or len(length) > 20
            or str(int(length)) != length
            or int(length) != len(body)
        ):
            raise LinuxExecSupervisorDockerError("response_framing")
    return _Response(status=status, headers=headers, body=body, digest=_sha256(raw))


def _json_object(body: bytes) -> Mapping[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise LinuxExecSupervisorDockerError("inspect_json")
            result[key] = value
        return result

    try:
        value = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                LinuxExecSupervisorDockerError("inspect_json")
            ),
        )
    except LinuxExecSupervisorDockerError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LinuxExecSupervisorDockerError("inspect_json") from exc
    if not isinstance(value, dict):
        raise LinuxExecSupervisorDockerError("inspect_json")
    return value


class FixedDockerExecCleanup:
    """Controller-owned, identity-pinned cleanup with no general request API."""

    def __init__(
        self,
        endpoint: LinuxDockerDaemonEndpoint,
        *,
        api_version: str,
        stop_timeout_seconds: int = 5,
        inspect_poll_seconds: float = 0.05,
        transport: _Transport | None = None,
        test_provider: bool,
        _token: object,
    ) -> None:
        if _token is not _CONSTRUCTION_TOKEN:
            raise LinuxExecSupervisorDockerError("construction_refused", cleanup_uncertain=False)
        if not isinstance(endpoint, LinuxDockerDaemonEndpoint):
            raise LinuxExecSupervisorDockerError("endpoint_invalid", cleanup_uncertain=False)
        match = _API_VERSION.fullmatch(api_version) if isinstance(api_version, str) else None
        if (
            match is None
            or not 24 <= int(match.group(1)) <= 99
            or api_version != _SUPPORTED_API_VERSION
        ):
            raise LinuxExecSupervisorDockerError("api_version_invalid", cleanup_uncertain=False)
        if (
            isinstance(stop_timeout_seconds, bool)
            or not isinstance(stop_timeout_seconds, int)
            or not 0 <= stop_timeout_seconds <= 10
        ):
            raise LinuxExecSupervisorDockerError("stop_timeout_invalid", cleanup_uncertain=False)
        if (
            isinstance(inspect_poll_seconds, bool)
            or not isinstance(inspect_poll_seconds, (int, float))
            or not math.isfinite(inspect_poll_seconds)
            or not 0.01 <= inspect_poll_seconds <= 0.25
        ):
            raise LinuxExecSupervisorDockerError("poll_interval_invalid", cleanup_uncertain=False)
        self._endpoint = endpoint
        self._api_version = api_version
        self._stop_timeout = stop_timeout_seconds
        self._poll = float(inspect_poll_seconds)
        if type(test_provider) is not bool or test_provider != (transport is not None):
            raise LinuxExecSupervisorDockerError("transport_mode_invalid", cleanup_uncertain=False)
        self._test_provider = test_provider
        self._transport: _Transport = transport or LinuxUnixDockerDaemonTransport(
            endpoint,
            response_byte_limit=_MAX_RESPONSE_BYTES,
            wire_byte_limit=2 * _MAX_RESPONSE_BYTES,
        )

    @classmethod
    def open(
        cls,
        endpoint: LinuxDockerDaemonEndpoint,
        *,
        api_version: str,
        stop_timeout_seconds: int = 5,
        inspect_poll_seconds: float = 0.05,
    ) -> FixedDockerExecCleanup:
        """Open the live path with the one concrete protected transport."""

        return cls(
            endpoint,
            api_version=api_version,
            stop_timeout_seconds=stop_timeout_seconds,
            inspect_poll_seconds=inspect_poll_seconds,
            transport=None,
            test_provider=False,
            _token=_CONSTRUCTION_TOKEN,
        )

    @classmethod
    def _for_test(
        cls,
        endpoint: LinuxDockerDaemonEndpoint,
        *,
        transport: _Transport,
        api_version: str = _SUPPORTED_API_VERSION,
        stop_timeout_seconds: int = 5,
        inspect_poll_seconds: float = 0.05,
    ) -> FixedDockerExecCleanup:
        """Explicit test-provider path; results cannot claim live daemon proof."""

        return cls(
            endpoint,
            api_version=api_version,
            stop_timeout_seconds=stop_timeout_seconds,
            inspect_poll_seconds=inspect_poll_seconds,
            transport=transport,
            test_provider=True,
            _token=_CONSTRUCTION_TOKEN,
        )

    def cleanup(
        self,
        identity: SupervisorDockerContainerIdentity,
        *,
        deadline_monotonic_ns: int,
        cancellation: ControllerOwnedDockerCleanupCancellation,
    ) -> SupervisorDockerCleanupResult:
        """Stop/remove one exact container and independently establish 404 absence."""

        if type(identity) is not SupervisorDockerContainerIdentity:
            raise LinuxExecSupervisorDockerError(
                "container_identity_invalid", cleanup_uncertain=False
            )
        container_id = identity.container_id
        if (
            isinstance(deadline_monotonic_ns, bool)
            or not isinstance(deadline_monotonic_ns, int)
            or deadline_monotonic_ns <= 0
        ):
            raise LinuxExecSupervisorDockerError("deadline_invalid", cleanup_uncertain=False)
        if type(cancellation) is not ControllerOwnedDockerCleanupCancellation:
            raise LinuxExecSupervisorDockerError(
                "cleanup_cancellation_invalid", cleanup_uncertain=False
            )
        requests: list[str] = []
        responses: list[str] = []
        stop_sent = False
        remove_sent = False
        effect_may_have_occurred = False

        def exchange(method: str, target: str) -> _Response:
            nonlocal effect_may_have_occurred
            self._check(deadline_monotonic_ns, cancellation)
            request = self._request(method, target)
            request_digest = _sha256(request)
            if method in {"POST", "DELETE"}:
                effect_may_have_occurred = True
            try:
                result = self._transport.exchange(
                    request,
                    deadline_monotonic_ns=deadline_monotonic_ns,
                    cancellation=cancellation,
                    response_byte_limit=_MAX_RESPONSE_BYTES,
                )
            except DockerDaemonTransportError as exc:
                raise LinuxExecSupervisorDockerError(
                    "transport_failed",
                    effect_may_have_occurred=(
                        effect_may_have_occurred or exc.request_may_have_been_sent
                    ),
                ) from exc
            except Exception as exc:
                raise LinuxExecSupervisorDockerError(
                    "transport_failed", effect_may_have_occurred=effect_may_have_occurred
                ) from exc
            if (
                not isinstance(result, DockerDaemonExchange)
                or result.request_digest != request_digest
                or result.daemon_instance_digest != self._endpoint.daemon_instance_digest
            ):
                raise LinuxExecSupervisorDockerError(
                    "exchange_binding", effect_may_have_occurred=effect_may_have_occurred
                )
            response = _parse_response(result.raw_response)
            self._check(deadline_monotonic_ns, cancellation)
            requests.append(request_digest)
            responses.append(response.digest)
            return response

        inspect_target = f"/{self._api_version}/containers/{container_id}/json"
        first = exchange("GET", inspect_target)
        if self._is_absent(first, container_id):
            self._check(deadline_monotonic_ns, cancellation)
            return self._result(identity, requests, responses, stop_sent=False, remove_sent=False)
        running = self._validate_inspect(first, identity)
        if running:
            stop_target = (
                f"/{self._api_version}/containers/{container_id}/stop?t={self._stop_timeout}"
            )
            stopped = exchange("POST", stop_target)
            stop_sent = True
            if stopped.status != 204:
                raise LinuxExecSupervisorDockerError("stop_refused", effect_may_have_occurred=True)
        remove_target = f"/{self._api_version}/containers/{container_id}?force=1&v=1"
        removed = exchange("DELETE", remove_target)
        remove_sent = True
        if removed.status not in {204, 404}:
            raise LinuxExecSupervisorDockerError("remove_refused", effect_may_have_occurred=True)

        for attempt in range(_MAX_INSPECT_ATTEMPTS):
            observed = exchange("GET", inspect_target)
            if self._is_absent(observed, container_id):
                self._check(deadline_monotonic_ns, cancellation)
                return self._result(
                    identity,
                    requests,
                    responses,
                    stop_sent=stop_sent,
                    remove_sent=remove_sent,
                )
            self._validate_inspect(observed, identity)
            if attempt + 1 == _MAX_INSPECT_ATTEMPTS:
                break
            remaining = deadline_monotonic_ns - time.monotonic_ns()
            if remaining <= 0:
                break
            time.sleep(min(self._poll, remaining / 1_000_000_000))
        raise LinuxExecSupervisorDockerError("absence_unverified", effect_may_have_occurred=True)

    def _request(self, method: str, target: str) -> bytes:
        # method and target are selected only by cleanup(); this helper is not public.
        headers = f"{method} {target} HTTP/1.1\r\nHost: docker\r\n"
        if method == "GET":
            headers += "Accept: application/json\r\n"
        elif method == "POST":
            headers += "Content-Length: 0\r\n"
        return (headers + "\r\n").encode("ascii")

    @staticmethod
    def _check(deadline: int, cancellation: DockerProxyCancellation) -> None:
        try:
            cancelled = cancellation.is_cancelled()
        except Exception as exc:
            raise LinuxExecSupervisorDockerError("cancellation_unavailable") from exc
        if type(cancelled) is not bool or cancelled:
            raise LinuxExecSupervisorDockerError("cancelled")
        if time.monotonic_ns() >= deadline:
            raise LinuxExecSupervisorDockerError("deadline_elapsed")

    @staticmethod
    def _validate_inspect(response: _Response, identity: SupervisorDockerContainerIdentity) -> bool:
        if response.status != 200:
            raise LinuxExecSupervisorDockerError("inspect_refused")
        if response.headers.get("content-type") != "application/json":
            raise LinuxExecSupervisorDockerError("inspect_content_type")
        value = _json_object(response.body)
        state = value.get("State")
        config = value.get("Config")
        if (
            value.get("Id") != identity.container_id
            or value.get("Name") != "/" + identity.container_name
            or value.get("Image") != identity.image_config_digest
            or not isinstance(state, dict)
            or not isinstance(config, dict)
            or config.get("Image") != identity.image_reference
            or config.get("Labels") != dict(identity.required_labels)
        ):
            raise LinuxExecSupervisorDockerError("inspect_identity")
        running = state.get("Running")
        if type(running) is not bool:
            raise LinuxExecSupervisorDockerError("inspect_state")
        return running

    @staticmethod
    def _is_absent(response: _Response, container_id: str) -> bool:
        if response.status != 404:
            return False
        if response.headers.get("content-type") != "application/json":
            raise LinuxExecSupervisorDockerError("absence_content_type")
        value = _json_object(response.body)
        if (
            set(value) != {"message"}
            or value.get("message") != f"No such container: {container_id}"
        ):
            raise LinuxExecSupervisorDockerError("absence_unqualified")
        return True

    def _result(
        self,
        identity: SupervisorDockerContainerIdentity,
        requests: list[str],
        responses: list[str],
        *,
        stop_sent: bool,
        remove_sent: bool,
    ) -> SupervisorDockerCleanupResult:
        container_id = identity.container_id
        final_inventory_digest = content_hash(
            {
                "schema_version": "bluefire.exec-supervisor-docker-absence.v1",
                "container_id": container_id,
                "container_identity_digest": identity.identity_digest,
                "daemon_instance_digest": self._endpoint.daemon_instance_digest,
                "api_version": self._api_version,
                "final_inspect_request_digest": requests[-1],
                "final_inspect_response_digest": responses[-1],
                "absence_status": 404,
            }
        )
        return SupervisorDockerCleanupResult(
            container_id=container_id,
            container_identity_digest=identity.identity_digest,
            daemon_instance_digest=self._endpoint.daemon_instance_digest,
            request_digests=tuple(requests),
            response_digests=tuple(responses),
            final_inventory_digest=final_inventory_digest,
            stop_sent=stop_sent,
            remove_sent=remove_sent,
            test_provider=self._test_provider,
            live_daemon_proof=not self._test_provider,
            _token=_RESULT_TOKEN,
        )


__all__ = [
    "ControllerOwnedDockerCleanupCancellation",
    "FixedDockerExecCleanup",
    "LinuxExecSupervisorDockerError",
    "SupervisorDockerContainerIdentity",
    "SupervisorDockerCleanupResult",
]
