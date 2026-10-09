"""Scoped AD transport adapters over the existing mTLS/task-ledger protocol.

Constructing the server is an explicit effect and is never done by discovery.
This increment admits authenticated health, inventory and original-task control
only. Execute is closed until the fixed AD native/secret admission is connected;
a general Rust runner or a caller-supplied callback cannot enable it.
"""

from __future__ import annotations

import socket
import threading
from pathlib import Path
from typing import Any, Mapping

from .ad_smb_channel import AdSmbHostChannel
from .ad_smb_channel_trust import load_channel_enrollment
from .ad_smb_contract import AdSmbError, AdSmbScope
from .runner_client import SubprocessRustRunner
from .runner_transport import (
    AuthenticatedRunnerClient,
    AuthenticatedRunnerServer,
    _EnrollmentCache,
    _RequestRefusal,
)
from .runner_transport_errors import RunnerAuthenticationError
from .runner_trust import RunnerEnrollment, RunnerTrustError
from .secret_store import SecretProvider
from .util import content_hash

_CONTROL = frozenset({"health", "inventory", "recover", "cancel"})
_TRANSPORT = "mutual-tls-ad-enrolled-host"


def _current(channel: AdSmbHostChannel) -> None:
    try:
        channel.assert_current()
    except AdSmbError:
        raise RunnerAuthenticationError("AD host channel is not currently valid.") from None


class _ChannelEnrollmentCache(_EnrollmentCache):
    def __init__(
        self, root: Path, channel: AdSmbHostChannel, side: str, provider: SecretProvider | None
    ) -> None:
        self.root = root
        self.channel = channel
        self.side = side
        self.secret_provider = provider

    def active(self) -> RunnerEnrollment:
        # Unlike cached local enrollment, each call checks the finite channel
        # expiry and all role files, including revocation and replaced material.
        try:
            return load_channel_enrollment(
                self.root,
                channel=self.channel,
                side=self.side,
                secret_provider=self.secret_provider,
            )
        except RunnerTrustError:
            raise RunnerAuthenticationError(
                "AD host enrollment is unavailable or inactive."
            ) from None


def _channel(scope: AdSmbScope, channel: AdSmbHostChannel) -> AdSmbHostChannel:
    checked = AdSmbHostChannel.from_mapping(scope, channel.to_dict())
    checked.assert_current()
    return checked


class EnrolledAdSmbClient(AuthenticatedRunnerClient):
    """Connect only to the saved literal endpoint using own-role credentials."""

    _transport_kind = _TRANSPORT
    ad_smb_execution_available = False

    def __init__(
        self,
        enrollment_root: str | Path,
        *,
        scope: AdSmbScope,
        channel: AdSmbHostChannel,
        secret_provider: SecretProvider | None = None,
    ) -> None:
        self.channel = _channel(scope, channel)
        row = self.channel.to_dict()
        super().__init__(
            enrollment_root,
            profile_id=row["profile_id"],
            host=row["host_ipv4"],
            port=row["port"],
            socket_timeout_seconds=10.0,
            max_frame_bytes=4 * 1024 * 1024,
            recovery_attempts=3,
            recovery_delay_seconds=0.05,
            secret_provider=secret_provider,
        )
        self._active_enrollment()

    def _checked_host(self, value: str) -> str:
        return self.channel.address(value)

    def _enrollment_cache(self, root: Path, provider: SecretProvider | None) -> _EnrollmentCache:
        return _ChannelEnrollmentCache(root, self.channel, "client", provider)

    def _connect_socket(self) -> socket.socket:
        _current(self.channel)
        row = self.channel.to_dict()
        if self.host != row["host_ipv4"] or self.port != row["port"]:
            raise RunnerAuthenticationError("AD channel destination changed.")
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection.settimeout(self.socket_timeout_seconds)
            connection.bind((row["controller_ipv4"], 0))
            connection.connect((row["host_ipv4"], row["port"]))
            if (
                connection.getpeername()[:2] != (row["host_ipv4"], row["port"])
                or connection.getsockname()[0] != row["controller_ipv4"]
            ):
                raise RunnerAuthenticationError("AD channel socket binding changed.")
            return connection
        except BaseException:
            connection.close()
            raise

    def _call(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        task_id: str,
        request_hash: str | None = None,
        abort_event: threading.Event | None = None,
    ) -> Mapping[str, Any]:
        if operation not in _CONTROL:
            raise RunnerAuthenticationError("AD native dispatch admission is not available.")
        _current(self.channel)
        return super()._call(
            operation, payload, task_id=task_id, request_hash=request_hash, abort_event=abort_event
        )

    def transport_identity(self) -> Mapping[str, Any]:
        identity = dict(super().transport_identity())
        row = self.channel.to_dict()
        if any(
            identity[field] != row[field] for field in ("runner_binary_digest", "inventory_digest")
        ):
            raise RunnerAuthenticationError("AD host implementation binding changed.")
        return {
            **identity,
            "channel_digest": self.channel.digest,
            "host_id": row["host_id"],
            "host_role": row["role"],
            "profile_digest": row["profile_digest"],
            "ad_smb_execution_available": False,
        }


class EnrolledAdSmbServer(AuthenticatedRunnerServer):
    """Explicit member/client listener with the unchanged durable receiver ledger."""

    _transport_kind = _TRANSPORT
    ad_smb_execution_available = False

    def __init__(
        self,
        enrollment_root: str | Path,
        runner: SubprocessRustRunner,
        *,
        state_path: str | Path,
        scope: AdSmbScope,
        channel: AdSmbHostChannel,
        secret_provider: SecretProvider | None = None,
    ) -> None:
        self.channel = _channel(scope, channel)
        row = self.channel.to_dict()
        timeout = getattr(runner, "timeout_seconds", None)
        if (
            type(runner) is not SubprocessRustRunner
            or isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 < timeout <= scope.to_dict()["limits"]["operation_seconds"]
        ):
            raise RunnerAuthenticationError("AD host requires the bounded native supervisor.")
        super().__init__(
            enrollment_root,
            runner,
            state_path=state_path,
            host=row["host_ipv4"],
            port=row["port"],
            socket_timeout_seconds=10.0,
            max_workers=4,
            control_worker_reserve=2,
            secret_provider=secret_provider,
        )

    def _checked_host(self, value: str) -> str:
        return self.channel.address(value)

    def _enrollment_cache(self, root: Path, provider: SecretProvider | None) -> _EnrollmentCache:
        return _ChannelEnrollmentCache(root, self.channel, "server", provider)

    def _validate_raw_peer(self, connection: socket.socket) -> None:
        _current(self.channel)
        row = self.channel.to_dict()
        if connection.getpeername()[0] != row["controller_ipv4"] or connection.getsockname()[
            :2
        ] != (row["host_ipv4"], row["port"]):
            raise RunnerAuthenticationError("AD channel peer address is not enrolled.")

    def _validated_request(
        self, request: Mapping[str, Any], enrollment: RunnerEnrollment
    ) -> dict[str, Any]:
        checked = super()._validated_request(request, enrollment)
        if checked["operation"] not in _CONTROL:
            raise _RequestRefusal("request_invalid")
        _current(self.channel)
        return checked

    def _verified_runner_binary_digest(self) -> str | None:
        value = super()._verified_runner_binary_digest()
        if value != self.channel.to_dict()["runner_binary_digest"]:
            raise RunnerAuthenticationError("AD host native identity changed.")
        return value

    def _bind_runner_binary(self) -> tuple[Path | None, str | None]:
        binary, value = super()._bind_runner_binary()
        if binary is None or value != self.channel.to_dict()["runner_binary_digest"]:
            raise RunnerAuthenticationError("AD host native identity does not match enrollment.")
        return binary, value

    def _validated_inventory(
        self, enrollment: RunnerEnrollment
    ) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        inventory, canonical = super()._validated_inventory(enrollment)
        if content_hash(canonical) != self.channel.to_dict()["inventory_digest"]:
            raise RunnerAuthenticationError("AD host inventory identity changed.")
        return inventory, canonical
