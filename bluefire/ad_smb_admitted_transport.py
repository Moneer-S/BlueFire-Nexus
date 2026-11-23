"""Explicit finite AD channel admission; not product discovery or enrollment.

Constructing the receiver is effectful. Callers must already own the installed
role bundle, native binary, private work root and literal listener endpoint.
This module never installs them or enables the product's default executor.
"""

from __future__ import annotations

import re
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping

from .ad_smb_channel import AdSmbHostChannel
from .ad_smb_channel_transport import EnrolledAdSmbClient, _channel, _current
from .ad_smb_channel_trust import load_channel_enrollment
from .ad_smb_contract import AdSmbError, AdSmbScope, digest, document, exact
from .ad_smb_credentials import load_credential_binding
from .ad_smb_private_storage import private_root
from .ad_smb_receiver import AdSmbReceiver, _now
from .ad_smb_receiver_results import context, native_generation, stored_result
from .ad_smb_results import ACTION
from .ad_smb_worker_wire import LIMIT_KEYS, RECEIVER_RESULT_MAX, TERMINAL_MAX, prepare_packet
from .runner_client import SubprocessRustRunner
from .runner_contracts import seal_profile
from .runner_transport import AuthenticatedRunnerClient, AuthenticatedRunnerServer, _RequestRefusal
from .runner_transport_errors import (
    RunnerAuthenticationError,
    RunnerConnectionError,
    RunnerTaskCancelled,
    RunnerTaskTimedOut,
)
from .runner_trust import RunnerEnrollment, _PinnedDirectory
from .secret_store import SecretProvider
from .util import canonical_json_bytes

_CONTROL = frozenset({"health", "inventory", "recover", "cancel"})
_ADMISSION_SCHEMA = "bluefire.ad-smb-configured-admission.v1"


def _admission(channel: AdSmbHostChannel, credential_digest: str | None) -> dict[str, Any]:
    row = channel.to_dict()
    if (row["role"] == "client") != (credential_digest is not None):
        raise AdSmbError("AD configured reader binding is missing or misplaced.")
    if credential_digest is not None:
        digest(credential_digest)
    return {
        "schema_version": _ADMISSION_SCHEMA,
        "scope_digest": row["scope_digest"],
        "channel_digest": channel.digest,
        "profile_digest": row["profile_digest"],
        "host_role": row["role"],
        "credential_binding_digest": credential_digest,
        "native_generation": native_generation(channel),
        "readiness_scope": "configuration_only",
    }


def _profile(scope: AdSmbScope, channel: AdSmbHostChannel, value: Mapping[str, Any]) -> bytes:
    row = document(value)
    exact(
        row,
        {
            "schema_version",
            "profile_id",
            "runner_id",
            "platform",
            "sandbox_root",
            "allowed_actions",
            "control_blocked_actions",
            "capabilities",
            "max_safety_tier",
            "approval_required_at_or_above",
            "target_scope",
            "limits",
            "policy_digest",
        },
        "Admitted AD profile",
    )
    bound = channel.to_dict()
    if (
        row != seal_profile(row)
        or row["profile_id"] != bound["profile_id"]
        or row["policy_digest"] != bound["profile_digest"]
        or row["runner_id"] != bound["runner_id"]
        or row["runner_id"] != "bluefire-rust-runner.v1"
        or row["platform"] != "windows"
        or row["allowed_actions"] != [ACTION]
        or row["control_blocked_actions"] != []
        or row["capabilities"] != ["ad_smb_access"]
        or row["max_safety_tier"] != "controlled"
        or row["approval_required_at_or_above"] != "safe"
        or row["target_scope"] != {"filesystem": [], "network": []}
    ):
        raise AdSmbError("Admitted AD profile differs from the fixed native recipe.")
    limits = scope.to_dict()["limits"]
    ceilings = {
        "timeout_ms": limits["operation_seconds"] * 1000,
        "max_stdout_bytes": TERMINAL_MAX,
        "max_stderr_bytes": 65536,
        "max_artifact_bytes": limits["returned_payload_bytes"],
        "max_files": 2,
    }
    exact(row["limits"], LIMIT_KEYS, "Admitted AD profile limits")
    if any(
        type(row["limits"][key]) is not int or not 0 < row["limits"][key] <= ceiling
        for key, ceiling in ceilings.items()
    ):
        raise AdSmbError("Admitted AD profile exceeds its finite limits.")
    return canonical_json_bytes(row)


def _original(
    profile_bytes: bytes,
    channel: AdSmbHostChannel,
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    current: bool,
) -> dict[str, Any]:
    original = context(manifest, profile)
    step = original["manifest"]["params"]["ad_smb_request"]
    if canonical_json_bytes(profile) != profile_bytes or step["host"][
        "native_generation"
    ] != native_generation(channel):
        raise AdSmbError("AD original profile or native generation changed.")
    if current:
        reading = channel.to_dict()["role"] == "client"
        prepare_packet(
            original,
            channel,
            challenge="0" * 64,
            credential_binding_digest=step["principal_binding_digest"] if reading else None,
            expected_upn_sha256="sha256:" + "0" * 64 if reading else None,
            prior_local_authentication_ids=[],
            clock=_now(),
        )
    return original


class AdmittedAdSmbReceiver(AdSmbReceiver):
    """Explicit installed native admission, with the unchanged owned receiver ledger."""

    _ad_profile: bytes
    _ad_credential_digest: str | None
    _ad_credential_root: Path | None
    _ad_scope: AdSmbScope
    _ad_secret_provider: SecretProvider | None

    def __init__(
        self,
        enrollment_root: str | Path,
        runner: SubprocessRustRunner,
        *,
        state_path: str | Path,
        scope: AdSmbScope,
        channel: AdSmbHostChannel,
        profile: Mapping[str, Any],
        credential_root: str | Path | None = None,
        credential_binding_digest: str | None = None,
        secret_provider: SecretProvider | None = None,
    ) -> None:
        constructed = False
        try:
            if sys.platform != "win32" or type(runner) is not SubprocessRustRunner:
                raise AdSmbError("AD native receiver requires the installed Windows runner.")
            self.channel = _channel(scope, channel)
            self._ad_profile = _profile(scope, self.channel, profile)
            timeout, output = runner.timeout_seconds, runner.output_limit_bytes
            if (
                type(timeout) not in {int, float}
                or not 0 < timeout <= scope.to_dict()["limits"]["operation_seconds"]
                or type(output) is not int
                or not 1 <= output <= 4 * 1024 * 1024
            ):
                raise AdSmbError("AD inventory supervisor exceeds its finite bounds.")
            root = private_root(Path(profile["sandbox_root"]))
            if (
                not isinstance(runner.work_root, Path)
                or runner.work_root.resolve(strict=True) != root
            ):
                raise AdSmbError("AD runner work root differs from its exact profile.")
            reading = self.channel.to_dict()["role"] == "client"
            if reading != (credential_root is not None) or reading != (
                credential_binding_digest is not None
            ):
                raise AdSmbError("AD reader material is required only on the client host.")
            self._ad_credential_digest = digest(credential_binding_digest) if reading else None
            self._ad_credential_root = (
                Path(credential_root) if credential_root is not None else None
            )
            self._ad_scope = scope
            self._ad_secret_provider = secret_provider
            self._ad_credentials = (
                load_credential_binding(
                    Path(credential_root),
                    scope=scope,
                    channel=self.channel,
                    expected_digest=digest(self._ad_credential_digest),
                    secret_provider=secret_provider,
                )
                if credential_root is not None
                else None
            )
            enrollment = load_channel_enrollment(
                Path(enrollment_root),
                channel=self.channel,
                side="server",
                secret_provider=secret_provider,
            )
            # These are the same fields used by the inherited identity guard;
            # no listener, ledger or alternate process is initialized here.
            self.runner = runner
            self._runner_binary, self._runner_binary_digest = self._bind_runner_binary()
            with (
                _PinnedDirectory(root, private=True, verify_permissions_only=True),
                self._verified_runner_binary_guard(),
            ):
                inventory, _ = self._validated_inventory(enrollment)
                if inventory.get("platform") != "windows":
                    raise AdSmbError("AD inventory is not the fixed Windows implementation.")
                super().__init__(
                    enrollment_root,
                    runner,
                    state_path=state_path,
                    scope=scope,
                    channel=self.channel,
                    secret_provider=secret_provider,
                )
                constructed = True
        except BaseException:
            if constructed:
                try:
                    AuthenticatedRunnerServer.shutdown(self)
                    if self._listener.fileno() != -1 or self._ledger_lock is not None:
                        raise RuntimeError("owned construction cleanup unknown")
                except BaseException:
                    raise RunnerAuthenticationError(
                        "AD receiver construction failed; owned cleanup is unverified."
                    ) from None
            raise RunnerAuthenticationError(
                "AD receiver admission is unavailable or changed."
            ) from None

    def _context(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> dict[str, Any]:
        original = super()._context(manifest, profile)
        if canonical_json_bytes(profile) != self._ad_profile:
            raise AdSmbError("AD receiver original profile differs from construction.")
        if (
            self.channel.to_dict()["role"] == "client"
            and original["manifest"]["params"]["ad_smb_request"]["principal_binding_digest"]
            != self._ad_credential_digest
        ):
            raise AdSmbError("AD original reader binding differs from construction.")
        return original

    def _success_response(
        self, request: Mapping[str, Any], enrollment: RunnerEnrollment, payload: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        if request["operation"] == "health":
            _current(self.channel)
            if self._ad_credential_root is not None:
                load_credential_binding(
                    self._ad_credential_root,
                    scope=self._ad_scope,
                    channel=self.channel,
                    expected_digest=digest(self._ad_credential_digest),
                    secret_provider=self._ad_secret_provider,
                )
            payload = {
                **payload,
                "ad_smb_admission": _admission(self.channel, self._ad_credential_digest),
            }
        return super()._success_response(request, enrollment, payload)

    def _validated_request(
        self, request: Mapping[str, Any], enrollment: RunnerEnrollment
    ) -> dict[str, Any]:
        checked = AuthenticatedRunnerServer._validated_request(self, request, enrollment)
        _current(self.channel)
        if checked["operation"] in _CONTROL:
            return checked
        if checked["operation"] != "execute":
            raise _RequestRefusal("request_invalid")
        try:
            supplied = self._require_payload(checked, frozenset({"manifest", "profile"}))
            self._context(supplied["manifest"], supplied["profile"])
        except (AdSmbError, KeyError, TypeError):
            raise _RequestRefusal("request_invalid") from None
        return checked


class AdmittedAdSmbClient(EnrolledAdSmbClient):
    """Exact AD Execute and original-only recovery, without automatic redispatch."""

    def __init__(
        self,
        enrollment_root: str | Path,
        *,
        scope: AdSmbScope,
        channel: AdSmbHostChannel,
        profile: Mapping[str, Any],
        credential_binding_digest: str | None = None,
        secret_provider: SecretProvider | None = None,
    ) -> None:
        try:
            self.channel = _channel(scope, channel)
            self._ad_profile = _profile(scope, self.channel, profile)
            self._ad_expected_admission = _admission(self.channel, credential_binding_digest)
            super().__init__(
                enrollment_root, scope=scope, channel=self.channel, secret_provider=secret_provider
            )
        except (AdSmbError, KeyError, TypeError, ValueError):
            raise RunnerAuthenticationError(
                "AD client admission is unavailable or changed."
            ) from None

    def health(self) -> Mapping[str, Any]:
        row = document(super().health(), limit=65536)
        exact(
            row,
            {
                "schema_version",
                "status",
                "runner_id",
                "client_id",
                "server_instance_id",
                "profile_id",
                "transport",
                "tls",
                "server_fingerprint",
                "client_fingerprint",
                "authenticated_peer_fingerprint",
                "enrollment_generation",
                "runner_binary_digest",
                "inventory_digest",
                "execution_timeout_seconds",
                "ledger",
                "ad_smb_admission",
            },
            "AD configured health",
        )
        ledger = row["ledger"]
        numbers = {
            "rows",
            "capacity",
            "execute_rows",
            "execute_capacity",
            "control_reserve",
            "blob_bytes",
            "committed_bytes",
            "byte_capacity",
            "execute_byte_capacity",
            "control_reserve_bytes",
        }
        exact(ledger, numbers | {"generation", "accepting_execute"}, "AD configured ledger")
        digest(ledger["generation"])
        if (
            row["schema_version"] != "bluefire.runner-health.v1"
            or row["status"] != "ready"
            or row["profile_id"] != self.profile_id
            or row["ad_smb_admission"] != self._ad_expected_admission
            or ledger["accepting_execute"] is not True
            or any(type(ledger[key]) is not int or not 0 <= ledger[key] < 2**63 for key in numbers)
            or type(row["execution_timeout_seconds"]) not in {int, float}
            or not 0 < row["execution_timeout_seconds"] <= 60
        ):
            raise RunnerAuthenticationError("AD configured admission is unavailable or changed.")
        return row

    def transport_identity(self) -> Mapping[str, Any]:
        # The inherited identity check calls the exact signed health validator
        # above. This means configured admission, not observed remote access.
        return {
            **super().transport_identity(),
            "ad_smb_execution_available": True,
            "readiness_scope": "configuration_only",
        }

    def _call(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        task_id: str,
        request_hash: str | None = None,
        abort_event: threading.Event | None = None,
    ) -> Mapping[str, Any]:
        if operation != "execute":
            return super()._call(
                operation,
                payload,
                task_id=task_id,
                request_hash=request_hash,
                abort_event=abort_event,
            )
        try:
            exact(dict(payload), {"manifest", "profile"}, "AD execute payload")
            original = _original(
                self._ad_profile,
                self.channel,
                payload["manifest"],
                payload["profile"],
                current=True,
            )
            if task_id != original["task_id"] or request_hash != original["transport_request_hash"]:
                raise AdSmbError("AD client original task binding changed.")
        except (AdSmbError, KeyError, TypeError):
            raise RunnerAuthenticationError("AD client execute request is invalid.") from None
        return AuthenticatedRunnerClient._call(
            self,
            operation,
            payload,
            task_id=task_id,
            request_hash=request_hash,
            abort_event=abort_event,
        )

    def _checked_result(
        self, value: Mapping[str, Any], manifest: Mapping[str, Any], profile: Mapping[str, Any]
    ) -> dict[str, Any]:
        try:
            _original(self._ad_profile, self.channel, manifest, profile, current=False)
            return stored_result(
                value, manifest, profile, self.channel, maximum=RECEIVER_RESULT_MAX
            )
        except (AdSmbError, KeyError, TypeError):
            raise RunnerAuthenticationError("AD original receiver result is invalid.") from None

    def execute(self, manifest: Mapping[str, Any], profile: Mapping[str, Any]) -> Mapping[str, Any]:
        value = super().execute(manifest, profile)
        return self._checked_result(value, manifest, profile)

    def execute_task(
        self,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        cancel_event: threading.Event,
        durable_result_path: str | Path,
        owned_service_grant: Any = None,
    ) -> Mapping[str, Any]:
        if owned_service_grant is not None:
            raise RunnerAuthenticationError("AD cannot dispatch an ordinary service grant.")
        value = super().execute_task(
            manifest,
            profile,
            task_id=task_id,
            cancel_event=cancel_event,
            durable_result_path=durable_result_path,
        )
        return self._checked_result(value, manifest, profile)

    def recover_original(
        self, manifest: Mapping[str, Any], profile: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        try:
            original = _original(self._ad_profile, self.channel, manifest, profile, current=False)
            response = dict(self.recover(original["task_id"], original["transport_request_hash"]))
            if response.get("state") == "completed":
                response["result"] = self._checked_result(
                    self._recovered_result_payload(response), manifest, profile
                )
            elif response.get("result") is not None:
                raise AdSmbError("Unsettled AD recovery cannot return a completed result.")
            return response
        except (AdSmbError, KeyError, TypeError):
            raise RunnerAuthenticationError("AD original recovery is invalid.") from None

    def recover(self, task_id: str, request_hash: str) -> Mapping[str, Any]:
        try:
            row = document(super().recover(task_id, request_hash), limit=4 * 1024 * 1024)
            exact(
                row,
                {
                    "original_task_id",
                    "original_request_hash",
                    "state",
                    "result",
                    "error_code",
                    "cancellation_requested",
                    "receipt_ids",
                    "cleanup_required",
                },
                "AD recovery response",
            )
            state = row["state"]
            if (
                row["original_task_id"] != task_id
                or row["original_request_hash"] != request_hash
                or state
                not in {
                    "not_found",
                    "running",
                    "completed",
                    "failed",
                    "indeterminate",
                    "recovery_required",
                    "cancelled",
                    "timed_out",
                }
                or type(row["cancellation_requested"]) is not bool
                or type(row["cleanup_required"]) is not bool
                or row["receipt_ids"] != []
                or (state != "completed" and row["result"] is not None)
                or (state == "completed" and not isinstance(row["result"], dict))
                or (
                    row["error_code"] is not None
                    and (
                        not isinstance(row["error_code"], str)
                        or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", row["error_code"]) is None
                    )
                )
                or (
                    state in {"not_found", "running", "completed"} and row["error_code"] is not None
                )
            ):
                raise AdSmbError("AD recovery response differs from its original task.")
            return row
        except (AdSmbError, KeyError, TypeError):
            raise RunnerAuthenticationError("AD original recovery is invalid.") from None

    def _recover_after_connection_loss(
        self, payload: Mapping[str, Any], task_id: str, request_hash: str
    ) -> Mapping[str, Any]:
        for attempt in range(self.recovery_attempts):
            if attempt and self.recovery_delay_seconds:
                time.sleep(self.recovery_delay_seconds)
            try:
                recovered = self.recover(task_id, request_hash)
            except RunnerConnectionError:
                continue
            state = recovered.get("state")
            if state == "completed":
                return self._checked_result(
                    self._recovered_result_payload(recovered),
                    payload["manifest"],
                    payload["profile"],
                )
            if state == "cancelled":
                raise RunnerTaskCancelled("AD owned worker cancellation was recorded.")
            if state == "timed_out":
                raise RunnerTaskTimedOut("AD owned worker timeout was recorded.")
            if state in {"failed", "indeterminate", "recovery_required"}:
                break
        raise RunnerConnectionError(
            "AD original outcome is unavailable; no replacement Execute was sent."
        )
