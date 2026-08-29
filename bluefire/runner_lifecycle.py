"""Managed, authenticated lifecycle for the separately hosted native runner.

Construction is deliberately inert.  Bootstrap, start, stop, revocation, and
removal are explicit operator actions, and a PID or port from disk is never
accepted as evidence that a runner is alive.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import stat
import subprocess  # nosec B404
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence, cast

from . import __version__
from .runner_bootstrap import (
    RUNNER_ID,
    BootstrappedRunner,
    InventoryProbe,
    bootstrap_runner,
)
from .runner_host import (
    LOOPBACK_HOST,
    RunnerHostError,
    default_host_command,
    read_process_record,
)
from .runner_transport import (
    AuthenticatedRunnerClient,
    AuthenticatedRunnerTransportError,
    RunnerAuthenticationError,
    RunnerConnectionError,
    RunnerRemoteError,
    audit_runner_ledger,
    runner_result_namespace_path,
)
from .runner_trust import (
    RunnerEnrollment,
    RunnerTrustError,
    _is_link_or_reparse,
    _owner_private,
    create_local_enrollment,
    enrollment_status,
    load_local_enrollment,
    local_enrollment_creation_path,
    remove_local_enrollment,
    revoke_local_enrollment,
)
from .secret_store import SecretProvider
from .util import canonical_json_bytes, file_hash

LIFECYCLE_STATUS_SCHEMA_VERSION = "bluefire.runner-lifecycle-status.v1"
BOOTSTRAP_RECORD_SCHEMA_VERSION = "bluefire.runner-lifecycle-bootstrap.v1"
ROOT_MARKER_SCHEMA_VERSION = "bluefire.runner-lifecycle-root.v1"
REMOVAL_JOURNAL_SCHEMA_VERSION = "bluefire.runner-enrollment-removal.v1"
BOOTSTRAP_RECORD_MAX_BYTES = 64 * 1024
ROOT_MARKER_MAX_BYTES = 4096
REMOVAL_JOURNAL_MAX_BYTES = 16 * 1024
CLIENT_ID = "bluefire-control-plane.v1"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
# AuthenticatedRunnerServer derives durable result names from the first 160 bits
# of SHA-256(task_id); lifecycle audit and removal must recognize that exact shape.
_DURABLE_RESULT_NAME = re.compile(r"^[0-9a-f]{40}\.json$")
_PENDING_RESULT_NAME = re.compile(r"^\.bluefire-result-[0-9a-f]{64}\.pending$")
_WATCHDOG_DIRECTORY_NAME = re.compile(r"^\.bluefire-watchdog-[0-9a-f]{64}$")
_WATCHDOG_FILES = frozenset({"config.json", "start", "cancel", "ready.json", "status.json"})
_ROOT_MARKER_FIELDS = frozenset({"schema_version", "runner_id", "root_digest", "marker_id"})
_REMOVAL_JOURNAL_FIELDS = frozenset(
    {
        "schema_version",
        "runner_id",
        "client_id",
        "root_digest",
        "tombstone_name",
        "secret_provider",
        "created_at_ns",
        "nonce",
        "authentication",
    }
)
_ENROLLMENT_MATERIAL_NAMES = frozenset(
    {
        "ca-cert.pem",
        "server-cert.pem",
        "server-key.pem",
        "server-key-password.secret",
        "client-cert.pem",
        "client-key.pem",
        "client-key-password.secret",
        "hmac.secret",
        "trust.json",
    }
)
_BOOTSTRAP_FIELDS = frozenset(
    {
        "schema_version",
        "runner_id",
        "source",
        "managed_binary",
        "managed_sandbox",
        "binary_path",
        "sandbox_path",
        "binary_digest",
        "product_version",
        "runner_version",
        "platform",
        "architecture",
        "inventory_schema",
        "action_sdk_version",
        "receipt_protocol",
        "authentication",
    }
)
_UNRESOLVED_EXECUTE_STATES = frozenset({"running", "indeterminate", "recovery_required"})
_LOCAL_OPERATION_LOCKS_GUARD = threading.Lock()
_LOCAL_OPERATION_LOCKS: dict[str, threading.RLock] = {}


class RunnerLifecycleError(RuntimeError):
    """A deliberately path- and secret-free lifecycle refusal."""


@dataclass(frozen=True, slots=True, repr=False)
class RunnerHostSpec:
    enrollment_root: Path
    runner_binary: Path
    work_root: Path
    state_path: Path
    process_record_path: Path
    start_gate_path: Path
    launch_id: str
    runner_timeout_seconds: float

    def __repr__(self) -> str:
        return "RunnerHostSpec(loopback_only=True)"


class HostCommandFactory(Protocol):
    def __call__(self, spec: RunnerHostSpec) -> Sequence[str]: ...


BootstrapFactory = Callable[..., BootstrappedRunner]
ClientFactory = Callable[..., AuthenticatedRunnerClient]
TrustRemoval = Callable[..., None]


@dataclass(frozen=True, slots=True, repr=False)
class _BootstrapRecord:
    binary_path: Path
    sandbox_path: Path
    binary_digest: str
    source: str
    managed_binary: bool
    managed_sandbox: bool
    product_version: str
    runner_version: str
    platform: str
    architecture: str
    inventory_schema: str
    action_sdk_version: str
    receipt_protocol: str

    def __repr__(self) -> str:
        return (
            "_BootstrapRecord(source="
            f"{self.source!r}, platform={self.platform!r}, architecture={self.architecture!r})"
        )


@dataclass(slots=True, repr=False)
class _LaunchProcess:
    process: subprocess.Popen[bytes]
    containment: Any | None = None

    def __repr__(self) -> str:
        return "_LaunchProcess(contained=True)"


class ManagedRunnerLifecycle:
    """Explicit lifecycle coordinator for one local enrolled runner."""

    def __init__(
        self,
        managed_root: str | Path,
        *,
        client_id: str = CLIENT_ID,
        secret_provider: SecretProvider | None = None,
        bootstrap_factory: BootstrapFactory = bootstrap_runner,
        host_command_factory: HostCommandFactory | None = None,
        client_factory: ClientFactory = AuthenticatedRunnerClient,
        trust_removal: TrustRemoval = remove_local_enrollment,
        start_timeout_seconds: float = 15.0,
        stop_timeout_seconds: float = 15.0,
        runner_timeout_seconds: float = 35.0,
    ) -> None:
        root = Path(managed_root).expanduser()
        if (
            not root.is_absolute()
            or any(part in {"", ".", ".."} for part in root.parts[1:])
            or _broad_root(root)
            or _IDENTIFIER.fullmatch(client_id) is None
            or not 0.5 <= start_timeout_seconds <= 120
            or not 0.5 <= stop_timeout_seconds <= 120
            or not 0.1 <= runner_timeout_seconds <= 24 * 60 * 60
        ):
            raise RunnerLifecycleError("Managed runner lifecycle configuration is invalid.")
        self.root = root
        self.runner_id = RUNNER_ID
        self.client_id = client_id
        self.secret_provider = secret_provider
        self.bootstrap_factory = bootstrap_factory
        self.host_command_factory = host_command_factory or _default_command_factory
        self.client_factory = client_factory
        self.trust_removal = trust_removal
        self.start_timeout_seconds = float(start_timeout_seconds)
        self.stop_timeout_seconds = float(stop_timeout_seconds)
        self.runner_timeout_seconds = float(runner_timeout_seconds)
        self._instance_operation_lock = threading.RLock()
        self._owned_processes: dict[str, subprocess.Popen[bytes]] = {}

    @property
    def enrollment_root(self) -> Path:
        return self.root / "enrollment"

    @property
    def enrollment_tombstone_root(self) -> Path:
        return self.root / ".enrollment.removing"

    @property
    def enrollment_staging_root(self) -> Path:
        try:
            return Path(local_enrollment_creation_path(self.enrollment_root))
        except RunnerTrustError:
            raise RunnerLifecycleError("Runner enrollment transition is unavailable.") from None

    @property
    def enrollment_creation_intent_path(self) -> Path:
        return self.enrollment_root.with_name(f".{self.enrollment_root.name}.creation-intent.json")

    @property
    def enrollment_removal_intent_path(self) -> Path:
        return self.enrollment_root.with_name(f".{self.enrollment_root.name}.removal-intent.json")

    @property
    def enrollment_revocation_intent_path(self) -> Path:
        return self.enrollment_root.with_name(
            f".{self.enrollment_root.name}.revocation-intent.json"
        )

    @property
    def enrollment_transition_lock_path(self) -> Path:
        return self.enrollment_root.with_name(f".{self.enrollment_root.name}.transition.lock")

    @property
    def runtime_root(self) -> Path:
        return self.root / "runtime"

    @property
    def control_root(self) -> Path:
        return self.root / "lifecycle"

    @property
    def bootstrap_record_path(self) -> Path:
        return self.control_root / "bootstrap.json"

    @property
    def root_marker_path(self) -> Path:
        return self.root / "lifecycle-root.json"

    @property
    def operation_lock_path(self) -> Path:
        return self.root / "lifecycle-operation.lock"

    @property
    def removal_journal_path(self) -> Path:
        return self.control_root / "removal.json"

    @property
    def removal_secret_path(self) -> Path:
        return self.control_root / "removal.secret"

    @property
    def process_record_path(self) -> Path:
        return self.control_root / "process.json"

    @property
    def ledger_path(self) -> Path:
        return self.control_root / "transport.sqlite3"

    @property
    def ledger_lock_path(self) -> Path:
        return self.ledger_path.with_name(self.ledger_path.name + ".lock")

    def bootstrap(
        self,
        *,
        allowed_profile_ids: Sequence[str],
        environ: Mapping[str, str] | None = None,
        resource_root: Any | None = None,
        product_version: str = __version__,
        platform_name: str | None = None,
        architecture: str | None = None,
        inventory_probe: InventoryProbe | None = None,
        allow_upgrade: bool = False,
    ) -> Mapping[str, Any]:
        with self._operation_guard(adopt=True):
            return self._bootstrap_locked(
                allowed_profile_ids=allowed_profile_ids,
                environ=environ,
                resource_root=resource_root,
                product_version=product_version,
                platform_name=platform_name,
                architecture=architecture,
                inventory_probe=inventory_probe,
                allow_upgrade=allow_upgrade,
            )

    def _bootstrap_locked(
        self,
        *,
        allowed_profile_ids: Sequence[str],
        environ: Mapping[str, str] | None = None,
        resource_root: Any | None = None,
        product_version: str = __version__,
        platform_name: str | None = None,
        architecture: str | None = None,
        inventory_probe: InventoryProbe | None = None,
        allow_upgrade: bool = False,
    ) -> Mapping[str, Any]:
        """Verify the native artifact and create or exactly reuse local trust."""

        profiles = _profile_ids(allowed_profile_ids)
        if type(allow_upgrade) is not bool:
            raise RunnerLifecycleError("Runner upgrade confirmation is invalid.")
        if (
            self.process_record_path.exists()
            or _is_link_or_reparse(self.process_record_path)
            or self._ledger_lock_state() != "free"
        ):
            raise RunnerLifecycleError("Runner must be stopped before bootstrap can change.")
        if self.enrollment_revocation_intent_path.exists() or _is_link_or_reparse(
            self.enrollment_revocation_intent_path
        ):
            try:
                revoke_local_enrollment(
                    self.enrollment_root,
                    secret_provider=self.secret_provider,
                )
            except (OSError, RunnerTrustError, RuntimeError):
                raise RunnerLifecycleError(
                    "Runner enrollment revocation must be reconciled first."
                ) from None
            raise RunnerLifecycleError(
                "Runner enrollment revocation was reconciled; retry bootstrap explicitly."
            )
        removal_transition = any(
            path.exists() or _is_link_or_reparse(path)
            for path in (
                self.enrollment_tombstone_root,
                self.enrollment_removal_intent_path,
            )
        )
        if removal_transition:
            try:
                self.trust_removal(
                    self.enrollment_root,
                    secret_provider=self.secret_provider,
                    confirm_runner_id=self.runner_id,
                )
            except (OSError, RunnerTrustError, RuntimeError):
                raise RunnerLifecycleError(
                    "Runner enrollment removal must be reconciled first."
                ) from None
            raise RunnerLifecycleError(
                "Runner enrollment removal was reconciled; retry bootstrap explicitly."
            )
        if self.removal_journal_path.exists() or _is_link_or_reparse(self.removal_journal_path):
            raise RunnerLifecycleError("Runner enrollment removal must be reconciled first.")

        enrollment: RunnerEnrollment | None = None
        previous: _BootstrapRecord | None = None
        try:
            creation_intent_present = self.enrollment_creation_intent_path.exists() or (
                _is_link_or_reparse(self.enrollment_creation_intent_path)
            )
            if creation_intent_present:
                enrollment = create_local_enrollment(
                    self.enrollment_root,
                    runner_id=self.runner_id,
                    client_id=self.client_id,
                    allowed_profile_ids=profiles,
                    secret_provider=self.secret_provider,
                )
            enrollment_present = self.enrollment_root.exists() or _is_link_or_reparse(
                self.enrollment_root
            )
            staging_present = self.enrollment_staging_root.exists() or _is_link_or_reparse(
                self.enrollment_staging_root
            )
            if enrollment_present and staging_present:
                raise RunnerLifecycleError("Runner enrollment transition is inconsistent.")
            if staging_present and not creation_intent_present:
                raise RunnerLifecycleError(
                    "Runner enrollment creation could not be completed safely."
                )
            if enrollment is not None:
                if (
                    enrollment.runner_id != self.runner_id
                    or enrollment.client_id != self.client_id
                    or enrollment.allowed_profile_ids != profiles
                ):
                    raise RunnerLifecycleError(
                        "Existing runner enrollment does not match the requested identities."
                    )
                if self.bootstrap_record_path.exists() or _is_link_or_reparse(
                    self.bootstrap_record_path
                ):
                    previous = self._parse_bootstrap_record(enrollment)
            elif enrollment_present:
                enrollment = load_local_enrollment(
                    self.enrollment_root,
                    secret_provider=self.secret_provider,
                )
                if (
                    enrollment.runner_id != self.runner_id
                    or enrollment.client_id != self.client_id
                    or enrollment.allowed_profile_ids != profiles
                ):
                    raise RunnerLifecycleError(
                        "Existing runner enrollment does not match the requested identities."
                    )
                if self.bootstrap_record_path.exists() or _is_link_or_reparse(
                    self.bootstrap_record_path
                ):
                    previous = self._parse_bootstrap_record(enrollment)
            bootstrapped = self.bootstrap_factory(
                environ=environ,
                resource_root=resource_root,
                managed_root=self.runtime_root,
                product_version=product_version,
                platform_name=platform_name,
                architecture=architecture,
                inventory_probe=inventory_probe,
            )
            payload = self._validated_bootstrap_payload(bootstrapped)
            if previous is not None and _bootstrap_record_payload(previous) != payload:
                if not allow_upgrade:
                    raise RunnerLifecycleError(
                        "Runner bootstrap differs; an explicit clean upgrade is required."
                    )
                if enrollment is None:
                    raise RunnerLifecycleError("Runner enrollment identity is unavailable.")
                self._require_upgrade_ready(previous, payload, enrollment)
            if enrollment is None:
                enrollment = create_local_enrollment(
                    self.enrollment_root,
                    runner_id=self.runner_id,
                    client_id=self.client_id,
                    allowed_profile_ids=profiles,
                    secret_provider=self.secret_provider,
                )
        except RunnerLifecycleError:
            raise
        except (RunnerTrustError, RuntimeError):
            raise RunnerLifecycleError(
                "Runner bootstrap or enrollment could not be completed."
            ) from None
        try:
            record = {
                **payload,
                "authentication": _record_authentication(enrollment, payload),
            }
            _write_private_json(
                self.bootstrap_record_path,
                record,
                maximum=BOOTSTRAP_RECORD_MAX_BYTES,
                replace=True,
            )
        except RunnerLifecycleError:
            raise
        except (OSError, RunnerTrustError, RuntimeError):
            raise RunnerLifecycleError("Runner bootstrap state could not be persisted.") from None
        return self.status(profile_id=profiles[0])

    def status(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        """Return path-free lifecycle state; only authenticated health yields ready."""

        if not self.root.exists() and not _is_link_or_reparse(self.root):
            return self._status_payload(
                state="unbootstrapped",
                enrollment_state="absent",
                process_state="absent",
            )
        try:
            self._validate_root_marker()
        except RunnerLifecycleError:
            return self._status_payload(
                state="unavailable",
                enrollment_state="unavailable",
                process_state="unavailable",
            )
        enrollment, enrollment_state = self._enrollment_for_status()
        if enrollment is None:
            lock_state = self._ledger_lock_state()
            process_present = self.process_record_path.exists() or _is_link_or_reparse(
                self.process_record_path
            )
            removal_present = self.enrollment_tombstone_root.exists() or _is_link_or_reparse(
                self.enrollment_tombstone_root
            )
            removal_present = (
                removal_present
                or self.enrollment_removal_intent_path.exists()
                or (_is_link_or_reparse(self.enrollment_removal_intent_path))
            )
            creation_present = self.enrollment_creation_intent_path.exists() or (
                _is_link_or_reparse(self.enrollment_creation_intent_path)
            )
            revocation_present = self.enrollment_revocation_intent_path.exists() or (
                _is_link_or_reparse(self.enrollment_revocation_intent_path)
            )
            unavailable = (
                lock_state != "free"
                or process_present
                or removal_present
                or creation_present
                or revocation_present
            )
            return self._status_payload(
                state=(
                    "unbootstrapped"
                    if enrollment_state == "absent" and not unavailable
                    else "unavailable"
                ),
                enrollment_state=enrollment_state,
                process_state="unavailable" if unavailable else "absent",
            )
        try:
            bootstrap = self._load_bootstrap(enrollment)
        except RunnerLifecycleError:
            unbootstrapped = (
                not self.bootstrap_record_path.exists()
                and not _is_link_or_reparse(self.bootstrap_record_path)
                and self._ledger_lock_state() == "free"
                and not self.process_record_path.exists()
                and not _is_link_or_reparse(self.process_record_path)
            )
            state = "unbootstrapped" if unbootstrapped else "unavailable"
            return self._status_payload(
                state=state,
                enrollment_state=enrollment_state,
                process_state="absent" if state == "unbootstrapped" else "unavailable",
            )
        selected = self._selected_profile(enrollment, profile_id)
        public_runner = self._public_runner(bootstrap)
        if not self.process_record_path.exists() and not _is_link_or_reparse(
            self.process_record_path
        ):
            lock_state = self._ledger_lock_state()
            return self._status_payload(
                state="stopped" if lock_state == "free" else "unavailable",
                enrollment_state=enrollment_state,
                process_state="absent" if lock_state == "free" else "unavailable",
                profile_id=selected,
                runner=public_runner,
            )
        if enrollment_state != "active":
            return self._status_payload(
                state="unavailable",
                enrollment_state=enrollment_state,
                process_state="unavailable",
                profile_id=selected,
                runner=public_runner,
            )
        try:
            record = read_process_record(
                self.process_record_path,
                enrollment=enrollment,
                expected_binary_digest=bootstrap.binary_digest,
            )
        except RunnerHostError:
            lock_state = self._ledger_lock_state()
            return self._status_payload(
                state="stale" if lock_state == "free" else "unavailable",
                enrollment_state=enrollment_state,
                process_state="stale" if lock_state == "free" else "unavailable",
                profile_id=selected,
                runner=public_runner,
            )
        try:
            _client, health = self._authenticated_health(
                enrollment,
                bootstrap,
                record,
                selected,
            )
        except RunnerLifecycleError:
            lock_state = self._ledger_lock_state()
            return self._status_payload(
                state="stale" if lock_state == "free" else "unavailable",
                enrollment_state=enrollment_state,
                process_state="stale" if lock_state == "free" else "unavailable",
                profile_id=selected,
                runner=public_runner,
            )
        accepting_execute = bool(
            isinstance(health.get("ledger"), Mapping)
            and health["ledger"].get("accepting_execute") is True
        )
        return self._status_payload(
            state="ready" if accepting_execute else "unavailable",
            enrollment_state=enrollment_state,
            process_state="authenticated",
            profile_id=selected,
            runner=public_runner,
            health={
                "transport": health["transport"],
                "tls": health["tls"],
                "runner_binary_digest": health["runner_binary_digest"],
                "inventory_digest": health.get("inventory_digest"),
                "accepting_execute": accepting_execute,
            },
        )

    def start(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        with self._operation_guard(adopt=False):
            return self._start_locked(profile_id=profile_id)

    def _start_locked(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        """Launch the installed host module and require authenticated health."""

        enrollment = self._load_active_enrollment()
        bootstrap = self._load_bootstrap(enrollment)
        selected = self._selected_profile(enrollment, profile_id)
        if self.process_record_path.exists() or _is_link_or_reparse(self.process_record_path):
            current = self.status(profile_id=selected)
            if current["state"] == "ready":
                return current
            if self._ledger_lock_state() != "free":
                raise RunnerLifecycleError("Runner host state is unavailable; start was refused.")
            self._remove_stale_process_record()
        elif self._ledger_lock_state() != "free":
            raise RunnerLifecycleError("Runner host ownership is unavailable; start was refused.")

        launch_id = secrets.token_hex(32)
        start_gate_path = self.control_root / f".host-start-{launch_id}.gate"
        spec = RunnerHostSpec(
            enrollment_root=enrollment.root,
            runner_binary=bootstrap.binary_path,
            work_root=bootstrap.sandbox_path,
            state_path=self.ledger_path,
            process_record_path=self.process_record_path,
            start_gate_path=start_gate_path,
            launch_id=launch_id,
            runner_timeout_seconds=self.runner_timeout_seconds,
        )
        command = _validated_host_command(self.host_command_factory(spec))
        launch: _LaunchProcess | None = None
        try:
            _write_private_bytes(start_gate_path, launch_id.encode("ascii"), replace=False)
            launch = _spawn_contained_host(command)
            _unlink_exact_regular(start_gate_path)
        except (OSError, RunnerLifecycleError):
            if launch is not None:
                self._stop_exact_failed_launch(launch)
            else:
                _best_effort_unlink(start_gate_path)
            raise RunnerLifecycleError("Runner host process could not be started.") from None

        deadline = time.monotonic() + self.start_timeout_seconds
        while time.monotonic() < deadline:
            if launch.process.poll() is not None:
                break
            if self.process_record_path.exists():
                try:
                    record = read_process_record(
                        self.process_record_path,
                        enrollment=enrollment,
                        expected_binary_digest=bootstrap.binary_digest,
                    )
                    if record["launch_id"] != launch_id:
                        raise RunnerLifecycleError("Runner launch identity did not match.")
                    self._authenticated_health(enrollment, bootstrap, record, selected)
                    try:
                        _release_launch_containment(launch)
                    except OSError:
                        self._stop_exact_failed_launch(launch)
                        raise RunnerLifecycleError(
                            "Runner launch containment could not be released."
                        ) from None
                    self._owned_processes[launch_id] = launch.process
                    return self.status(profile_id=selected)
                except (RunnerHostError, RunnerLifecycleError):
                    pass
            time.sleep(0.025)
        self._stop_exact_failed_launch(launch)
        raise RunnerLifecycleError("Runner host did not reach authenticated readiness.")

    def client_for_profile(self, profile_id: str) -> tuple[AuthenticatedRunnerClient, Path]:
        """Return a verified client and the exact sandbox for one enrolled profile."""

        enrollment = self._load_active_enrollment()
        bootstrap = self._load_bootstrap(enrollment)
        selected = self._selected_profile(enrollment, profile_id)
        try:
            record = read_process_record(
                self.process_record_path,
                enrollment=enrollment,
                expected_binary_digest=bootstrap.binary_digest,
            )
        except RunnerHostError:
            raise RunnerLifecycleError("Runner host is not authenticated and ready.") from None
        _control_client, _health = self._authenticated_health(
            enrollment, bootstrap, record, selected
        )
        ledger = _health.get("ledger")
        if not isinstance(ledger, Mapping) or ledger.get("accepting_execute") is not True:
            raise RunnerLifecycleError("Runner recovery ledger cannot accept execution.")
        client = self._new_client(
            enrollment,
            selected,
            port=int(record["port"]),
            execution=True,
        )
        return client, bootstrap.sandbox_path

    def stop(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        with self._operation_guard(adopt=False):
            return self._stop_locked(profile_id=profile_id)

    def _stop_locked(self, *, profile_id: str | None = None) -> Mapping[str, Any]:
        """Stop only through the authenticated lifecycle operation."""

        enrollment = self._load_active_enrollment()
        bootstrap = self._parse_bootstrap_record(enrollment)
        selected = self._selected_profile(enrollment, profile_id)
        if not self.process_record_path.exists() and not _is_link_or_reparse(
            self.process_record_path
        ):
            if self._ledger_lock_state() != "free":
                raise RunnerLifecycleError(
                    "Runner host ownership is unavailable; stop was refused."
                )
            return self.status(profile_id=selected)
        try:
            record = read_process_record(
                self.process_record_path,
                enrollment=enrollment,
                expected_binary_digest=bootstrap.binary_digest,
            )
            client = self._new_client(enrollment, selected, port=int(record["port"]))
        except (RunnerHostError, RunnerLifecycleError):
            if self._ledger_lock_state() != "free":
                raise RunnerLifecycleError(
                    "Runner host is unavailable; stop was refused."
                ) from None
            self._remove_stale_process_record()
            return self.status(profile_id=selected)

        try:
            client.shutdown(server_instance_id=str(record["server_instance_id"]))
        except RunnerRemoteError as exc:
            if exc.code == "active_tasks":
                raise RunnerLifecycleError(
                    "Runner is draining active tasks; retry authenticated shutdown."
                ) from None
            raise RunnerLifecycleError(
                "Authenticated runner shutdown was not acknowledged."
            ) from None
        except RunnerConnectionError:
            if self._ledger_lock_state() == "free":
                self._remove_stale_process_record()
                return self.status(profile_id=selected)
            raise RunnerLifecycleError(
                "Authenticated runner shutdown was not acknowledged."
            ) from None
        except RunnerAuthenticationError:
            raise RunnerLifecycleError(
                "Authenticated runner shutdown was not acknowledged."
            ) from None
        deadline = time.monotonic() + self.stop_timeout_seconds
        while time.monotonic() < deadline:
            if not self.process_record_path.exists() and self._ledger_lock_state() == "free":
                self._reap_owned_process(str(record["launch_id"]))
                return self.status(profile_id=selected)
            time.sleep(0.025)
        if self._ledger_lock_state() == "free":
            self._remove_stale_process_record()
            self._reap_owned_process(str(record["launch_id"]))
            return self.status(profile_id=selected)
        raise RunnerLifecycleError("Runner host did not complete authenticated shutdown.")

    def revoke(self) -> Mapping[str, Any]:
        with self._operation_guard(adopt=False):
            return self._revoke_locked()

    def _revoke_locked(self) -> Mapping[str, Any]:
        """Revoke trust only after a separately completed stop."""

        if self.enrollment_revocation_intent_path.exists() or _is_link_or_reparse(
            self.enrollment_revocation_intent_path
        ):
            try:
                revoke_local_enrollment(
                    self.enrollment_root,
                    secret_provider=self.secret_provider,
                )
            except RunnerTrustError:
                raise RunnerLifecycleError("Runner enrollment could not be revoked.") from None
            return self.status()
        enrollment = self._load_enrollment(require_active=False)
        if enrollment.status == "revoked":
            return self.status()
        if enrollment.status != "active":
            raise RunnerLifecycleError("Runner enrollment is unavailable or inactive.")
        bootstrap = self._parse_bootstrap_record(enrollment)
        self._require_stopped("enrollment revocation")
        ledger_generation = self._ledger_preflight(enrollment)
        self._require_no_live_watchdogs(
            enrollment,
            ledger_generation=ledger_generation,
            require_namespace_empty=False,
        )
        self._require_no_receipt_obligations(bootstrap.sandbox_path)
        try:
            revoke_local_enrollment(enrollment.root, secret_provider=self.secret_provider)
        except RunnerTrustError:
            raise RunnerLifecycleError("Runner enrollment could not be revoked.") from None
        return self.status()

    def remove(self, *, confirm_runner_id: str) -> Mapping[str, Any]:
        with self._operation_guard(adopt=False):
            return self._remove_locked(confirm_runner_id=confirm_runner_id)

    def _remove_locked(self, *, confirm_runner_id: str) -> Mapping[str, Any]:
        """Remove revoked trust only when no execution cleanup duty remains."""

        if confirm_runner_id != self.runner_id:
            raise RunnerLifecycleError("Runner removal confirmation does not match.")
        if self.enrollment_revocation_intent_path.exists() or _is_link_or_reparse(
            self.enrollment_revocation_intent_path
        ):
            try:
                revoke_local_enrollment(
                    self.enrollment_root,
                    secret_provider=self.secret_provider,
                )
            except RunnerTrustError:
                raise RunnerLifecycleError(
                    "Runner enrollment revocation must be reconciled first."
                ) from None
        if not self.enrollment_root.exists() and not _is_link_or_reparse(self.enrollment_root):
            return self._complete_partial_removal(confirm_runner_id=confirm_runner_id)
        enrollment = self._load_enrollment(require_active=False)
        if enrollment.status != "revoked":
            raise RunnerLifecycleError("Runner enrollment must be revoked before removal.")
        bootstrap = self._parse_bootstrap_record(enrollment)
        self._require_stopped("removal")
        ledger_generation = self._ledger_preflight(enrollment)
        self._require_no_live_watchdogs(
            enrollment,
            ledger_generation=ledger_generation,
            require_namespace_empty=False,
        )
        self._require_no_receipt_obligations(bootstrap.sandbox_path)
        try:
            self._remove_transport_state(enrollment, ledger_generation=ledger_generation)
            self.trust_removal(
                enrollment.root,
                secret_provider=self.secret_provider,
                confirm_runner_id=confirm_runner_id,
            )
            _unlink_exact_regular(self.bootstrap_record_path)
        except (OSError, RunnerLifecycleError, RunnerTrustError, RuntimeError):
            raise RunnerLifecycleError("Runner enrollment could not be removed safely.") from None
        return self._status_payload(
            state="unbootstrapped",
            enrollment_state="absent",
            process_state="absent",
        )

    def _complete_partial_removal(self, *, confirm_runner_id: str) -> Mapping[str, Any]:
        """Finish only the safe tail of an already trust-removed operation."""

        if self.process_record_path.exists() or _is_link_or_reparse(self.process_record_path):
            raise RunnerLifecycleError("Runner must be stopped before removal.")
        transport_paths = (
            self.ledger_path,
            self.ledger_lock_path,
            self.ledger_path.with_name(self.ledger_path.name + "-wal"),
            self.ledger_path.with_name(self.ledger_path.name + "-shm"),
            self.ledger_path.with_name(self.ledger_path.name + "-journal"),
        )
        if any(path.exists() or _is_link_or_reparse(path) for path in transport_paths):
            raise RunnerLifecycleError("Orphaned runner transport state requires reconciliation.")
        try:
            if any(
                path.exists() or _is_link_or_reparse(path)
                for path in (
                    self.enrollment_tombstone_root,
                    self.enrollment_removal_intent_path,
                )
            ):
                self.trust_removal(
                    self.enrollment_root,
                    secret_provider=self.secret_provider,
                    confirm_runner_id=confirm_runner_id,
                )
            _unlink_exact_regular(self.bootstrap_record_path)
        except (OSError, RunnerTrustError, RuntimeError):
            raise RunnerLifecycleError(
                "Runner bootstrap state could not be removed safely."
            ) from None
        return self._status_payload(
            state="unbootstrapped",
            enrollment_state="absent",
            process_state="absent",
        )

    @contextmanager
    def _operation_guard(self, *, adopt: bool) -> Any:
        """Serialize lifecycle mutations in-process and across processes."""

        local = _local_operation_lock(self.root)
        with self._instance_operation_lock, local:
            self._prepare_operation_root(adopt=adopt)
            handle, lock_identity = _open_private_lock_file(self.operation_lock_path)
            try:
                _lock_file(
                    handle,
                    path=self.operation_lock_path,
                    expected_identity=lock_identity,
                    timeout_seconds=120.0,
                )
                if adopt:
                    self._adopt_or_validate_root()
                else:
                    self._validate_root_marker()
                yield
            finally:
                _unlock_file(handle)
                handle.close()

    def _prepare_operation_root(self, *, adopt: bool) -> None:
        try:
            _reject_linked_ancestors(self.root)
        except OSError:
            raise RunnerLifecycleError("Managed runner storage is unavailable or unsafe.") from None
        if not self.root.exists():
            if not adopt:
                raise RunnerLifecycleError("Managed runner lifecycle is not bootstrapped.")
            try:
                parent = self.root.parent.resolve(strict=True)
                if (
                    not parent.is_dir()
                    or _is_link_or_reparse(parent)
                    or not _same_path(parent, self.root.parent)
                ):
                    raise OSError("unsafe lifecycle parent")
                try:
                    self.root.mkdir(mode=0o700, parents=False, exist_ok=False)
                except FileExistsError:
                    # A competing lifecycle operation may have created the
                    # exact root immediately before opening the shared lock.
                    pass
            except OSError:
                raise RunnerLifecycleError(
                    "Managed runner storage is unavailable or unsafe."
                ) from None
        try:
            resolved = self.root.resolve(strict=True)
            if (
                _is_link_or_reparse(self.root)
                or not resolved.is_dir()
                or not _same_path(self.root, resolved)
            ):
                raise OSError("unsafe lifecycle root")
            entries = {entry.name for entry in resolved.iterdir()}
            marker_present = self.root_marker_path.name in entries
            if marker_present:
                value = _read_private_json(
                    self.root_marker_path,
                    maximum=ROOT_MARKER_MAX_BYTES,
                    enforce_private=False,
                )
                if not _valid_root_marker(value, self.runner_id, resolved):
                    raise OSError("invalid lifecycle marker")
            else:
                allowed = {
                    self.operation_lock_path.name,
                    self.enrollment_transition_lock_path.name,
                }
                if entries - allowed:
                    raise OSError("unowned lifecycle root")
                # A non-adopting operation may have raced a bootstrap that
                # has created only its known lock artifacts. It will validate
                # the ownership marker after acquiring the operation lock.
            _owner_private_pinned(resolved, directory=True)
        except (OSError, RunnerLifecycleError, RunnerTrustError):
            raise RunnerLifecycleError("Managed runner storage is unavailable or unsafe.") from None

    def _adopt_or_validate_root(self) -> None:
        if self.root_marker_path.exists() or _is_link_or_reparse(self.root_marker_path):
            self._validate_root_marker()
        else:
            entries = {entry.name for entry in self.root.iterdir()}
            allowed = {
                self.operation_lock_path.name,
                self.enrollment_transition_lock_path.name,
            }
            if entries - allowed:
                raise RunnerLifecycleError("Managed runner root is not empty or owned.")
            marker = {
                "schema_version": ROOT_MARKER_SCHEMA_VERSION,
                "runner_id": self.runner_id,
                "root_digest": _root_digest(self.root),
                "marker_id": secrets.token_hex(32),
            }
            _write_private_json(
                self.root_marker_path,
                marker,
                maximum=ROOT_MARKER_MAX_BYTES,
                replace=False,
            )
        self._prepare_directories()

    def _validate_root_marker(self) -> None:
        try:
            _reject_linked_ancestors(self.root)
            resolved = self.root.resolve(strict=True)
            value = _read_private_json(
                self.root_marker_path,
                maximum=ROOT_MARKER_MAX_BYTES,
                enforce_private=False,
            )
            if not _valid_root_marker(value, self.runner_id, resolved):
                raise OSError("invalid lifecycle marker")
            _owner_private_pinned(resolved, directory=True)
            _owner_private_pinned(self.root_marker_path, directory=False)
            for child in (self.control_root, self.runtime_root):
                if child.exists():
                    checked = child.resolve(strict=True)
                    if (
                        _is_link_or_reparse(child)
                        or not checked.is_dir()
                        or checked.parent != resolved
                        or not _same_path(child, checked)
                    ):
                        raise OSError("managed child escaped lifecycle root")
                    _owner_private_pinned(checked, directory=True)
        except (OSError, RunnerLifecycleError, RunnerTrustError):
            raise RunnerLifecycleError("Managed runner root marker is unavailable.") from None

    def _prepare_directories(self) -> None:
        root = _ensure_private_directory(self.root)
        _ensure_private_directory(self.control_root, expected_parent=root)
        _ensure_private_directory(self.runtime_root, expected_parent=root)

    def _load_active_enrollment(self) -> RunnerEnrollment:
        return self._load_enrollment(require_active=True)

    def _load_enrollment(self, *, require_active: bool) -> RunnerEnrollment:
        try:
            enrollment = load_local_enrollment(
                self.enrollment_root,
                require_active=require_active,
                secret_provider=self.secret_provider,
            )
        except RunnerTrustError:
            raise RunnerLifecycleError("Runner enrollment is unavailable or inactive.") from None
        if enrollment.runner_id != self.runner_id or enrollment.client_id != self.client_id:
            raise RunnerLifecycleError("Runner enrollment identity does not match.")
        return enrollment

    def _enrollment_for_status(self) -> tuple[RunnerEnrollment | None, str]:
        try:
            transitions = (
                self.enrollment_staging_root,
                self.enrollment_creation_intent_path,
                self.enrollment_revocation_intent_path,
                self.enrollment_removal_intent_path,
            )
            if any(path.exists() or _is_link_or_reparse(path) for path in transitions):
                return None, "unavailable"
        except RunnerLifecycleError:
            return None, "unavailable"
        if not self.enrollment_root.exists() and not _is_link_or_reparse(self.enrollment_root):
            return None, "absent"
        try:
            enrollment = self._load_enrollment(require_active=False)
            state = str(
                enrollment_status(
                    enrollment.root,
                    secret_provider=self.secret_provider,
                )["status"]
            )
            return enrollment, state
        except (RunnerLifecycleError, RunnerTrustError, KeyError):
            return None, "unavailable"

    def _parse_bootstrap_record(self, enrollment: RunnerEnrollment) -> _BootstrapRecord:
        try:
            value = _read_private_json(
                self.bootstrap_record_path,
                maximum=BOOTSTRAP_RECORD_MAX_BYTES,
            )
            if not isinstance(value, dict) or set(value) != _BOOTSTRAP_FIELDS:
                raise ValueError("unsupported bootstrap record")
            unsigned = {key: value[key] for key in value if key != "authentication"}
            authentication = value.get("authentication")
            if (
                value.get("schema_version") != BOOTSTRAP_RECORD_SCHEMA_VERSION
                or value.get("runner_id") != self.runner_id
                or value.get("source") not in {"packaged", "environment_override"}
                or type(value.get("managed_binary")) is not bool
                or type(value.get("managed_sandbox")) is not bool
                or not isinstance(value.get("binary_path"), str)
                or not 1 <= len(value["binary_path"]) <= 32768
                or not isinstance(value.get("sandbox_path"), str)
                or not 1 <= len(value["sandbox_path"]) <= 32768
                or not isinstance(value.get("binary_digest"), str)
                or _DIGEST.fullmatch(value["binary_digest"]) is None
                or not all(
                    isinstance(value.get(field), str) and 1 <= len(value[field]) <= 200
                    for field in (
                        "product_version",
                        "runner_version",
                        "platform",
                        "architecture",
                        "inventory_schema",
                        "action_sdk_version",
                        "receipt_protocol",
                    )
                )
                or not isinstance(authentication, str)
                or _DIGEST.fullmatch(authentication) is None
                or not hmac.compare_digest(
                    authentication,
                    _record_authentication(enrollment, unsigned),
                )
            ):
                raise ValueError("invalid bootstrap record")
            binary = _canonical_record_path(Path(value["binary_path"]))
            sandbox = _canonical_record_path(Path(value["sandbox_path"]))
            runtime = _canonical_record_path(self.runtime_root)
            if value["managed_binary"] and not binary.is_relative_to(runtime):
                raise OSError("managed binary escaped runtime root")
            if value["managed_sandbox"] and not sandbox.is_relative_to(runtime):
                raise OSError("managed sandbox escaped runtime root")
        except (OSError, ValueError, KeyError, RunnerHostError, RunnerTrustError):
            raise RunnerLifecycleError("Managed runner bootstrap state is unavailable.") from None
        return _BootstrapRecord(
            binary_path=binary,
            sandbox_path=sandbox,
            binary_digest=str(value["binary_digest"]),
            source=str(value["source"]),
            managed_binary=bool(value["managed_binary"]),
            managed_sandbox=bool(value["managed_sandbox"]),
            product_version=str(value["product_version"]),
            runner_version=str(value["runner_version"]),
            platform=str(value["platform"]),
            architecture=str(value["architecture"]),
            inventory_schema=str(value["inventory_schema"]),
            action_sdk_version=str(value["action_sdk_version"]),
            receipt_protocol=str(value["receipt_protocol"]),
        )

    def _load_bootstrap(self, enrollment: RunnerEnrollment) -> _BootstrapRecord:
        record = self._parse_bootstrap_record(enrollment)
        return self._require_live_bootstrap(record)

    def _require_live_bootstrap(self, record: _BootstrapRecord) -> _BootstrapRecord:
        try:
            binary = _canonical_record_path(record.binary_path)
            sandbox = _canonical_record_path(record.sandbox_path)
            if (
                not binary.is_file()
                or not sandbox.is_dir()
                or not os.access(sandbox, os.W_OK)
                or file_hash(binary) != record.binary_digest
            ):
                raise OSError("bootstrap artifact changed")
        except OSError:
            raise RunnerLifecycleError("Managed runner artifacts are unavailable.") from None
        return record

    def _validated_bootstrap_payload(self, bootstrapped: BootstrappedRunner) -> dict[str, Any]:
        if bootstrapped.manifest.runner_id != self.runner_id:
            raise RunnerLifecycleError("Bootstrapped runner identity is incompatible.")
        try:
            binary = _canonical_record_path(Path(bootstrapped.binary_path))
            sandbox = _canonical_record_path(Path(bootstrapped.sandbox_path))
            if (
                not binary.is_file()
                or not sandbox.is_dir()
                or not os.access(sandbox, os.W_OK)
                or file_hash(binary) != "sha256:" + bootstrapped.binary_sha256
            ):
                raise OSError("invalid bootstrap output")
            payload = _bootstrap_payload(bootstrapped, self.runner_id)
            if payload["binary_path"] != str(binary) or payload["sandbox_path"] != str(sandbox):
                raise OSError("bootstrap path changed")
            return payload
        except OSError:
            raise RunnerLifecycleError("Bootstrapped runner artifacts are invalid.") from None

    def _require_upgrade_ready(
        self,
        previous: _BootstrapRecord,
        replacement: Mapping[str, Any],
        enrollment: RunnerEnrollment,
    ) -> None:
        if str(previous.sandbox_path) != replacement.get("sandbox_path"):
            raise RunnerLifecycleError("Runner upgrade cannot abandon the enrolled sandbox.")
        self._require_stopped("upgrade")
        ledger_generation = self._ledger_preflight(enrollment, require_zero_execute=True)
        self._require_no_receipt_obligations(previous.sandbox_path)
        self._require_no_live_watchdogs(
            enrollment,
            ledger_generation=ledger_generation,
            require_namespace_empty=True,
        )

    def _selected_profile(self, enrollment: RunnerEnrollment, requested: str | None) -> str:
        selected = requested or enrollment.allowed_profile_ids[0]
        if (
            not isinstance(selected, str)
            or _IDENTIFIER.fullmatch(selected) is None
            or selected not in enrollment.allowed_profile_ids
        ):
            raise RunnerLifecycleError("Runner profile is not enrolled.")
        return selected

    def _authenticated_health(
        self,
        enrollment: RunnerEnrollment,
        bootstrap: _BootstrapRecord,
        record: Mapping[str, Any],
        profile_id: str,
    ) -> tuple[AuthenticatedRunnerClient, Mapping[str, Any]]:
        try:
            client = self._new_client(enrollment, profile_id, port=int(record["port"]))
            health = client.health()
        except (RunnerAuthenticationError, RunnerConnectionError, OSError, RuntimeError):
            raise RunnerLifecycleError("Runner authenticated health is unavailable.") from None
        if (
            not isinstance(health, Mapping)
            or health.get("schema_version") != "bluefire.runner-health.v1"
            or health.get("status") != "ready"
            or health.get("runner_id") != self.runner_id
            or health.get("profile_id") != profile_id
            or health.get("transport") != "mutual-tls-loopback"
            or health.get("tls") != "TLSv1.3"
            or health.get("server_fingerprint") != enrollment.metadata["server_fingerprint"]
            or health.get("client_fingerprint") != enrollment.metadata["client_fingerprint"]
            or health.get("authenticated_peer_fingerprint")
            != enrollment.metadata["client_fingerprint"]
            or health.get("runner_binary_digest") != bootstrap.binary_digest
            or health.get("server_instance_id") != record.get("server_instance_id")
        ):
            raise RunnerLifecycleError("Runner authenticated health identity does not match.")
        return client, health

    def _new_client(
        self,
        enrollment: RunnerEnrollment,
        profile_id: str,
        *,
        port: int,
        execution: bool = False,
    ) -> AuthenticatedRunnerClient:
        try:
            return self.client_factory(
                enrollment.root,
                profile_id=profile_id,
                host=LOOPBACK_HOST,
                port=port,
                # Execute may remain silent until the native runner deadline.
                # The server adds five seconds for watchdog termination and
                # terminal publication; the client needs a separate five-second
                # response margin because its deadline starts before TLS and
                # request validation. Lifecycle control probes retain their
                # short readiness bound.
                socket_timeout_seconds=(
                    max(self.runner_timeout_seconds + 5.0, 10.0) + 5.0
                    if execution
                    else min(5.0, self.start_timeout_seconds)
                ),
                recovery_delay_seconds=0.025,
                secret_provider=self.secret_provider,
            )
        except (OSError, RuntimeError):
            raise RunnerLifecycleError("Runner authenticated endpoint is unavailable.") from None

    def _ledger_lock_state(self) -> str:
        path = self.ledger_lock_path
        if not path.exists() and not _is_link_or_reparse(path):
            return "free"
        handle: Any = None
        descriptor: int | None = None
        try:
            if _is_link_or_reparse(path) or not path.is_file() or path.stat().st_nlink != 1:
                return "unsafe"
            descriptor = os.open(
                path,
                os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            _owner_private_open_regular(path, descriptor)
            if os.name == "nt":
                import msvcrt

                pin, pinned = _windows_open_pinned_path(
                    path,
                    directory=False,
                    delete_access=False,
                )
                if pinned[2:] != _descriptor_identity(descriptor):
                    _windows_close_handle(pin)
                    raise OSError("ledger lock changed")
                handle = _WindowsPinnedLockHandle(
                    os.fdopen(descriptor, "r+b", buffering=0),
                    pin,
                )
                descriptor = None
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                handle = os.fdopen(descriptor, "r+b", buffering=0)
                descriptor = None
                fcntl.flock(  # type: ignore[attr-defined]
                    handle.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined]
                )
                fcntl.flock(  # type: ignore[attr-defined]
                    handle.fileno(),
                    fcntl.LOCK_UN,  # type: ignore[attr-defined]
                )
            return "free"
        except (OSError, RunnerTrustError):
            return "held"
        finally:
            if handle is not None:
                handle.close()
            elif descriptor is not None:
                os.close(descriptor)

    def _require_stopped(self, operation: str) -> None:
        if self.process_record_path.exists() or _is_link_or_reparse(self.process_record_path):
            raise RunnerLifecycleError(f"Runner must be stopped before {operation}.")
        if self._ledger_lock_state() != "free":
            raise RunnerLifecycleError(f"Runner must be stopped before {operation}.")

    def _ledger_preflight(
        self,
        enrollment: RunnerEnrollment,
        *,
        require_zero_execute: bool = False,
    ) -> str | None:
        try:
            audit = audit_runner_ledger(self.ledger_path, enrollment)
            if audit is None:
                self._require_empty_result_parent_without_ledger()
                return None
            fields = frozenset(
                {
                    "schema_version",
                    "ledger_generation",
                    "total_rows",
                    "execute_rows",
                    "unresolved_rows",
                    "active_rows",
                    "cleanup_required_rows",
                }
            )
            raw_counts = tuple(
                audit.get(field)
                for field in (
                    "total_rows",
                    "execute_rows",
                    "unresolved_rows",
                    "active_rows",
                    "cleanup_required_rows",
                )
            )
            generation = audit.get("ledger_generation")
            if (
                set(audit) != fields
                or audit.get("schema_version") != "bluefire.runner-ledger-audit.v1"
                or not isinstance(generation, str)
                or _DIGEST.fullmatch("sha256:" + generation) is None
                or any(
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or not 0 <= value <= 1_000_000
                    for value in raw_counts
                )
            ):
                raise ValueError("invalid ledger audit")
            counts = cast(tuple[int, int, int, int, int], raw_counts)
            if any(value > counts[0] for value in counts[1:]):
                raise ValueError("invalid ledger audit counts")
        except RunnerLifecycleError:
            raise
        except (
            AuthenticatedRunnerTransportError,
            OSError,
            RunnerTrustError,
            TypeError,
            ValueError,
            RuntimeError,
        ):
            raise RunnerLifecycleError("Runner recovery ledger could not be verified.") from None
        if counts[2] or counts[3] or counts[4]:
            raise RunnerLifecycleError(
                "Runner removal is blocked by unresolved execution recovery or cleanup."
            )
        if require_zero_execute and counts[1]:
            raise RunnerLifecycleError(
                "Runner upgrade is blocked by prior execution recovery history."
            )
        return str(generation)

    def _require_empty_result_parent_without_ledger(self) -> None:
        parent = self.ledger_path.parent / ".bluefire-runner-results"
        try:
            if not parent.exists() and not _is_link_or_reparse(parent):
                return
            if _is_link_or_reparse(parent) or not parent.is_dir():
                raise OSError("unsafe result parent")
            resolved = parent.resolve(strict=True)
            if not _same_path(parent, resolved):
                raise OSError("result parent identity changed")
            if any(resolved.iterdir()):
                raise RunnerLifecycleError(
                    "Runner result recovery state has no authenticated ledger generation."
                )
        except RunnerLifecycleError:
            raise
        except (OSError, RunnerTrustError):
            raise RunnerLifecycleError(
                "Runner result recovery state could not be verified."
            ) from None

    def _require_no_live_watchdogs(
        self,
        enrollment: RunnerEnrollment,
        *,
        ledger_generation: str | None,
        require_namespace_empty: bool,
    ) -> None:
        try:
            parent = self.ledger_path.parent / ".bluefire-runner-results"
            if ledger_generation is None:
                self._require_empty_result_parent_without_ledger()
                return
            namespace = runner_result_namespace_path(
                self.ledger_path,
                enrollment,
                ledger_generation=ledger_generation,
            )
            if namespace.parent != parent or namespace.name in {"", ".", ".."}:
                raise OSError("result namespace escaped")
            if not parent.exists() and not _is_link_or_reparse(parent):
                return
            if _is_link_or_reparse(parent) or not parent.is_dir():
                raise OSError("unsafe result parent")
            checked_parent = parent.resolve(strict=True)
            if not _same_path(parent, checked_parent):
                raise OSError("result parent identity changed")
            if not namespace.exists() and not _is_link_or_reparse(namespace):
                return
            if _is_link_or_reparse(namespace) or not namespace.is_dir():
                raise OSError("unsafe result namespace")
            checked_namespace = namespace.resolve(strict=True)
            if checked_namespace.parent != checked_parent or not _same_path(
                namespace, checked_namespace
            ):
                raise OSError("result namespace identity changed")
            for entry in checked_namespace.iterdir():
                if _is_link_or_reparse(entry):
                    raise OSError("linked result state")
                if require_namespace_empty:
                    raise RunnerLifecycleError("Runner upgrade is blocked by prior result state.")
                if entry.is_file() and _DURABLE_RESULT_NAME.fullmatch(entry.name):
                    details = entry.stat(follow_symlinks=False)
                    if details.st_nlink != 1 or details.st_size > 8 * 1024 * 1024:
                        raise OSError("unsafe result file")
                    continue
                if (entry.is_file() and _PENDING_RESULT_NAME.fullmatch(entry.name) is not None) or (
                    entry.is_dir() and _WATCHDOG_DIRECTORY_NAME.fullmatch(entry.name) is not None
                ):
                    raise RunnerLifecycleError(
                        "Runner removal is blocked by live watchdog or pending result state."
                    )
                raise OSError("unexpected result state")
        except RunnerLifecycleError:
            raise
        except (OSError, RuntimeError, RunnerTrustError):
            raise RunnerLifecycleError(
                "Runner result recovery state could not be verified."
            ) from None

    @staticmethod
    def _require_no_receipt_obligations(sandbox: Path) -> None:
        try:
            sandbox = _canonical_record_path(sandbox)
            if not sandbox.exists() and not _is_link_or_reparse(sandbox):
                return
            if _is_link_or_reparse(sandbox) or not sandbox.is_dir():
                raise OSError("unsafe sandbox")
            state_root = sandbox / ".bluefire"
            if not state_root.exists() and not _is_link_or_reparse(state_root):
                return
            if _is_link_or_reparse(state_root) or not state_root.is_dir():
                raise OSError("unsafe receipt root")
            for name in ("receipts", "receipt-commits"):
                directory = state_root / name
                if not directory.exists() and not _is_link_or_reparse(directory):
                    continue
                if _is_link_or_reparse(directory) or not directory.is_dir():
                    raise OSError("unsafe receipt directory")
                with os.scandir(directory) as entries:
                    if next(entries, None) is not None:
                        raise RunnerLifecycleError(
                            "Runner removal is blocked by committed receipt cleanup obligations."
                        )
        except RunnerLifecycleError:
            raise
        except OSError:
            raise RunnerLifecycleError(
                "Runner receipt obligations could not be verified."
            ) from None

    def _remove_transport_state(
        self,
        enrollment: RunnerEnrollment,
        *,
        ledger_generation: str | None,
    ) -> None:
        """Remove only verified lifecycle-owned transport/recovery artifacts."""

        if self._ledger_lock_state() != "free":
            raise RunnerLifecycleError("Runner host ownership is unresolved; removal was refused.")
        try:
            shared_parent = self.ledger_path.parent / ".bluefire-runner-results"
            if ledger_generation is not None:
                namespace = runner_result_namespace_path(
                    self.ledger_path,
                    enrollment,
                    ledger_generation=ledger_generation,
                )
                if namespace.parent != shared_parent:
                    raise OSError("result namespace escaped")
                if namespace.exists() or _is_link_or_reparse(namespace):
                    _remove_result_namespace(namespace, expected_parent=shared_parent)
            else:
                self._require_empty_result_parent_without_ledger()
            if shared_parent.exists() or _is_link_or_reparse(shared_parent):
                if _is_link_or_reparse(shared_parent) or not shared_parent.is_dir():
                    raise OSError("unsafe result parent")
                checked_parent = shared_parent.resolve(strict=True)
                if not _same_path(shared_parent, checked_parent):
                    raise OSError("result parent identity changed")
                if not any(checked_parent.iterdir()):
                    _remove_empty_exact_directory(
                        checked_parent,
                        expected_parent=checked_parent.parent,
                    )
            for path in (
                self.ledger_path.with_name(self.ledger_path.name + "-wal"),
                self.ledger_path.with_name(self.ledger_path.name + "-shm"),
                self.ledger_path.with_name(self.ledger_path.name + "-journal"),
                self.ledger_path,
                self.ledger_lock_path,
            ):
                _unlink_exact_regular(path)
        except (OSError, RunnerTrustError):
            raise RunnerLifecycleError(
                "Runner transport state could not be removed safely."
            ) from None

    def _remove_stale_process_record(self) -> None:
        try:
            _unlink_exact_regular(self.process_record_path)
        except (OSError, RunnerTrustError):
            raise RunnerLifecycleError("Stale runner process state could not be removed.") from None

    def _stop_exact_failed_launch(self, launch: _LaunchProcess) -> None:
        if not _terminate_contained_launch(launch):
            raise RunnerLifecycleError("Failed runner launch containment could not be confirmed.")

    def _reap_owned_process(self, launch_id: str) -> None:
        process = self._owned_processes.get(launch_id)
        if process is None:
            return
        try:
            process.wait(timeout=0)
        except (OSError, subprocess.TimeoutExpired):
            return
        self._owned_processes.pop(launch_id, None)

    def _public_runner(self, bootstrap: _BootstrapRecord) -> Mapping[str, Any]:
        return {
            "id": self.runner_id,
            "source": bootstrap.source,
            "product_version": bootstrap.product_version,
            "runner_version": bootstrap.runner_version,
            "platform": bootstrap.platform,
            "architecture": bootstrap.architecture,
            "binary_digest": bootstrap.binary_digest,
            "managed_binary": bootstrap.managed_binary,
            "managed_sandbox": bootstrap.managed_sandbox,
            "inventory_schema": bootstrap.inventory_schema,
            "action_sdk_version": bootstrap.action_sdk_version,
            "receipt_protocol": bootstrap.receipt_protocol,
        }

    def _status_payload(
        self,
        *,
        state: str,
        enrollment_state: str,
        process_state: str,
        profile_id: str | None = None,
        runner: Mapping[str, Any] | None = None,
        health: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        return {
            "schema_version": LIFECYCLE_STATUS_SCHEMA_VERSION,
            "state": state,
            "runner_id": self.runner_id,
            "profile_id": profile_id,
            "loopback_only": True,
            "enrollment": enrollment_state,
            "process": process_state,
            "runner": dict(runner) if runner is not None else None,
            "health": dict(health) if health is not None else None,
        }


def _default_command_factory(spec: RunnerHostSpec) -> Sequence[str]:
    return default_host_command(
        enrollment_root=spec.enrollment_root,
        runner_binary=spec.runner_binary,
        work_root=spec.work_root,
        state_path=spec.state_path,
        process_record_path=spec.process_record_path,
        start_gate_path=spec.start_gate_path,
        launch_id=spec.launch_id,
        runner_timeout_seconds=spec.runner_timeout_seconds,
    )


def _spawn_contained_host(command: Sequence[str]) -> _LaunchProcess:
    options: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        options["start_new_session"] = True
    process = subprocess.Popen(command, shell=False, **options)  # nosec B603
    if os.name != "nt":
        return _LaunchProcess(process=process, containment=process.pid)
    try:
        job = _windows_create_kill_job()
        _windows_assign_process(job, process)
        return _LaunchProcess(process=process, containment=job)
    except OSError:
        try:
            process.kill()
            process.wait(timeout=5.0)
        except (OSError, subprocess.TimeoutExpired):
            pass
        raise


def _release_launch_containment(launch: _LaunchProcess) -> None:
    if os.name != "nt" or launch.containment is None:
        launch.containment = None
        return
    job = int(launch.containment)
    _windows_set_job_kill(job, enabled=False)
    _windows_close_handle(job)
    launch.containment = None


def _terminate_contained_launch(launch: _LaunchProcess) -> bool:
    process = launch.process
    if os.name == "nt":
        job = launch.containment
        if job is None:
            return process.poll() is not None
        succeeded = _windows_terminate_job(int(job))
        try:
            process.wait(timeout=5.0)
        except (OSError, subprocess.TimeoutExpired):
            succeeded = False
        succeeded = _windows_wait_job_empty(int(job), timeout_seconds=5.0) and succeeded
        _windows_close_handle(int(job))
        launch.containment = None
        return succeeded and process.poll() is not None

    group = int(launch.containment if launch.containment is not None else process.pid)
    try:
        _kill_process_group(group, int(signal.SIGTERM))
    except ProcessLookupError:
        pass
    except OSError:
        return False
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if not _posix_group_exists(group):
            break
        time.sleep(0.025)
    if _posix_group_exists(group):
        try:
            _kill_process_group(group, int(getattr(signal, "SIGKILL", 9)))
        except ProcessLookupError:
            pass
        except OSError:
            return False
    try:
        process.wait(timeout=5.0)
    except (OSError, subprocess.TimeoutExpired):
        return False
    deadline = time.monotonic() + 5.0
    while _posix_group_exists(group) and time.monotonic() < deadline:
        time.sleep(0.025)
    launch.containment = None
    return not _posix_group_exists(group)


def _posix_group_exists(group: int) -> bool:
    try:
        _kill_process_group(group, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _kill_process_group(group: int, signal_number: int) -> None:
    operation = getattr(os, "killpg", None)
    if not callable(operation):
        raise OSError("process-group signalling is unavailable")
    operation(group, signal_number)


def _windows_create_kill_job() -> int:
    import ctypes
    from ctypes import wintypes

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    create = kernel32.CreateJobObjectW
    create.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    create.restype = wintypes.HANDLE
    job = create(None, None)
    if not job:
        raise OSError("job creation failed")
    value = int(job)
    try:
        limits = _ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x00002000
        set_information = kernel32.SetInformationJobObject
        if not set_information(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise OSError("job configuration failed")
        return value
    except OSError:
        _windows_close_handle(value)
        raise


def _windows_set_job_kill(job: int, *, enabled: bool) -> None:
    import ctypes

    # A zeroed extended limit structure is sufficient when clearing the only
    # limit this module sets. Its native size is stable for the current process.
    buffer = ctypes.create_string_buffer(144 if ctypes.sizeof(ctypes.c_void_p) == 8 else 112)
    if enabled:
        ctypes.c_uint32.from_buffer(buffer, 16).value = 0x00002000
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    if not kernel32.SetInformationJobObject(
        ctypes.c_void_p(job), 9, ctypes.byref(buffer), ctypes.sizeof(buffer)
    ):
        raise OSError("job configuration failed")


def _windows_assign_process(job: int, process: subprocess.Popen[bytes]) -> None:
    import ctypes

    process_handle = getattr(process, "_handle", None)
    if process_handle is None:
        raise OSError("process handle unavailable")
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    if not kernel32.AssignProcessToJobObject(
        ctypes.c_void_p(job), ctypes.c_void_p(int(process_handle))
    ):
        _windows_close_handle(job)
        raise OSError("job assignment failed")


def _windows_terminate_job(job: int) -> bool:
    import ctypes

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    return bool(kernel32.TerminateJobObject(ctypes.c_void_p(job), 1))


def _windows_wait_job_empty(job: int, *, timeout_seconds: float) -> bool:
    import ctypes
    from ctypes import wintypes

    class _Accounting(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_longlong),
            ("TotalKernelTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        value = _Accounting()
        if not kernel32.QueryInformationJobObject(
            ctypes.c_void_p(job),
            1,
            ctypes.byref(value),
            ctypes.sizeof(value),
            None,
        ):
            return False
        if value.ActiveProcesses == 0:
            return True
        time.sleep(0.025)
    return False


def _windows_close_handle(handle: int) -> None:
    import ctypes

    if handle:
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def _local_operation_lock(root: Path) -> threading.RLock:
    key = os.path.normcase(os.path.normpath(str(root)))
    with _LOCAL_OPERATION_LOCKS_GUARD:
        lock = _LOCAL_OPERATION_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCAL_OPERATION_LOCKS[key] = lock
        return lock


class _WindowsPinnedLockHandle:
    """Keep a no-share-delete native pin for the CRT lock stream's lifetime."""

    def __init__(self, stream: Any, native_handle: int) -> None:
        self._stream = stream
        self._native_handle = native_handle

    def fileno(self) -> int:
        return int(self._stream.fileno())

    def seek(self, offset: int) -> int:
        return int(self._stream.seek(offset))

    def write(self, value: bytes) -> int:
        return int(self._stream.write(value))

    def flush(self) -> None:
        self._stream.flush()

    @property
    def closed(self) -> bool:
        return bool(self._stream.closed)

    def close(self) -> None:
        try:
            self._stream.close()
        finally:
            if self._native_handle:
                _windows_close_handle(self._native_handle)
                self._native_handle = 0


def _open_private_lock_file(path: Path) -> tuple[Any, tuple[int, ...]]:
    handle: Any = None
    native_handle: int | None = None
    try:
        if _is_link_or_reparse(path):
            raise OSError("linked operation lock")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        handle = os.fdopen(descriptor, "r+b", buffering=0)
        details = os.fstat(descriptor)
        identity = _descriptor_identity(descriptor)
        if (
            details.st_nlink != 1
            or _is_link_or_reparse(path)
            or _path_descriptor_identity(path) != identity
        ):
            handle.close()
            raise OSError("unsafe operation lock")
        if os.fstat(descriptor).st_size == 0:
            handle.write(b"\0")
            handle.flush()
            os.fsync(descriptor)
        elif os.fstat(descriptor).st_size != 1:
            handle.close()
            raise OSError("invalid operation lock")
        if os.name == "nt":
            native_handle, pinned = _windows_open_pinned_path(
                path,
                directory=False,
                delete_access=False,
            )
            if pinned[2:] != identity or pinned[0] & 0x00000410 or pinned[1] != 1:
                raise OSError("operation lock changed")
            _owner_private(path, directory=False)
            if _windows_handle_details(native_handle) != pinned:
                raise OSError("operation lock changed")
            handle = _WindowsPinnedLockHandle(handle, native_handle)
            native_handle = None
        else:
            _owner_private_open_regular(path, descriptor)
        return handle, identity
    except (OSError, RunnerTrustError):
        if native_handle is not None:
            _windows_close_handle(native_handle)
        if handle is not None and not handle.closed:
            handle.close()
        raise RunnerLifecycleError("Runner lifecycle operation lock is unavailable.") from None


def _lock_file(
    handle: Any,
    *,
    path: Path,
    expected_identity: tuple[int, ...],
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(  # type: ignore[attr-defined]
                    handle.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,  # type: ignore[attr-defined]
                )
            if (
                _descriptor_identity(handle.fileno()) != expected_identity
                or _path_descriptor_identity(path) != expected_identity
            ):
                _unlock_file(handle)
                raise RunnerLifecycleError("Runner lifecycle operation lock changed while waiting.")
            return
        except OSError:
            if time.monotonic() >= deadline:
                raise RunnerLifecycleError(
                    "Runner lifecycle operation is already active."
                ) from None
            time.sleep(0.025)


def _descriptor_identity(descriptor: int) -> tuple[int, ...]:
    if os.name != "nt":
        details = os.fstat(descriptor)
        return int(details.st_dev), int(details.st_ino)

    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    information = _ByHandleFileInformation()
    handle = msvcrt.get_osfhandle(descriptor)
    if handle == -1 or not kernel32.GetFileInformationByHandle(
        ctypes.c_void_p(handle), ctypes.byref(information)
    ):
        raise OSError("file identity is unavailable")
    return (
        int(information.dwVolumeSerialNumber),
        int(information.nFileIndexHigh),
        int(information.nFileIndexLow),
    )


def _path_descriptor_identity(path: Path) -> tuple[int, ...]:
    if _is_link_or_reparse(path):
        raise OSError("linked lock path")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        identity = _descriptor_identity(descriptor)
    finally:
        os.close(descriptor)
    if _is_link_or_reparse(path):
        raise OSError("linked lock path")
    return identity


def _unlock_file(handle: Any) -> None:
    try:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(  # type: ignore[attr-defined]
                handle.fileno(),
                fcntl.LOCK_UN,  # type: ignore[attr-defined]
            )
    except OSError:
        pass


def _root_digest(root: Path) -> str:
    return (
        "sha256:"
        + hashlib.sha256(os.path.normcase(os.path.normpath(str(root))).encode("utf-8")).hexdigest()
    )


def _valid_root_marker(value: Any, runner_id: str, resolved_root: Path) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value) == _ROOT_MARKER_FIELDS
        and value.get("schema_version") == ROOT_MARKER_SCHEMA_VERSION
        and value.get("runner_id") == runner_id
        and value.get("root_digest") == _root_digest(resolved_root)
        and isinstance(value.get("marker_id"), str)
        and _DIGEST.fullmatch("sha256:" + str(value["marker_id"])) is not None
    )


def _broad_root(root: Path) -> bool:
    lexical = os.path.normcase(os.path.normpath(str(root)))
    candidates = {os.path.normcase(os.path.normpath(str(Path(root.anchor))))}
    for provider in (Path.home, Path.cwd):
        try:
            candidate = provider()
        except (OSError, RuntimeError):
            continue
        try:
            candidates.add(os.path.normcase(os.path.normpath(str(candidate.resolve()))))
        except OSError:
            candidates.add(os.path.normcase(os.path.normpath(str(candidate))))
    return lexical in candidates


def _bootstrap_payload(bootstrapped: BootstrappedRunner, runner_id: str) -> dict[str, Any]:
    manifest = bootstrapped.manifest
    return {
        "schema_version": BOOTSTRAP_RECORD_SCHEMA_VERSION,
        "runner_id": runner_id,
        "source": bootstrapped.source,
        "managed_binary": bootstrapped.managed_binary,
        "managed_sandbox": bootstrapped.managed_sandbox,
        "binary_path": str(bootstrapped.binary_path.resolve(strict=True)),
        "sandbox_path": str(bootstrapped.sandbox_path.resolve(strict=True)),
        "binary_digest": "sha256:" + bootstrapped.binary_sha256,
        "product_version": manifest.product_version,
        "runner_version": manifest.runner_version,
        "platform": manifest.platform,
        "architecture": manifest.architecture,
        "inventory_schema": manifest.inventory_schema,
        "action_sdk_version": manifest.action_sdk_version,
        "receipt_protocol": manifest.receipt_protocol,
    }


def _bootstrap_record_payload(record: _BootstrapRecord) -> dict[str, Any]:
    return {
        "schema_version": BOOTSTRAP_RECORD_SCHEMA_VERSION,
        "runner_id": RUNNER_ID,
        "source": record.source,
        "managed_binary": record.managed_binary,
        "managed_sandbox": record.managed_sandbox,
        "binary_path": str(record.binary_path),
        "sandbox_path": str(record.sandbox_path),
        "binary_digest": record.binary_digest,
        "product_version": record.product_version,
        "runner_version": record.runner_version,
        "platform": record.platform,
        "architecture": record.architecture,
        "inventory_schema": record.inventory_schema,
        "action_sdk_version": record.action_sdk_version,
        "receipt_protocol": record.receipt_protocol,
    }


def _canonical_record_path(path: Path) -> Path:
    if not path.is_absolute() or str(path) in {"", ".", ".."}:
        raise OSError("state path is not absolute")
    _reject_linked_ancestors(path)
    resolved = path.resolve(strict=False)
    if not _same_path(path, resolved) or _is_link_or_reparse(path):
        raise OSError("state path is not canonical")
    return resolved


def _record_authentication(enrollment: RunnerEnrollment, payload: Mapping[str, Any]) -> str:
    return (
        "sha256:"
        + hmac.new(
            enrollment.hmac_key(), canonical_json_bytes(dict(payload)), hashlib.sha256
        ).hexdigest()
    )


def _profile_ids(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not values or len(values) > 128:
        raise RunnerLifecycleError("Allowed runner profiles are invalid.")
    profiles = tuple(values)
    if len(set(profiles)) != len(profiles) or any(
        not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None for value in profiles
    ):
        raise RunnerLifecycleError("Allowed runner profiles are invalid.")
    return profiles


def _validated_host_command(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise RunnerLifecycleError("Runner host command is invalid.")
    command = tuple(value)
    if (
        not command
        or len(command) > 64
        or any(not isinstance(item, str) or not item or len(item) > 32768 for item in command)
        or sum(len(item) for item in command) > 128 * 1024
        or not Path(command[0]).is_absolute()
    ):
        raise RunnerLifecycleError("Runner host command is invalid.")
    return command


def _owner_private_pinned(path: Path, *, directory: bool) -> None:
    """Harden the object named by path while pinning its exact identity."""

    if os.name == "nt":
        handle, details = _windows_open_pinned_path(
            path,
            directory=directory,
            delete_access=False,
        )
        try:
            if details[0] & 0x00000400 or (not directory and details[1] != 1):
                raise RunnerTrustError("Managed state is unavailable or unsafe.")
            _owner_private(path, directory=directory)
        finally:
            _windows_close_handle(handle)
        return
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        posix_details = os.fstat(descriptor)
        expected_kind = (
            stat.S_ISDIR(posix_details.st_mode)
            if directory
            else stat.S_ISREG(posix_details.st_mode)
        )
        if not expected_kind or (not directory and posix_details.st_nlink != 1):
            raise RunnerTrustError("Managed state is unavailable or unsafe.")
        mode = 0o700 if directory else 0o600
        fchmod = getattr(os, "fchmod", None)
        if not callable(fchmod):
            raise RunnerTrustError("Managed state permissions could not be restricted.")
        fchmod(descriptor, mode)
        checked = os.fstat(descriptor)
        getuid = getattr(os, "getuid", None)
        if stat.S_IMODE(checked.st_mode) != mode or (
            callable(getuid) and checked.st_uid != getuid()
        ):
            raise RunnerTrustError("Managed state permissions could not be restricted.")
    except OSError:
        raise RunnerTrustError("Managed state permissions could not be restricted.") from None
    finally:
        os.close(descriptor)


def _owner_private_open_regular(path: Path, descriptor: int) -> None:
    details = os.fstat(descriptor)
    if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
        raise RunnerTrustError("Managed state is unavailable or unsafe.")
    identity = _descriptor_identity(descriptor)
    if os.name == "nt":
        handle: int | None = None
        try:
            handle, pinned = _windows_open_pinned_path(
                path,
                directory=False,
                delete_access=False,
            )
            if pinned[2:] != identity or pinned[0] & 0x00000410 or pinned[1] != 1:
                raise RunnerTrustError("Managed state changed while it was opened.")
            # This native handle explicitly denies FILE_SHARE_DELETE, so the
            # path cannot be renamed while the path-based ACL utility runs.
            _owner_private(path, directory=False)
            if _windows_handle_details(handle) != pinned:
                raise RunnerTrustError("Managed state changed while it was hardened.")
        except OSError:
            raise RunnerTrustError("Managed state changed while it was opened.") from None
        finally:
            if handle is not None:
                _windows_close_handle(handle)
        return
    if _path_descriptor_identity(path) != identity:
        raise RunnerTrustError("Managed state changed while it was opened.")
    fchmod = getattr(os, "fchmod", None)
    if not callable(fchmod):
        raise RunnerTrustError("Managed state permissions could not be restricted.")
    fchmod(descriptor, 0o600)
    checked = os.fstat(descriptor)
    getuid = getattr(os, "getuid", None)
    if stat.S_IMODE(checked.st_mode) != 0o600 or (callable(getuid) and checked.st_uid != getuid()):
        raise RunnerTrustError("Managed state permissions could not be restricted.")


def _ensure_private_directory(path: Path, *, expected_parent: Path | None = None) -> Path:
    try:
        _reject_linked_ancestors(path)
        if _is_link_or_reparse(path):
            raise OSError("linked lifecycle directory")
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        resolved = path.resolve(strict=True)
        if (
            _is_link_or_reparse(path)
            or not resolved.is_dir()
            or not _same_path(path, resolved)
            or (expected_parent is not None and resolved.parent != expected_parent)
        ):
            raise OSError("unsafe lifecycle directory")
        _owner_private_pinned(resolved, directory=True)
        return resolved
    except (OSError, RunnerTrustError):
        raise RunnerLifecycleError("Managed runner storage is unavailable or unsafe.") from None


def _reject_linked_ancestors(path: Path) -> None:
    current = path
    while True:
        if current.exists() and _is_link_or_reparse(current):
            raise OSError("linked lifecycle ancestor")
        if current.parent == current:
            return
        current = current.parent


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.normpath(str(left))) == os.path.normcase(
        os.path.normpath(str(right))
    )


def _write_private_json(
    path: Path,
    value: Mapping[str, Any],
    *,
    maximum: int,
    replace: bool,
) -> None:
    payload = canonical_json_bytes(dict(value))
    if not payload or len(payload) > maximum:
        raise RunnerLifecycleError("Managed runner state exceeds its size limit.")
    try:
        _persist_private_payload(path, payload, replace=replace)
    except (OSError, RunnerTrustError):
        raise RunnerLifecycleError("Managed runner state could not be persisted safely.") from None


def _write_private_bytes(path: Path, payload: bytes, *, replace: bool) -> None:
    if not payload or len(payload) > 64 * 1024:
        raise RunnerLifecycleError("Managed runner state exceeds its size limit.")
    try:
        _persist_private_payload(path, payload, replace=replace)
    except (OSError, RunnerTrustError):
        raise RunnerLifecycleError("Managed runner state could not be persisted safely.") from None


def _persist_private_payload(path: Path, payload: bytes, *, replace: bool) -> None:
    # Keep the private staging basename independent of the destination.  Lifecycle
    # destinations such as the one-use host-start gate already carry a 256-bit
    # identifier; repeating that basename here can cross the legacy Windows path
    # limit even when the final destination itself is valid.
    temporary = path.with_name(f".bfstate-{secrets.token_hex(16)}.tmp")
    parent = path.parent.resolve(strict=True)
    if (
        _is_link_or_reparse(parent)
        or not parent.is_dir()
        or not _same_path(path.parent, parent)
        or _is_link_or_reparse(path)
        or _is_link_or_reparse(temporary)
    ):
        raise OSError("unsafe state storage")
    _owner_private_pinned(parent, directory=True)
    if path.exists():
        details = path.stat(follow_symlinks=False)
        if not replace or not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise OSError("unsafe existing state")
        # Replacement is decomposed into exact deletion and no-replace
        # publication so a raced foreign destination is never overwritten.
        _unlink_exact_regular(path)
    if path.exists() or _is_link_or_reparse(path):
        raise OSError("state destination changed")
    if os.name == "nt":
        _windows_publish_private_payload(path, temporary, payload)
    else:
        _posix_publish_private_payload(path, temporary, parent, payload)


def _posix_publish_private_payload(
    path: Path,
    temporary: Path,
    parent: Path,
    payload: bytes,
) -> None:
    parent_descriptor = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    descriptor: int | None = None
    opened: os.stat_result | None = None
    published = False
    try:
        descriptor = os.open(
            temporary.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_descriptor,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _owner_private_open_regular(temporary, descriptor)
        opened = os.fstat(descriptor)
        current = os.stat(
            temporary.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise OSError("state temporary changed")
        os.link(
            temporary.name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        final = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("state publication changed identity")
        published = True
        current = os.stat(
            temporary.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("state temporary changed after publication")
        os.unlink(temporary.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        if not published and descriptor is not None and opened is not None:
            try:
                current = os.stat(
                    temporary.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) == (opened.st_dev, opened.st_ino):
                    os.unlink(temporary.name, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
            except OSError:
                pass
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_descriptor)


def _windows_publish_private_payload(path: Path, temporary: Path, payload: bytes) -> None:
    descriptor: int | None = None
    tracking_handle: int | None = None
    tracking_exact = False
    promoted = False
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _owner_private_open_regular(temporary, descriptor)
        expected = _windows_descriptor_details(descriptor)
        os.close(descriptor)
        descriptor = None
        tracking_handle, tracked = _windows_open_pinned_path(
            temporary,
            directory=False,
            delete_access=True,
        )
        if tracked != expected or tracked[0] & 0x00000410 or tracked[1] != 1:
            raise OSError("state temporary changed")
        tracking_exact = True
        _windows_rename_handle(tracking_handle, path)
        final_handle, final = _windows_open_pinned_path(
            path,
            directory=False,
            delete_access=False,
            share_delete=True,
        )
        try:
            if final != expected:
                raise OSError("state publication changed identity")
        finally:
            _windows_close_handle(final_handle)
        promoted = True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if tracking_handle is not None:
            if tracking_exact and not promoted:
                try:
                    _windows_mark_delete(tracking_handle)
                except OSError:
                    pass
            _windows_close_handle(tracking_handle)


def _read_private_json(path: Path, *, maximum: int, enforce_private: bool = True) -> Any:
    try:
        if _is_link_or_reparse(path):
            raise OSError("linked state")
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError("unsafe state")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise OSError("state changed")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                payload = handle.read(maximum + 1)
            if enforce_private:
                _owner_private_open_regular(path, descriptor)
        finally:
            os.close(descriptor)
        after = path.stat(follow_symlinks=False)
        if (
            not payload
            or len(payload) > maximum
            or _is_link_or_reparse(path)
            or after.st_nlink != 1
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise OSError("state changed")
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
        if canonical_json_bytes(value) != payload:
            raise ValueError("non-canonical state")
        return value
    except (OSError, UnicodeDecodeError, ValueError, RunnerTrustError):
        raise RunnerLifecycleError("Managed runner state is unavailable or invalid.") from None


def _best_effort_unlink(path: Path) -> None:
    try:
        _unlink_exact_regular(path)
    except (OSError, RunnerTrustError):
        pass


def _unlink_exact_regular(path: Path) -> None:
    if os.name == "nt":
        _windows_unlink_exact_regular(path)
        return
    try:
        parent_descriptor = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except FileNotFoundError:
        return
    try:
        try:
            before = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise OSError("unsafe lifecycle state")
        descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise OSError("lifecycle state changed")
            fchmod = getattr(os, "fchmod", None)
            if not callable(fchmod):
                raise OSError("descriptor permission hardening is unavailable")
            fchmod(descriptor, 0o600)
            checked = os.fstat(descriptor)
            getuid = getattr(os, "getuid", None)
            if stat.S_IMODE(checked.st_mode) != 0o600 or (
                callable(getuid) and checked.st_uid != getuid()
            ):
                raise OSError("unsafe lifecycle state owner")
            current = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                raise OSError("lifecycle state changed")
            os.unlink(path.name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)


def _windows_unlink_exact_regular(path: Path) -> None:
    try:
        handle, details = _windows_open_pinned_path(path, directory=False)
    except FileNotFoundError:
        return
    try:
        if details[0] & 0x00000410 or details[1] != 1:
            raise OSError("unsafe lifecycle state")
        # The open handle omits FILE_SHARE_DELETE, pinning this exact path while
        # ACL hardening runs and while deletion is marked on the same handle.
        _owner_private(path, directory=False)
        if _windows_handle_details(handle) != details:
            raise OSError("lifecycle state changed")
        _windows_mark_delete(handle)
    finally:
        _windows_close_handle(handle)


def _windows_open_pinned_path(
    path: Path,
    *,
    directory: bool,
    delete_access: bool = True,
    share_delete: bool = False,
) -> tuple[int, tuple[int, ...]]:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    create = kernel32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    flags = 0x00200000 | (0x02000000 if directory else 0)
    desired_access = 0x00020000 | 0x00000080
    if delete_access:
        desired_access |= 0x00010000
    share_mode = 0x00000001 | 0x00000002
    if share_delete:
        share_mode |= 0x00000004
    raw_handle = create(
        str(path),
        desired_access,
        share_mode,
        None,
        3,
        flags,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if not raw_handle or int(raw_handle) == invalid:
        error = ctypes.get_last_error()
        if error in {2, 3}:
            raise FileNotFoundError(error, "path is absent")
        raise OSError(error, "path handle is unavailable")
    handle = int(raw_handle)
    try:
        details = _windows_handle_details(handle)
    except OSError:
        _windows_close_handle(handle)
        raise
    is_directory = bool(details[0] & 0x00000010)
    if is_directory is not directory:
        _windows_close_handle(handle)
        raise OSError("path kind changed")
    return handle, details


def _windows_handle_details(handle: int) -> tuple[int, int, int, int, int]:
    import ctypes
    from ctypes import wintypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    information = _ByHandleFileInformation()
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ByHandleFileInformation)]
    get_information.restype = wintypes.BOOL
    if not get_information(ctypes.c_void_p(handle), ctypes.byref(information)):
        raise OSError(ctypes.get_last_error(), "path identity is unavailable")
    return (
        int(information.dwFileAttributes),
        int(information.nNumberOfLinks),
        int(information.dwVolumeSerialNumber),
        int(information.nFileIndexHigh),
        int(information.nFileIndexLow),
    )


def _windows_descriptor_details(descriptor: int) -> tuple[int, int, int, int, int]:
    import msvcrt

    handle = msvcrt.get_osfhandle(descriptor)
    if handle == -1:
        raise OSError("file identity is unavailable")
    return _windows_handle_details(handle)


def _windows_rename_handle(handle: int, destination: Path) -> None:
    import ctypes
    from ctypes import wintypes

    destination_text = str(destination)

    class _RenameInformation(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", ctypes.c_wchar * (len(destination_text) + 1)),
        ]

    value = _RenameInformation()
    value.Flags = 0
    value.RootDirectory = None
    value.FileNameLength = len(destination_text.encode("utf-16-le"))
    value.FileName = destination_text
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    operation = kernel32.SetFileInformationByHandle
    operation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    operation.restype = wintypes.BOOL
    if not operation(ctypes.c_void_p(handle), 3, ctypes.byref(value), ctypes.sizeof(value)):
        raise OSError(ctypes.get_last_error(), "state could not be promoted safely")


def _windows_path_identity(path: Path) -> tuple[int, int, int]:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:

        class _ByHandleFileInformation(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", wintypes.DWORD),
                ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME),
                ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD),
                ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            ]

        information = _ByHandleFileInformation()
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
        if not kernel32.GetFileInformationByHandle(
            ctypes.c_void_p(msvcrt.get_osfhandle(descriptor)), ctypes.byref(information)
        ):
            raise OSError("path identity is unavailable")
        return (
            int(information.dwVolumeSerialNumber),
            int(information.nFileIndexHigh),
            int(information.nFileIndexLow),
        )
    finally:
        os.close(descriptor)


def _windows_mark_delete(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    class _Disposition(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOL)]

    value = _Disposition(True)
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)  # type: ignore[attr-defined]
    operation = kernel32.SetFileInformationByHandle
    operation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    operation.restype = wintypes.BOOL
    if not operation(ctypes.c_void_p(handle), 4, ctypes.byref(value), ctypes.sizeof(value)):
        raise OSError(ctypes.get_last_error(), "path could not be deleted safely")


def _remove_result_namespace(root: Path, *, expected_parent: Path) -> None:
    """Remove only one exact, strictly shaped, inactive result namespace."""

    if os.name == "nt":
        _windows_remove_result_namespace(root, expected_parent=expected_parent)
        return
    parent_descriptor = os.open(
        expected_parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    namespace_descriptor: int | None = None
    try:
        if not _same_path(expected_parent, expected_parent.resolve(strict=True)):
            raise OSError("result parent identity changed")
        namespace_before = os.stat(
            root.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISDIR(namespace_before.st_mode):
            raise OSError("unsafe result namespace")
        namespace_descriptor = os.open(
            root.name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(namespace_descriptor)
        if (opened.st_dev, opened.st_ino) != (
            namespace_before.st_dev,
            namespace_before.st_ino,
        ):
            raise OSError("result namespace changed")
        for name in tuple(os.listdir(namespace_descriptor)):
            if _DURABLE_RESULT_NAME.fullmatch(name) is None:
                raise OSError("unexpected result state")
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=namespace_descriptor,
            )
            try:
                details = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(details.st_mode)
                    or details.st_nlink != 1
                    or details.st_size > 8 * 1024 * 1024
                ):
                    raise OSError("unsafe result file")
                fchmod = getattr(os, "fchmod", None)
                if not callable(fchmod):
                    raise OSError("descriptor permission hardening is unavailable")
                fchmod(descriptor, 0o600)
                current = os.stat(
                    name,
                    dir_fd=namespace_descriptor,
                    follow_symlinks=False,
                )
                if (current.st_dev, current.st_ino) != (details.st_dev, details.st_ino):
                    raise OSError("result file changed")
                os.unlink(name, dir_fd=namespace_descriptor)
            finally:
                os.close(descriptor)
        os.fsync(namespace_descriptor)
        current_namespace = os.stat(
            root.name,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        if (current_namespace.st_dev, current_namespace.st_ino) != (
            opened.st_dev,
            opened.st_ino,
        ):
            raise OSError("result namespace changed")
        os.rmdir(root.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        if namespace_descriptor is not None:
            os.close(namespace_descriptor)
        os.close(parent_descriptor)


def _remove_empty_exact_directory(path: Path, *, expected_parent: Path) -> None:
    if path.parent != expected_parent:
        raise OSError("directory escaped expected parent")
    if os.name == "nt":
        parent_handle, parent_details = _windows_open_pinned_path(
            expected_parent,
            directory=True,
        )
        directory_handle: int | None = None
        try:
            if parent_details[0] & 0x00000400:
                raise OSError("unsafe directory parent")
            directory_handle, details = _windows_open_pinned_path(path, directory=True)
            if details[0] & 0x00000400 or any(path.iterdir()):
                raise OSError("directory is unsafe or not empty")
            _owner_private(path, directory=True)
            _windows_mark_delete(directory_handle)
        finally:
            if directory_handle is not None:
                _windows_close_handle(directory_handle)
            _windows_close_handle(parent_handle)
        return
    parent_descriptor = os.open(
        expected_parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    directory_descriptor: int | None = None
    try:
        before = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise OSError("unsafe directory")
        directory_descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(directory_descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or os.listdir(
            directory_descriptor
        ):
            raise OSError("directory changed or is not empty")
        current = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("directory changed")
        os.rmdir(path.name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        os.close(parent_descriptor)


def _windows_remove_result_namespace(root: Path, *, expected_parent: Path) -> None:
    parent_handle, parent_details = _windows_open_pinned_path(
        expected_parent,
        directory=True,
    )
    namespace_handle: int | None = None
    try:
        if parent_details[0] & 0x00000400:
            raise OSError("unsafe result parent")
        namespace_handle, namespace_details = _windows_open_pinned_path(
            root,
            directory=True,
        )
        if namespace_details[0] & 0x00000400 or root.parent != expected_parent:
            raise OSError("unsafe result namespace")
        for entry in tuple(root.iterdir()):
            if _DURABLE_RESULT_NAME.fullmatch(entry.name) is None:
                raise OSError("unexpected result state")
            details = entry.stat(follow_symlinks=False)
            if details.st_size > 8 * 1024 * 1024:
                raise OSError("unsafe result file")
            _windows_unlink_exact_regular(entry)
        if any(root.iterdir()):
            raise OSError("result namespace changed")
        _owner_private(root, directory=True)
        _windows_mark_delete(namespace_handle)
    finally:
        if namespace_handle is not None:
            _windows_close_handle(namespace_handle)
        _windows_close_handle(parent_handle)


def _strict_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _sync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "BOOTSTRAP_RECORD_SCHEMA_VERSION",
    "CLIENT_ID",
    "HostCommandFactory",
    "LIFECYCLE_STATUS_SCHEMA_VERSION",
    "ManagedRunnerLifecycle",
    "RunnerHostSpec",
    "RunnerLifecycleError",
]
