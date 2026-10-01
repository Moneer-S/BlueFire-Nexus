"""Host-enrolled, inherited admission for the fixed Linux service boundary.

The local account running the configured host and packaged watchdog is trusted.
A sealed data document is not authority: enrollment-derived secret context is
issued separately by the configured host and both descriptors stay outside the
manifest, watchdog JSON configuration, filesystem and public CLI grammar.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Mapping

from .owned_service_authority import (
    OwnedServiceAdmission,
    OwnedServiceGrant,
    validate_owned_service_grant_for_request,
)
from .runner_host_identity import read_pinned_process_record
from .runner_transport_errors import RunnerTransportError
from .runner_trust import RunnerEnrollment, load_local_enrollment
from .secret_store import SecretProvider
from .util import canonical_json_bytes, content_hash, file_hash

SERVICE_ACTION_ID = "owned.user_service.fixed_wait.v1"
PROTOCOL = "bluefire.owned-user-service-launch.v1"
_CONTEXT_ENV = "BLUEFIRE_SERVICE_CONTEXT_FD"
_ENVELOPE_ENV = "BLUEFIRE_SERVICE_ENVELOPE_FD"
_MAX_BYTES = 64 * 1024
_DOMAIN = b"bluefire.owned-user-service-launch.v1\0"


def _refuse() -> RunnerTransportError:
    return RunnerTransportError("Protected owned-service launch admission is unavailable.")


def _process_identity(pid: int) -> dict[str, Any]:
    root = Path(f"/proc/{pid}")
    raw = (root / "stat").read_bytes()
    if len(raw) > 4096:
        raise _refuse()
    fields = raw[raw.rfind(b")") + 2 :].split()
    return {
        "pid": pid,
        "start_ticks": int(fields[19]),
        "executable_digest": file_hash(root / "exe"),
    }


def _configured_host_arguments(pid: int) -> dict[str, str]:
    """Read the actual managed-host invocation, never an admission-supplied path."""
    with Path(f"/proc/{pid}/cmdline").open("rb") as source:
        raw = source.read(8193)
    return _parse_host_arguments(raw)


def _parse_host_arguments(raw: bytes) -> dict[str, str]:
    fields = raw.split(b"\0")
    expected_flags = (
        "--enrollment-root",
        "--runner-binary",
        "--work-root",
        "--state-path",
        "--process-record-path",
        "--start-gate-path",
        "--launch-id",
        "--runner-timeout-seconds",
    )
    if (
        len(raw) > 8192
        or not raw.endswith(b"\0")
        or len(fields) != 21
        or fields[1:4] != [b"-I", b"-m", b"bluefire.runner_host"]
    ):
        raise _refuse()
    arguments = [os.fsdecode(field) for field in fields[:-1]]
    if tuple(arguments[4::2]) != expected_flags or any(not field for field in arguments):
        raise _refuse()
    return dict(zip(expected_flags, arguments[5::2], strict=True))


def _configured_host_enrollment(
    pid: int,
    *,
    admission: OwnedServiceAdmission,
    profile: Mapping[str, Any],
    runner_digest: str,
    expected_root: Path | None = None,
    secret_provider: SecretProvider | None = None,
) -> RunnerEnrollment:
    before = _process_identity(pid)
    arguments = _configured_host_arguments(pid)
    enrollment = load_local_enrollment(
        arguments["--enrollment-root"], secret_provider=secret_provider
    )
    if expected_root is not None and enrollment.root != expected_root.resolve(strict=True):
        raise _refuse()
    record = read_pinned_process_record(
        arguments["--process-record-path"],
        enrollment=enrollment,
        expected_binary_digest=runner_digest,
    )
    document = admission.to_dict()
    if (
        record["pid"] != pid
        or record["launch_id"] != arguments["--launch-id"]
        or record["server_instance_id"] != document["issuer"]["server_instance_id"]
        or file_hash(Path(arguments["--runner-binary"])) != runner_digest
        or profile.get("profile_id") not in enrollment.allowed_profile_ids
        or _process_identity(pid) != before
    ):
        raise _refuse()
    return enrollment


def _enrollment_issuer(enrollment: RunnerEnrollment) -> dict[str, str]:
    public = {
        "runner_id": enrollment.runner_id,
        "client_id": enrollment.client_id,
        **{
            name: str(enrollment.metadata[name])
            for name in ("ca_fingerprint", "server_fingerprint", "client_fingerprint")
        },
    }
    return {
        "runner_id": enrollment.runner_id,
        "client_id": enrollment.client_id,
        "enrollment_generation": content_hash(public),
        "peer_fingerprint": public["client_fingerprint"],
    }


def _admission_key(enrollment: RunnerEnrollment, admission: OwnedServiceAdmission) -> bytes:
    return hmac.new(
        enrollment.hmac_key(),
        _DOMAIN
        + canonical_json_bytes(
            {"issuer": _enrollment_issuer(enrollment), "admission": admission.digest}
        ),
        hashlib.sha256,
    ).digest()


def _linux_member(module: Any, name: str) -> Any:
    member = getattr(module, name, None)
    if not sys.platform.startswith("linux") or member is None:
        raise _refuse()
    return member


def _sealed_descriptor(payload: bytes) -> int:
    import fcntl

    if not payload or len(payload) > _MAX_BYTES:
        raise _refuse()
    fd = int(
        _linux_member(os, "memfd_create")(
            "bluefire-service-launch",
            _linux_member(os, "MFD_CLOEXEC") | _linux_member(os, "MFD_ALLOW_SEALING"),
        )
    )
    try:
        _linux_member(os, "fchmod")(fd, 0o600)
        with os.fdopen(os.dup(fd), "wb") as output:
            output.write(payload)
        _linux_member(fcntl, "fcntl")(fd, _linux_member(fcntl, "F_ADD_SEALS"), 0xF)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_sealed(fd: int, *, parent: int | None = None) -> bytes:
    import fcntl

    details = os.fstat(fd)
    if (
        fd <= 2
        or not stat.S_ISREG(details.st_mode)
        or details.st_uid != _linux_member(os, "getuid")()
        or _linux_member(os, "getuid")() != _linux_member(os, "geteuid")()
        or details.st_nlink != 0
        or stat.S_IMODE(details.st_mode) != 0o600
        or not 0 < details.st_size <= _MAX_BYTES
        or _linux_member(fcntl, "fcntl")(fd, _linux_member(fcntl, "F_GET_SEALS")) & 0xF != 0xF
    ):
        raise _refuse()
    if parent is not None:
        inherited = Path(f"/proc/{parent}/fd/{fd}").stat()
        if (inherited.st_dev, inherited.st_ino) != (details.st_dev, details.st_ino):
            raise _refuse()
    value = bytes(_linux_member(os, "pread")(fd, _MAX_BYTES + 1, 0))
    if len(value) != details.st_size:
        raise _refuse()
    return value


class ServiceLaunch:
    """Owned inherited descriptors; never serialize this object or its secret."""

    def __init__(self, context_fd: int, envelope_fd: int) -> None:
        self._fds = (context_fd, envelope_fd)
        # Preserve only this normal product configuration for the watchdog's
        # independent OS-protected enrollment read. No secret value is inherited.
        self._secret_state_home = os.environ.get("XDG_STATE_HOME")

    @property
    def descriptors(self) -> tuple[int, int]:
        if self._fds[0] <= 2 or self._fds[0] == self._fds[1]:
            raise _refuse()
        for fd in self._fds:
            _read_sealed(fd)
        return self._fds

    @property
    def environment(self) -> dict[str, str]:
        first, second = self.descriptors
        environment = {_CONTEXT_ENV: str(first), _ENVELOPE_ENV: str(second)}
        if self._secret_state_home:
            if not Path(self._secret_state_home).is_absolute():
                raise _refuse()
            environment["XDG_STATE_HOME"] = self._secret_state_home
        return environment

    def close(self) -> None:
        descriptors, self._fds = self._fds, (-1, -1)
        failure = None
        for fd in descriptors:
            if fd > 2:
                try:
                    os.close(fd)
                except OSError as exc:
                    failure = exc
        if failure is not None:
            raise _refuse() from None


def _channels(context: Mapping[str, Any], envelope: bytes) -> ServiceLaunch:
    first = _sealed_descriptor(canonical_json_bytes(context))
    try:
        return ServiceLaunch(first, _sealed_descriptor(envelope))
    except BaseException:
        os.close(first)
        raise


class ConfiguredServiceLaunchAuthority:
    """Only a configured managed host supplies the enrollment root/provider."""

    def __init__(self, enrollment_root: Path, secret_provider: SecretProvider | None) -> None:
        self._root = enrollment_root
        self._provider = secret_provider

    def prepare(
        self,
        admission: OwnedServiceAdmission,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        runner_digest: str,
        watchdog_digest: str,
        interpreter_digest: str,
    ) -> ServiceLaunch:
        if not sys.platform.startswith("linux") or not isinstance(admission, OwnedServiceAdmission):
            raise _refuse()
        try:
            enrollment = _configured_host_enrollment(
                os.getpid(),
                admission=admission,
                profile=profile,
                runner_digest=runner_digest,
                expected_root=self._root,
                secret_provider=self._provider,
            )
            issuer = _enrollment_issuer(enrollment)
            document = admission.to_dict()
            actual_issuer = dict(document["issuer"])
            actual_issuer.pop("server_instance_id")
            if (
                actual_issuer != issuer
                or profile.get("profile_id") not in enrollment.allowed_profile_ids
            ):
                raise _refuse()
            validate_owned_service_grant_for_request(
                OwnedServiceGrant.from_mapping(document["grant"]),
                manifest=manifest,
                profile=profile,
                task_id=task_id,
            )
            key = _admission_key(enrollment, admission)
            # Secret context and authenticated document are distinct descriptors.
            envelope = canonical_json_bytes(
                {
                    "admission": document,
                    "authentication": hmac.new(
                        key, admission.canonical_bytes(), hashlib.sha256
                    ).hexdigest(),
                }
            )
            context = {
                "schema_version": PROTOCOL,
                "stage": "host",
                "issuer": issuer,
                "enrollment_digest": content_hash(issuer),
                "key": key.hex(),
                "envelope_digest": "sha256:" + hashlib.sha256(envelope).hexdigest(),
                "parent": _process_identity(os.getpid()),
                "runner_digest": runner_digest,
                "watchdog_digest": watchdog_digest,
                "interpreter_digest": interpreter_digest,
            }
            return _channels(context, envelope)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError):
            raise _refuse() from None


def consume_service_launch(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    task_id: str,
    runner_digest: str,
    watchdog_digest: str,
    interpreter_digest: str,
) -> ServiceLaunch | None:
    """Packaged watchdog-only transition from configured host to native parent."""
    values = [os.environ.pop(name, None) for name in (_CONTEXT_ENV, _ENVELOPE_ENV)]
    if values == [None, None]:
        if manifest.get("action_id") == SERVICE_ACTION_ID:
            raise _refuse()
        return None
    descriptors: list[int] = []
    issued: ServiceLaunch | None = None
    try:
        if not sys.platform.startswith("linux") or any(value is None for value in values):
            raise _refuse()
        descriptors = [int(str(value)) for value in values]
        if len(set(descriptors)) != 2 or any(fd <= 2 for fd in descriptors):
            raise _refuse()
        parent = os.getppid()
        context_raw, envelope_raw = [_read_sealed(fd, parent=parent) for fd in descriptors]
        context, envelope = json.loads(context_raw), json.loads(envelope_raw)
        if (
            set(context)
            != {
                "schema_version",
                "stage",
                "issuer",
                "enrollment_digest",
                "key",
                "envelope_digest",
                "parent",
                "runner_digest",
                "watchdog_digest",
                "interpreter_digest",
            }
            or set(envelope) != {"admission", "authentication"}
            or canonical_json_bytes(context) != context_raw
            or canonical_json_bytes(envelope) != envelope_raw
            or context.get("schema_version") != PROTOCOL
            or context.get("stage") != "host"
            or context.get("parent") != _process_identity(parent)
            or context.get("runner_digest") != runner_digest
            or context.get("watchdog_digest") != watchdog_digest
            or context.get("interpreter_digest") != interpreter_digest
            or _process_identity(os.getpid())["executable_digest"] != interpreter_digest
            or context.get("envelope_digest")
            != "sha256:" + hashlib.sha256(envelope_raw).hexdigest()
        ):
            raise _refuse()
        admission = OwnedServiceAdmission.from_mapping(envelope["admission"])
        enrollment = _configured_host_enrollment(
            parent,
            admission=admission,
            profile=profile,
            runner_digest=runner_digest,
        )
        issuer = dict(admission.to_dict()["issuer"])
        issuer.pop("server_instance_id")
        if (
            issuer != _enrollment_issuer(enrollment)
            or context["issuer"] != issuer
            or context["enrollment_digest"] != content_hash(issuer)
        ):
            raise _refuse()
        key = _admission_key(enrollment, admission)
        if not hmac.compare_digest(context["key"], key.hex()):
            raise _refuse()
        expected = hmac.new(key, admission.canonical_bytes(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, envelope["authentication"]):
            raise _refuse()
        validate_owned_service_grant_for_request(
            OwnedServiceGrant.from_mapping(admission.to_dict()["grant"]),
            manifest=manifest,
            profile=profile,
            task_id=task_id,
        )
        context["stage"] = "watchdog"
        context["parent"] = _process_identity(os.getpid())
        issued = _channels(context, envelope_raw)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        raise _refuse() from None
    finally:
        close_failed = False
        for fd in set(descriptors):
            if fd > 2:
                try:
                    os.close(fd)
                except OSError:
                    close_failed = True
        if close_failed and issued is not None:
            try:
                issued.close()
            except RunnerTransportError:
                pass
            raise _refuse() from None
    return issued
