"""Configured S3 host-to-watchdog admission and separate temporary-material FD.

The enrolled local host account and fixed packaged code are trusted. These
sealed inherited channels prevent plans/data from creating authority; they do
not isolate secrets from malicious processes running as that same local user.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .runner_transport_errors import RunnerTransportError
from .s3_access_admission import ACTION, PROTOCOL, S3HostAdmission, approved_request
from .s3_access_host_config import read_configuration, selected_environment, temporary_material
from .service_launch import (
    _configured_host_enrollment,
    _enrollment_issuer,
    _process_identity,
    _read_sealed,
    _resolved_secret_state_home,
    _sealed_descriptor,
)
from .util import canonical_json_bytes, content_hash

_ENV = ("BLUEFIRE_S3_CONTEXT_FD", "BLUEFIRE_S3_ENVELOPE_FD", "BLUEFIRE_S3_CREDENTIALS_FD")
_CONTEXT = {
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


def _refuse() -> RunnerTransportError:
    return RunnerTransportError("Protected S3 launch admission is unavailable.")


@dataclass(frozen=True, repr=False)
class S3LaunchIntent:
    """Authenticated transport context, independently checked by the host."""

    issuer: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"issuer": dict(self.issuer)}


def _key(enrollment, admission: S3HostAdmission) -> bytes:
    return hmac.new(
        enrollment.hmac_key(),
        PROTOCOL.encode("ascii")
        + b"\0"
        + canonical_json_bytes(
            {
                "issuer": _enrollment_issuer(enrollment),
                "admission": admission.digest,
            }
        ),
        hashlib.sha256,
    ).digest()


class S3Launch:
    """Owned descriptors; deliberately absent from JSON/argv/public results."""

    def __init__(self, descriptors: tuple[int, int, int], state_home: str):
        self._fds = descriptors
        self._state_home = state_home

    @property
    def descriptors(self) -> tuple[int, int, int]:
        if len(set(self._fds)) != 3 or any(fd <= 2 for fd in self._fds):
            raise _refuse()
        for fd in self._fds:
            _read_sealed(fd)
        return self._fds

    @property
    def environment(self) -> dict[str, str]:
        return {
            **dict(zip(_ENV, map(str, self.descriptors), strict=True)),
            "XDG_STATE_HOME": self._state_home,
        }

    def close(self) -> None:
        descriptors, self._fds = self._fds, (-1, -1, -1)
        failed = False
        for fd in descriptors:
            if fd > 2:
                try:
                    os.close(fd)
                except OSError:
                    failed = True
        if failed:
            raise _refuse()


def _channels(context: Mapping[str, Any], envelope: bytes, material: bytes) -> S3Launch:
    state_home = _resolved_secret_state_home()
    descriptors: list[int] = []
    try:
        for payload in (canonical_json_bytes(context), envelope, material):
            descriptors.append(_sealed_descriptor(payload))
        return S3Launch((descriptors[0], descriptors[1], descriptors[2]), state_home)
    except BaseException:
        for fd in descriptors:
            os.close(fd)
        raise


def _current_material(enrollment, manifest, profile, task_id, now):
    request, workflow = approved_request(manifest, profile, task_id=task_id, now=now)
    configuration = read_configuration(enrollment)
    if configuration is None:
        raise _refuse()
    entry = selected_environment(configuration, request, workflow, profile)
    material = temporary_material(enrollment, entry, request, lambda: now)
    return configuration, material


class ConfiguredS3LaunchAuthority:
    def __init__(self, enrollment_root: Path, secret_provider) -> None:
        self._root, self._provider = enrollment_root, secret_provider

    def prepare(
        self,
        intent: S3LaunchIntent,
        manifest: Mapping[str, Any],
        profile: Mapping[str, Any],
        *,
        task_id: str,
        runner_digest: str,
        watchdog_digest: str,
        interpreter_digest: str,
    ) -> S3Launch:
        if not sys.platform.startswith("linux") or not isinstance(intent, S3LaunchIntent):
            raise _refuse()
        try:
            now = datetime.now(timezone.utc)
            approved_request(manifest, profile, task_id=task_id, now=now)
            enrollment = _configured_host_enrollment(
                os.getpid(),
                admission=intent,
                profile=profile,
                runner_digest=runner_digest,
                expected_root=self._root,
                secret_provider=self._provider,
            )
            issuer = _enrollment_issuer(enrollment)
            actual_issuer = dict(intent.issuer)
            actual_issuer.pop("server_instance_id")
            if actual_issuer != issuer:
                raise _refuse()
            configuration, material = _current_material(enrollment, manifest, profile, task_id, now)
            admission = S3HostAdmission.issue(
                issuer=intent.issuer,
                configuration=configuration,
                manifest=manifest,
                profile=profile,
                task_id=task_id,
                runner_digest=runner_digest,
                credential_digest="sha256:" + hashlib.sha256(material).hexdigest(),
                owner_uid=os.getuid(),
                now=now,
            )
            key = _key(enrollment, admission)
            envelope = canonical_json_bytes(
                {
                    "admission": admission.to_dict(),
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
            return _channels(context, envelope, material)
        except (OSError, ValueError, KeyError, TypeError, RuntimeError):
            raise _refuse() from None


def consume_s3_launch(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    *,
    task_id: str,
    runner_digest: str,
    watchdog_digest: str,
    interpreter_digest: str,
) -> S3Launch | None:
    """Watchdog reopens enrollment, scope and temporary material before reissuing."""
    values = [os.environ.pop(name, None) for name in _ENV]
    if values == [None, None, None]:
        if manifest.get("action_id") == ACTION:
            raise _refuse()
        return None
    descriptors: list[int] = []
    issued = None
    try:
        if not sys.platform.startswith("linux") or any(value is None for value in values):
            raise _refuse()
        descriptors = [int(str(value)) for value in values]
        if len(set(descriptors)) != 3 or any(fd <= 2 for fd in descriptors):
            raise _refuse()
        parent = os.getppid()
        context_raw, envelope_raw, material = [
            _read_sealed(fd, parent=parent) for fd in descriptors
        ]
        context, envelope = json.loads(context_raw), json.loads(envelope_raw)
        if (
            set(context) != _CONTEXT
            or set(envelope) != {"admission", "authentication"}
            or canonical_json_bytes(context) != context_raw
            or canonical_json_bytes(envelope) != envelope_raw
            or context["schema_version"] != PROTOCOL
            or context["stage"] != "host"
            or context["parent"] != _process_identity(parent)
            or context["runner_digest"] != runner_digest
            or context["watchdog_digest"] != watchdog_digest
            or context["interpreter_digest"] != interpreter_digest
            or _process_identity(os.getpid())["executable_digest"] != interpreter_digest
            or context["envelope_digest"] != "sha256:" + hashlib.sha256(envelope_raw).hexdigest()
        ):
            raise _refuse()
        admission = S3HostAdmission(canonical_json_bytes(envelope["admission"]))
        enrollment = _configured_host_enrollment(
            parent, admission=admission, profile=profile, runner_digest=runner_digest
        )
        issuer = _enrollment_issuer(enrollment)
        actual_issuer = admission.to_dict()["issuer"]
        public_issuer = dict(actual_issuer)
        public_issuer.pop("server_instance_id")
        if (
            public_issuer != issuer
            or context["issuer"] != issuer
            or context["enrollment_digest"] != content_hash(issuer)
        ):
            raise _refuse()
        key = _key(enrollment, admission)
        if not hmac.compare_digest(context["key"], key.hex()) or not hmac.compare_digest(
            envelope["authentication"],
            hmac.new(key, admission.canonical_bytes(), hashlib.sha256).hexdigest(),
        ):
            raise _refuse()
        now = datetime.now(timezone.utc)
        configuration, expected_material = _current_material(
            enrollment, manifest, profile, task_id, now
        )
        if not hmac.compare_digest(material, expected_material):
            raise _refuse()
        admission.recheck(
            issuer=actual_issuer,
            configuration=configuration,
            manifest=manifest,
            profile=profile,
            task_id=task_id,
            runner_digest=runner_digest,
            credential_digest="sha256:" + hashlib.sha256(material).hexdigest(),
            owner_uid=os.getuid(),
            now=now,
        )
        context["stage"], context["parent"] = "watchdog", _process_identity(os.getpid())
        issued = _channels(context, envelope_raw, material)
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
        if close_failed:
            if issued is not None:
                try:
                    issued.close()
                except RunnerTransportError:
                    pass
            raise _refuse() from None
    return issued
