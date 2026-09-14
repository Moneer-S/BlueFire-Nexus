"""Canonical bootstrap-record representation and authentication, without lifecycle actions."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .runner_bootstrap import RUNNER_ID, BootstrappedRunner
from .runner_host import RunnerHostError
from .runner_trust import RunnerEnrollment, RunnerTrustError
from .util import canonical_json_bytes, file_hash

BOOTSTRAP_RECORD_SCHEMA_VERSION = "bluefire.runner-lifecycle-bootstrap.v1"


def lifecycle_root_digest(root: Path) -> str:
    return (
        "sha256:"
        + hashlib.sha256(os.path.normcase(os.path.normpath(str(root))).encode("utf-8")).hexdigest()
    )


def validated_profile_ids(values: Sequence[str], *, error: type[RuntimeError]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not values or len(values) > 128:
        raise error("Allowed runner profiles are invalid.")
    profiles = tuple(values)
    if len(set(profiles)) != len(profiles) or any(
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", value) is None
        for value in profiles
    ):
        raise error("Allowed runner profiles are invalid.")
    return profiles


def selected_profile_id(
    profiles: Sequence[str], requested: str | None, *, error: type[RuntimeError]
) -> str:
    """Select diagnostics within the already validated, unchanged profile set."""
    selected = profiles[0] if requested is None else requested
    if (
        not isinstance(selected, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", selected) is None
        or selected not in profiles
    ):
        raise error("Runner profile is not enrolled.")
    return selected


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


def _record_authentication(enrollment: RunnerEnrollment, payload: Mapping[str, Any]) -> str:
    return (
        "sha256:"
        + hmac.new(
            enrollment.hmac_key(), canonical_json_bytes(dict(payload)), hashlib.sha256
        ).hexdigest()
    )


_BOOTSTRAP_FIELDS = frozenset(
    {
        "product_version",
        "authentication",
        "platform",
        "architecture",
        "receipt_protocol",
        "schema_version",
        "managed_binary",
        "runner_id",
        "source",
        "binary_path",
        "runner_version",
        "sandbox_path",
        "inventory_schema",
        "managed_sandbox",
        "action_sdk_version",
        "binary_digest",
    }
)
BOOTSTRAP_RECORD_MAX_BYTES = 64 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class BootstrapRecordValidator:
    """Validate immutable bootstrap records through the caller's pinned I/O seams."""

    runner_id: str
    runtime_root: Path
    bootstrap_record_path: Path
    read: Callable[..., Any]
    canonical_path: Callable[[Path], Path]
    error: type[RuntimeError]

    def _parse_bootstrap_record(self, enrollment: RunnerEnrollment) -> _BootstrapRecord:
        try:
            value = self.read(
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
            binary = self.canonical_path(Path(value["binary_path"]))
            sandbox = self.canonical_path(Path(value["sandbox_path"]))
            runtime = self.canonical_path(self.runtime_root)
            if value["managed_binary"] and not binary.is_relative_to(runtime):
                raise OSError("managed binary escaped runtime root")
            if value["managed_sandbox"] and not sandbox.is_relative_to(runtime):
                raise OSError("managed sandbox escaped runtime root")
        except (OSError, ValueError, KeyError, RunnerHostError, RunnerTrustError):
            raise self.error("Managed runner bootstrap state is unavailable.") from None
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

    def _require_live_bootstrap(self, record: _BootstrapRecord) -> _BootstrapRecord:
        try:
            binary = self.canonical_path(record.binary_path)
            sandbox = self.canonical_path(record.sandbox_path)
            if (
                not binary.is_file()
                or not sandbox.is_dir()
                or not os.access(sandbox, os.W_OK)
                or file_hash(binary) != record.binary_digest
            ):
                raise OSError("bootstrap artifact changed")
        except OSError:
            raise self.error("Managed runner artifacts are unavailable.") from None
        return record

    def _validated_bootstrap_payload(self, bootstrapped: BootstrappedRunner) -> dict[str, Any]:
        if bootstrapped.manifest.runner_id != self.runner_id:
            raise self.error("Bootstrapped runner identity is incompatible.")
        try:
            binary = self.canonical_path(Path(bootstrapped.binary_path))
            sandbox = self.canonical_path(Path(bootstrapped.sandbox_path))
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
            raise self.error("Bootstrapped runner artifacts are invalid.") from None

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
