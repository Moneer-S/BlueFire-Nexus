"""Canonical bootstrap-record representation and authentication, without lifecycle actions."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .runner_bootstrap import RUNNER_ID, BootstrappedRunner
from .runner_trust import RunnerEnrollment
from .util import canonical_json_bytes

BOOTSTRAP_RECORD_SCHEMA_VERSION = "bluefire.runner-lifecycle-bootstrap.v1"


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
