"""Authenticated managed-host identity shared by host and launch consumers."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path
from typing import Any, Mapping

from .runner_trust import RunnerEnrollment, RunnerTrustError, _bounded_regular_read
from .util import canonical_json_bytes

PROCESS_RECORD_SCHEMA_VERSION = "bluefire.runner-process.v1"
PROCESS_RECORD_MAX_BYTES = 16 * 1024
LOOPBACK_HOST = "127.0.0.1"
_HEX_32 = re.compile(r"^[0-9a-f]{64}$")
_HEX_16 = re.compile(r"^[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROCESS_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "launch_id",
        "pid",
        "host",
        "port",
        "runner_id",
        "client_id",
        "server_fingerprint",
        "server_instance_id",
        "runner_binary_digest",
        "started_at_ns",
        "authentication",
    }
)


class RunnerHostError(RuntimeError):
    """A deliberately path- and secret-free managed-host refusal."""


def process_record_authentication(enrollment: RunnerEnrollment, payload: Mapping[str, Any]) -> str:
    """Authenticate the exact process-record payload with enrollment material."""
    return (
        "sha256:"
        + hmac.new(
            enrollment.hmac_key(), canonical_json_bytes(dict(payload)), hashlib.sha256
        ).hexdigest()
    )


def validate_process_record(
    value: Any,
    *,
    enrollment: RunnerEnrollment,
    expected_binary_digest: str,
) -> dict[str, Any]:
    """Validate a process record as an address hint, never as health proof."""
    if not isinstance(value, dict) or set(value) != _PROCESS_RECORD_FIELDS:
        raise RunnerHostError("Runner process record is invalid.")
    unsigned = {key: value[key] for key in value if key != "authentication"}
    authentication = value.get("authentication")
    expected_authentication = process_record_authentication(enrollment, unsigned)
    if (
        value.get("schema_version") != PROCESS_RECORD_SCHEMA_VERSION
        or not isinstance(value.get("launch_id"), str)
        or _HEX_32.fullmatch(str(value["launch_id"])) is None
        or isinstance(value.get("pid"), bool)
        or not isinstance(value.get("pid"), int)
        or not 1 <= int(value["pid"]) <= 2**63 - 1
        or value.get("host") != LOOPBACK_HOST
        or isinstance(value.get("port"), bool)
        or not isinstance(value.get("port"), int)
        or not 1 <= int(value["port"]) <= 65535
        or value.get("runner_id") != enrollment.runner_id
        or value.get("client_id") != enrollment.client_id
        or value.get("server_fingerprint") != enrollment.metadata["server_fingerprint"]
        or not isinstance(value.get("server_instance_id"), str)
        or _HEX_16.fullmatch(str(value["server_instance_id"])) is None
        or value.get("runner_binary_digest") != expected_binary_digest
        or _DIGEST.fullmatch(str(value.get("runner_binary_digest"))) is None
        or isinstance(value.get("started_at_ns"), bool)
        or not isinstance(value.get("started_at_ns"), int)
        or not 1 <= int(value["started_at_ns"]) <= 2**63 - 1
        or not isinstance(authentication, str)
        or _DIGEST.fullmatch(authentication) is None
        or not hmac.compare_digest(authentication, expected_authentication)
    ):
        raise RunnerHostError("Runner process record is invalid.")
    return dict(value)


def read_pinned_process_record(
    path: str | Path,
    *,
    enrollment: RunnerEnrollment,
    expected_binary_digest: str,
) -> dict[str, Any]:
    """Read an existing private identity without publishing or repairing it."""
    try:
        payload = _bounded_regular_read(Path(path), PROCESS_RECORD_MAX_BYTES)
        value = json.loads(payload)
        if canonical_json_bytes(value) != payload:
            raise ValueError("non-canonical process record")
    except (OSError, ValueError, TypeError, RunnerTrustError):
        raise RunnerHostError("Runner process record is unavailable or invalid.") from None
    return validate_process_record(
        value,
        enrollment=enrollment,
        expected_binary_digest=expected_binary_digest,
    )
