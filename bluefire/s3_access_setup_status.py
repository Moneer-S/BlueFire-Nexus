"""Bounded local setup evidence, never AWS readiness or permission to execute."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .s3_access_admission import ACTION
from .s3_access_admission import SCHEMA as ADMISSION_SCHEMA
from .s3_access_configuration import _identifier
from .s3_access_contract import S3AccessError, S3AccessScope, digest, document, exact, timestamp
from .s3_access_extension_store import S3ExtensionStore
from .s3_access_host_config import require_owned_host
from .s3_access_runtime import validate_runtime
from .util import content_hash

OPERATION = "s3_access_setup_status"
SCHEMA = "bluefire.s3-setup-status.v1"
STATES = frozenset(
    {
        "unsupported_host",
        "method_unavailable",
        "missing",
        "incomplete",
        "invalid",
        "profile_missing",
        "configured",
    }
)


def _now():
    return datetime.now(timezone.utc)


def _result(profile_id, state, revision=None, rows=None) -> dict[str, Any]:
    value = {
        "schema_version": SCHEMA,
        "profile_id": profile_id,
        "configuration_state": state,
        "revision_digest": revision,
        "environments": rows or [],
    }
    return {**value, "context_digest": content_hash(value)}


def inspect_status(enrollment, profile_id: str, *, clock=_now) -> dict[str, Any]:
    """Read one authenticated revision; never complete an interrupted publication."""
    _identifier(profile_id)
    try:
        require_owned_host()
    except S3AccessError:
        return _result(profile_id, "unsupported_host")
    try:
        store = S3ExtensionStore(enrollment)
        before = store.publication_state()
        if before["status"] == "incomplete":
            return _result(profile_id, "incomplete")
        current = store.read()
        if current is None:
            if store.publication_state() != before:
                raise S3AccessError("S3 setup changed during inspection")
            return _result(profile_id, "missing")
        rows = []
        now = clock()
        for entry in current["configuration"]["environments"]:
            if entry["profile"]["profile_id"] != profile_id:
                continue
            runtime_state = "unavailable"
            try:
                runtime = validate_runtime(Path(entry["runtime_root"]), entry["runtime_digest"])
                if runtime.worker_generation == entry["worker_generation"]:
                    runtime_state = "verified"
            except (OSError, ValueError, RuntimeError):
                pass
            protected = current["credentials"].get(entry["environment_id"])
            reference_state = (
                "absent"
                if protected is None
                else "current" if timestamp(protected["expires_at"]) > now else "expired"
            )
            scope_state = "current"
            try:
                S3AccessScope.from_mapping(entry["scope"]).assert_current(clock=lambda: now)
            except S3AccessError:
                scope_state = "not_current"
            rows.append(
                {
                    "environment_id": entry["environment_id"],
                    "runtime_state": runtime_state,
                    "access_reference_state": reference_state,
                    "scope_state": scope_state,
                    "fixture_generation": 2 if "fixture_lifecycle" in entry else 1,
                }
            )
        if store.publication_state() != before or store.read() != current:
            raise S3AccessError("S3 setup changed during inspection")
        return _result(
            profile_id, "configured" if rows else "profile_missing", content_hash(current), rows
        )
    except (OSError, TypeError, ValueError, RuntimeError):
        # Errors may contain private paths or provider context; expose only a closed state.
        return _result(profile_id, "invalid")


def validate_status(value: Any, *, profile_id: str) -> dict[str, Any]:
    row = document(value, limit=16 * 1024)
    exact(
        row,
        {
            "schema_version",
            "profile_id",
            "configuration_state",
            "revision_digest",
            "environments",
            "context_digest",
        },
        "S3 setup status",
    )
    state = row["configuration_state"]
    if (
        row["schema_version"] != SCHEMA
        or row["profile_id"] != _identifier(profile_id)
        or not isinstance(state, str)
        or state not in STATES
    ):
        raise S3AccessError("S3 setup identity is invalid")
    digest(row["context_digest"])
    if row["context_digest"] != content_hash(
        {key: value for key, value in row.items() if key != "context_digest"}
    ):
        raise S3AccessError("S3 setup context is invalid")
    configured = state in {"configured", "profile_missing"}
    if configured:
        digest(row["revision_digest"])
    elif row["revision_digest"] is not None:
        raise S3AccessError("S3 setup revision is invalid")
    entries = row["environments"]
    if (
        not isinstance(entries, list)
        or len(entries) > 8
        or bool(entries) != (state == "configured")
    ):
        raise S3AccessError("S3 setup environments are invalid")
    identifiers = set()
    for entry in entries:
        exact(
            entry,
            {
                "environment_id",
                "runtime_state",
                "access_reference_state",
                "scope_state",
                "fixture_generation",
            },
            "S3 setup environment",
        )
        identifier = _identifier(entry["environment_id"])
        if (
            identifier in identifiers
            or entry["runtime_state"] not in ("verified", "unavailable")
            or entry["access_reference_state"] not in ("absent", "current", "expired")
            or entry["scope_state"] not in ("current", "not_current")
            or type(entry["fixture_generation"]) is not int
            or entry["fixture_generation"] not in (1, 2)
        ):
            raise S3AccessError("S3 setup environment states are invalid")
        identifiers.add(identifier)
    return row


def server_status(server, request, enrollment):
    server._require_payload(request, frozenset())
    server._verified_runner_binary_digest()
    inventory, _canonical = server._validated_inventory(enrollment)
    descriptors = [row for row in inventory.get("actions", []) if row.get("action_id") == ACTION]
    if (
        getattr(server.runner, "s3_access_admission_protocol", None) != ADMISSION_SCHEMA
        or len(descriptors) != 1
        or descriptors[0].get("capabilities") != ["cloud_aws_s3_access"]
    ):
        return _result(request["profile_id"], "method_unavailable")
    return validate_status(
        inspect_status(enrollment, request["profile_id"]), profile_id=request["profile_id"]
    )


def client_status(client) -> dict[str, Any]:
    from .runner_transport_errors import RunnerAuthenticationError

    raw = client._call(OPERATION, {}, task_id=client._random_task("s3-setup"))
    try:
        return validate_status(raw, profile_id=client.profile_id)
    except (KeyError, TypeError, ValueError):
        raise RunnerAuthenticationError("S3 setup response is invalid.") from None
