"""Closed Windows provenance and original private-read preparation contracts.

Parsing establishes consistency, never setup authority. Only the concrete
protected observer can supply a first import. Preparation is not dispatch.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, cast

from . import _windows_file_access_native_contract as wire
from .domain_errors import ProductStoreError
from .execution_contracts import execution_task_identity
from .file_access_contract import MAX_ENROLLMENT_MS, FileAccessContractError
from .util import canonical_json_bytes, content_hash

SCHEMA = "bluefire.windows-file-access-enrollment.v1"
ANCHOR_PATH = r"C:\ProgramData\BlueFire\EndpointAccess\enrollment.json"
MAX_ENROLLMENT_BYTES = 16384
_FIELDS = (
    "schema_version enrollment_id resource_id generation issued_at_ms expires_at_ms "
    "setup_receipt_digest host resource native_image credential_reference limits"
)
_FAILURES = (
    wire.NativeWireError,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    OverflowError,
    RecursionError,
)


@dataclass(frozen=True, slots=True)
class _SetupProtocol:
    version: int
    wire: wire._Protocol
    profile_prefix: str
    reference_prefix: str
    command: str

    def schema(self, name: str) -> str:
        _setup_protocol(self)
        return f"bluefire.windows-file-{name}.v{self.version}"

    def limits(self) -> dict[str, int]:
        _setup_protocol(self)
        if self is _READER_SETUP:
            return {"max_reads": 1, "max_read_bytes": 1048576, "per_request_ms": 5000}
        return {
            "max_reader_reads": 1,
            "max_owner_reads": 1,
            "max_data_opens": 2,
            "max_bytes_per_read": 1048576,
            "max_total_read_bytes": 2097152,
            "per_request_ms": 5000,
        }


_READER_SETUP = _SetupProtocol(
    1, wire._V1, "windows-file-", "secret-ref:windows-file-reader-", "windows-file-worker"
)
_PAIR_SETUP = _SetupProtocol(
    2,
    wire._PAIR,
    "windows-file-pair-",
    "secret-ref:windows-file-pair-reader-",
    "windows-file-baseline-worker",
)


def _setup_protocol(protocol: _SetupProtocol) -> None:
    wire._require(protocol is _READER_SETUP or protocol is _PAIR_SETUP)


def _protocol_from_record(raw: bytes) -> _SetupProtocol:
    """Closed syntax selection only; protected observation remains mandatory."""
    schema = wire._document(raw, MAX_ENROLLMENT_BYTES).get("schema_version")
    if schema == SCHEMA:
        return _READER_SETUP
    wire._require(schema == _PAIR_SETUP.schema("access-enrollment"))
    return _PAIR_SETUP


class WindowsEnrollmentUnavailable(FileAccessContractError):
    def __init__(
        self,
        code: Literal[
            "windows_protected_setup_unavailable", "windows_native_admission_unavailable"
        ],
    ):
        self.code = code
        super().__init__(
            "Windows file access requires verified protected setup and native admission."
        )


def _identity(value: Any) -> None:
    row = wire._exact(value, "volume_serial file_id")
    wire._hex(row["volume_serial"], 16)
    wire._hex(row["file_id"], 32)
    wire._require(row["file_id"] != "0" * 32)


def _purpose(row: dict[str, Any]) -> str:
    return _purpose_for(row, _READER_SETUP)


def _purpose_for(row: dict[str, Any], protocol: _SetupProtocol) -> str:
    _setup_protocol(protocol)
    return content_hash(
        {
            "schema_version": protocol.schema("reader-purpose"),
            "enrollment_id": row["enrollment_id"],
            "generation": row["generation"],
            "host": row["host"],
            "owner_sid": row["resource"]["owner_sid"],
            "reader_sid": row["resource"]["reader_sid"],
            **({"operation": "read_generated_pair"} if protocol is _PAIR_SETUP else {}),
        }
    )


def _document(value: Any) -> dict[str, Any]:
    return _document_for(value, _READER_SETUP)


def _document_for(value: Any, protocol: _SetupProtocol) -> dict[str, Any]:
    _setup_protocol(protocol)
    row = wire._document(value, MAX_ENROLLMENT_BYTES)
    wire._exact(row, _FIELDS)
    wire._require(row["schema_version"] == protocol.schema("access-enrollment"))
    generation = wire._hex(row["generation"], 32)
    wire._require(row["enrollment_id"] == "win-file-enrollment-" + generation)
    wire._require(row["resource_id"] == "win-file-resource-" + generation)
    issued = wire._int(row["issued_at_ms"], 1, 2**63 - 1 - MAX_ENROLLMENT_MS)
    wire._int(row["expires_at_ms"], issued + 1, issued + MAX_ENROLLMENT_MS)
    wire._digest(row["setup_receipt_digest"])
    host = wire._exact(
        row["host"], "runner_profile_id profile_digest native_generation host_id channel_digest"
    )
    wire._identifier(host["runner_profile_id"])
    for name in ("profile_digest", "native_generation", "host_id", "channel_digest"):
        wire._digest(host[name])
    wire._resource(row["resource"])
    image = wire._exact(
        row["native_image"],
        "schema_version image_name identity size_bytes sha256 architecture worker_schema read_schema",
    )
    wire._require(image["schema_version"] == "bluefire.windows-file-native-image.v1")
    wire._require(
        image["image_name"] == "bluefire-runner.exe" and image["architecture"] == "x86_64"
    )
    _identity(image["identity"])
    wire._int(image["size_bytes"], 1, 64 * 1024 * 1024)
    wire._digest(image["sha256"])
    wire._require(image["worker_schema"] == protocol.wire.schema("request"))
    wire._require(image["read_schema"] == protocol.wire.proof)
    wire._require(host["native_generation"] == content_hash(image))
    reference = wire._exact(
        row["credential_reference"],
        "schema_version reference secret_provider generation reader_sid identity_receipt_digest protected_sha256 purpose_digest",
    )
    wire._require(reference["schema_version"] == protocol.schema("reader-reference"))
    wire._require(reference["reference"] == protocol.reference_prefix + generation)
    wire._require(reference["secret_provider"] == "windows-dpapi-current-user.v1")
    wire._require(
        reference["generation"] == generation
        and reference["reader_sid"] == row["resource"]["reader_sid"]
    )
    for name in ("identity_receipt_digest", "protected_sha256", "purpose_digest"):
        wire._digest(reference[name])
    wire._require(reference["purpose_digest"] == _purpose_for(row, protocol))
    wire._require(row["limits"] == protocol.limits())
    for value in row["limits"].values():
        wire._require(type(value) is int)
    return row


@dataclass(frozen=True, slots=True)
class WindowsEnrollmentCandidate:
    """Immutable parsed bytes; this type deliberately cannot claim verification."""

    _raw: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self._raw) is not bytes:
            raise FileAccessContractError("Windows enrollment candidate is invalid.")
        try:
            _document(self._raw)
        except _FAILURES:
            raise FileAccessContractError("Windows enrollment candidate is invalid.") from None

    @property
    def consistency_digest(self) -> str:
        return content_hash(_document(self._raw))

    @property
    def generation(self) -> str:
        return cast(str, _document(self._raw)["generation"])

    @property
    def resource_path(self) -> str:
        return "C:\\BlueFire\\EndpointAccess\\" + self.generation + "\\records.jsonl"

    @property
    def reader_account(self) -> str:
        return "bf_" + self.generation[:16]


def parse_windows_enrollment_candidate(value: Any, *, now_ms: int) -> WindowsEnrollmentCandidate:
    """Validate bounded current syntax, not producer authenticity or native facts."""
    try:
        row = _document(value)
        current = wire._int(now_ms, 1, 2**63 - 1)
        wire._require(row["issued_at_ms"] <= current < row["expires_at_ms"])
        return WindowsEnrollmentCandidate(canonical_json_bytes(row))
    except _FAILURES:
        raise FileAccessContractError("Windows enrollment candidate is invalid or stale.") from None


@dataclass(frozen=True, slots=True, init=False)
class VerifiedWindowsSetup:
    """Read-only checked setup snapshot; deliberately no execution authority."""

    _raw: bytes = field(repr=False)
    _receipt: bytes = field(repr=False)

    def __init__(self) -> None:
        raise TypeError("Windows setup snapshots require the concrete protected observer")

    def summary(self) -> dict[str, Any]:
        row = _document(self._raw)
        return {
            "enrollment_id": row["enrollment_id"],
            "enrollment_digest": content_hash(row),
            "expires_at_ms": row["expires_at_ms"],
            "verification": "protected_setup_only",
        }


class WindowsEnrollmentNativeError(RuntimeError):
    """A path-free refusal; partial facts never imply verified enrollment."""


def file_identity_wire(volume_serial: int, file_id: int) -> tuple[str, str]:
    """Serialize FILE_ID_INFO without truncation or reversing its opaque ID bytes.

    The existing Python descriptor helper decodes FileId bytes as a little-endian
    integer. The native worker consumes raw hex-decoded bytes, not a numeric u128.
    """
    if (
        type(volume_serial) is not int
        or not 0 <= volume_serial < 1 << 64
        or type(file_id) is not int
        or not 0 < file_id < 1 << 128
    ):
        raise WindowsEnrollmentNativeError("Windows enrollment file identity is invalid")
    return f"{volume_serial:016x}", file_id.to_bytes(16, "little").hex()


ANCHOR_ROOT = r"C:\ProgramData\BlueFire\EndpointAccessAnchors"
ANCHOR_SCHEMA = "bluefire.windows-file-setup-anchor.v1"
MAX_ANCHOR_BYTES = 4096


_ANCHOR_FIELDS = (
    "schema_version enrollment_id generation host_id record_identity enrollment_digest "
    "setup_receipt_digest image_sha256 credential_binding_digest"
)


def _anchor_paths(generation: str) -> tuple[str, ...]:
    generation = wire._hex(generation, 32)
    root = ANCHOR_ROOT + "\\" + generation
    return (
        "C:\\",
        r"C:\ProgramData",
        r"C:\ProgramData\BlueFire",
        ANCHOR_ROOT,
        root,
        root + "\\setup.json",
    )


def _anchor_document(raw: bytes) -> dict[str, Any]:
    wire._require(type(raw) is bytes)
    row = wire._document(raw, MAX_ANCHOR_BYTES)
    wire._exact(row, _ANCHOR_FIELDS)
    wire._require(row["schema_version"] == ANCHOR_SCHEMA)
    generation = wire._hex(row["generation"], 32)
    wire._require(row["enrollment_id"] == "win-file-enrollment-" + generation)
    _identity(row["record_identity"])
    for name in (
        "host_id",
        "enrollment_digest",
        "setup_receipt_digest",
        "image_sha256",
        "credential_binding_digest",
    ):
        wire._digest(row[name])
    return row


def _match_anchor_record(raw: bytes, record_raw: bytes, record_identity: tuple[int, int]) -> None:
    """Internal linkage after native reads, never producer/lifecycle authority."""
    _match_anchor_record_for(raw, record_raw, record_identity, _READER_SETUP)


def _match_anchor_record_for(
    raw: bytes, record_raw: bytes, record_identity: tuple[int, int], protocol: _SetupProtocol
) -> None:
    anchor, record = _anchor_document(raw), _document_for(record_raw, protocol)
    volume, file_id = file_identity_wire(*record_identity)
    wire._require(anchor["record_identity"] == {"volume_serial": volume, "file_id": file_id})
    for name in ("enrollment_id", "generation", "setup_receipt_digest"):
        wire._require(anchor[name] == record[name])
    wire._require(anchor["host_id"] == record["host"]["host_id"])
    wire._require(anchor["enrollment_digest"] == content_hash(record))
    wire._require(anchor["image_sha256"] == record["native_image"]["sha256"])
    wire._require(
        anchor["credential_binding_digest"] == content_hash(record["credential_reference"])
    )


def _private_profile(generation: str) -> dict[str, Any]:
    return _private_profile_for(generation, _READER_SETUP)


def _private_profile_for(generation: str, protocol: _SetupProtocol) -> dict[str, Any]:
    _setup_protocol(protocol)
    profile = {
        "schema_version": "bluefire.runner-profile.v1",
        "profile_id": protocol.profile_prefix + generation,
        "runner_id": "bluefire-rust-runner.v1",
        "platform": "windows",
        "sandbox_root": "C:\\BlueFire\\EndpointAccess\\" + generation,
        "allowed_actions": [protocol.wire.action],
        "control_blocked_actions": [],
        "capabilities": [protocol.wire.capability],
        "max_safety_tier": "controlled",
        "approval_required_at_or_above": "safe",
        "target_scope": {"filesystem": [], "network": []},
        "limits": {
            "timeout_ms": 5000,
            "max_stdout_bytes": 8192,
            "max_stderr_bytes": 1024,
            "max_artifact_bytes": 1,
            "max_files": 1,
        },
        "policy_digest": "",
    }
    profile["policy_digest"] = content_hash(profile)
    return profile


def _capability(raw: bytes, version: str) -> dict[str, Any]:
    return _capability_for(raw, version, _READER_SETUP)


def _capability_for(raw: bytes, version: str, protocol: _SetupProtocol) -> dict[str, Any]:
    _setup_protocol(protocol)
    row = wire._document(raw, 1024)
    extra = (
        {}
        if protocol is _READER_SETUP
        else {
            "action_id": protocol.wire.action,
            "capability": protocol.wire.capability,
            "max_data_opens": 2,
            "max_bytes_per_read": 1048576,
            "max_total_read_bytes": 2097152,
            "max_execution_ms": 5000,
        }
    )
    wire._exact(
        row,
        "schema_version runner_id runner_version platform architecture supported worker_command worker_schema read_schema scope "
        + " ".join(extra),
    )
    wire._require(
        row
        == {
            "schema_version": protocol.schema("worker-capability"),
            "runner_id": "bluefire-rust-runner.v1",
            "runner_version": version,
            "platform": "windows",
            "architecture": "x86_64",
            "supported": True,
            "worker_command": protocol.command,
            "worker_schema": protocol.wire.schema("request"),
            "read_schema": protocol.wire.proof,
            "scope": "protocol_support_only",
            **extra,
        }
        and type(row["supported"]) is bool
    )
    for name in extra.keys() - {"action_id", "capability"}:
        wire._require(type(row[name]) is int)
    return row


def _source_document(source: Any) -> None:
    _source_document_for(source, _READER_SETUP)


def _source_document_for(source: Any, protocol: _SetupProtocol) -> None:
    _setup_protocol(protocol)
    wire._exact(
        source, "source_profile_id source_enrollment_generation transport native_image capability"
    )
    wire._identifier(source["source_profile_id"])
    wire._digest(source["source_enrollment_generation"])
    transport = wire._exact(
        source["transport"],
        "schema_version runner_id client_id transport tls server_fingerprint client_fingerprint authenticated_peer_fingerprint enrollment_generation runner_binary_digest inventory_digest",
    )
    wire._require(
        transport["schema_version"] == "bluefire.runner-transport-identity.v1"
        and transport["runner_id"] == "bluefire-rust-runner.v1"
        and transport["transport"] == "mutual-tls-loopback"
        and transport["tls"] == "TLSv1.3"
    )
    wire._identifier(transport["client_id"])
    for name in (
        "server_fingerprint",
        "client_fingerprint",
        "authenticated_peer_fingerprint",
        "enrollment_generation",
        "runner_binary_digest",
        "inventory_digest",
    ):
        wire._digest(transport[name])
    wire._require(
        transport["authenticated_peer_fingerprint"] == transport["client_fingerprint"]
        and source["source_enrollment_generation"] == transport["enrollment_generation"]
        and source["native_image"]["sha256"] == transport["runner_binary_digest"]
    )
    version = source["capability"]["runner_version"]
    wire._require(
        type(version) is str
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.]+)?", version) is not None
        and len(version) <= 128
    )
    _capability_for(canonical_json_bytes(source["capability"]), version, protocol)


IMPORT_SCHEMA = "bluefire.windows-file-setup-import.v1"
CONTROL_SCHEMA = "bluefire.windows-file-access-control.v1"
PREPARATION_SCHEMA = "bluefire.windows-file-access-baseline-preparation.v1"
CONTEXT_SCHEMA = "bluefire.windows-file-access-baseline-context.v1"


def selected(value: Any) -> dict[str, Any]:
    row = wire._exact(value, "enrollment_id enrollment_digest")
    identity = row["enrollment_id"]
    wire._require(type(identity) is str and identity.startswith("win-file-enrollment-"))
    wire._hex(identity[len("win-file-enrollment-") :], 32)
    wire._digest(row["enrollment_digest"])
    return row


def _provenance(record: Any, receipt: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    return _provenance_for(record, receipt, _READER_SETUP)


def _provenance_for(
    record: Any, receipt: Any, protocol: _SetupProtocol
) -> tuple[dict[str, Any], dict[str, Any]]:
    row = _document_for(record, protocol)
    receipt = wire._exact(
        receipt,
        "schema_version original_intent_digest generation issued_at_ms expires_at_ms source "
        "private_profile account_receipt resource native_image credential_reference "
        "account_cleanup_required context_available",
    )
    wire._require(
        receipt["schema_version"] == protocol.schema("setup-receipt")
        and content_hash(receipt) == row["setup_receipt_digest"]
        and receipt["private_profile"] == _private_profile_for(row["generation"], protocol)
        and receipt["account_cleanup_required"] is True
        and receipt["context_available"] is False
        and row["resource"]["state"] == "readable"
    )
    wire._digest(receipt["original_intent_digest"])
    for key in (
        "generation",
        "issued_at_ms",
        "expires_at_ms",
        "resource",
        "native_image",
        "credential_reference",
    ):
        wire._require(wire._same(row[key], receipt[key]))
    _source_document_for(receipt["source"], protocol)
    wire._require(receipt["source"]["native_image"] == row["native_image"])
    account = wire._exact(
        receipt["account_receipt"],
        "schema_version generation original_intent_digest account_name reader_sid owner_sid "
        "net_user_add_succeeded account_expires_seconds cleanup_obligation",
    )
    wire._require(
        account["schema_version"] == "bluefire.windows-file-owned-account.v1"
        and account["generation"] == row["generation"]
        and account["original_intent_digest"] == receipt["original_intent_digest"]
        and account["account_name"] == "bf_" + row["generation"][:16]
        and account["owner_sid"] == row["resource"]["owner_sid"]
        and account["reader_sid"] == row["resource"]["reader_sid"]
        and account["net_user_add_succeeded"] is True
        and type(account["account_expires_seconds"]) is int
        and account["account_expires_seconds"] == row["expires_at_ms"] // 1000
        and account["cleanup_obligation"] == "retained_account_and_objects_not_deleted"
        and content_hash(account) == row["credential_reference"]["identity_receipt_digest"]
    )
    wire._require(
        row["host"]
        == {
            "runner_profile_id": receipt["private_profile"]["profile_id"],
            "profile_digest": receipt["private_profile"]["policy_digest"],
            "native_generation": content_hash(row["native_image"]),
            "host_id": content_hash(
                {
                    "schema_version": "bluefire.windows-local-account-authority.v1",
                    "local_owner_sid": row["resource"]["owner_sid"],
                }
            ),
            "channel_digest": content_hash(receipt["source"]["transport"]),
        }
    )
    return row, receipt


def checked_provenance(checked: VerifiedWindowsSetup) -> tuple[dict, dict]:
    wire._require(type(checked) is VerifiedWindowsSetup)
    return _provenance(wire._document(checked._raw), wire._document(checked._receipt, 16384))


def control_id(row: dict) -> str:
    return _control_id_for(row, _READER_SETUP)


def _control_id_for(row: dict, protocol: _SetupProtocol) -> str:
    identity = content_hash(
        {
            "schema_version": protocol.schema("setup-import"),
            "enrollment_id": row["enrollment_id"],
            "setup_receipt_digest": row["setup_receipt_digest"],
        }
    )
    return "win-file-control-" + identity[7:39]


def import_document(checked: VerifiedWindowsSetup, *, now_ms: int) -> dict:
    row, receipt = checked_provenance(checked)
    return _import_document_for(row, receipt, now_ms, _READER_SETUP)


def _import_document_for(row: dict, receipt: dict, now_ms: int, protocol: _SetupProtocol) -> dict:
    row, receipt = _provenance_for(row, receipt, protocol)
    wire._int(now_ms, 1, 2**63 - 1)
    wire._require(row["issued_at_ms"] <= now_ms < row["expires_at_ms"])
    return {
        "schema_version": protocol.schema("setup-import"),
        "control_owner_id": _control_id_for(row, protocol),
        "revision": 1,
        "status": "setup_verified",
        "enrollment_id": row["enrollment_id"],
        "generation": row["generation"],
        "expires_at_ms": row["expires_at_ms"],
        "enrollment": row,
        "setup_receipt": receipt,
        "imported_at_ms": now_ms,
    }


def validate_import(value: Any) -> dict:
    return _validate_import_for(value, _READER_SETUP)


def _validate_import_for(value: Any, protocol: _SetupProtocol) -> dict:
    row = wire._exact(
        value,
        "schema_version control_owner_id revision status enrollment_id "
        "generation expires_at_ms enrollment setup_receipt imported_at_ms",
    )
    record, _ = _provenance_for(row["enrollment"], row["setup_receipt"], protocol)
    wire._int(row["imported_at_ms"], 1, 2**63 - 1)
    wire._require(
        row["schema_version"] == protocol.schema("setup-import")
        and row["control_owner_id"] == _control_id_for(record, protocol)
        and type(row["revision"]) is int
        and row["revision"] == 1
        and row["status"] == "setup_verified"
        and row["enrollment_id"] == record["enrollment_id"]
        and row["generation"] == record["generation"]
        and row["expires_at_ms"] == record["expires_at_ms"]
        and record["issued_at_ms"] <= row["imported_at_ms"] < record["expires_at_ms"]
    )
    return row


def projection(value: Any) -> dict:
    return _projection_for(value, _READER_SETUP)


def _projection_for(value: Any, protocol: _SetupProtocol) -> dict:
    saved = _validate_import_for(value, protocol)
    record = saved["enrollment"]
    return {
        "schema_version": CONTROL_SCHEMA,
        "platform": "windows",
        "control_owner_id": saved["control_owner_id"],
        "control_digest": content_hash(saved),
        "revision": 1,
        "status": "setup_verified",
        "expires_at_ms": saved["expires_at_ms"],
        "provenance": {
            "kind": "protected_setup",
            "enrollment_id": record["enrollment_id"],
            "enrollment_digest": content_hash(record),
            "setup_receipt_digest": record["setup_receipt_digest"],
        },
        "resource": {
            "resource_id": record["resource_id"],
            "resource_generation": record["generation"],
            "expected_sha256": record["resource"]["sha256"],
            "size_bytes": record["resource"]["size_bytes"],
            "protection": "reader_readable",
        },
        "baseline": None,
        "operations": [],
        "allowed_operations": [],
        "task_usage_state": "none",
        "account_object_cleanup": "required",
    }


def baseline_context(imported: Any) -> dict:
    return _baseline_context_for(imported, _READER_SETUP)


def _baseline_context_for(imported: Any, protocol: _SetupProtocol) -> dict:
    saved = _validate_import_for(imported, protocol)
    return {
        "schema_version": protocol.schema("access-baseline-context"),
        "control_digest": content_hash(saved),
        "enrollment_digest": content_hash(saved["enrollment"]),
        "setup_receipt_digest": saved["enrollment"]["setup_receipt_digest"],
        "profile_digest": saved["setup_receipt"]["private_profile"]["policy_digest"],
    }


def _iso(value: int) -> str:
    return (
        datetime.fromtimestamp(value / 1000, timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def build_preparation(job_id: str, original: dict, imported: dict, *, issued_at_ms: int) -> dict:
    """Pure builder for an already-reserved real review; not a public admission API."""
    return _build_preparation_for(job_id, original, imported, issued_at_ms, _READER_SETUP)


def _build_preparation_for(
    job_id: str, original: dict, imported: dict, issued_at_ms: int, protocol: _SetupProtocol
) -> dict:
    import hashlib
    import uuid

    saved = _validate_import_for(imported, protocol)
    record, receipt = saved["enrollment"], saved["setup_receipt"]
    wire._exact(original, "submitted_request review review_context enrollment_digest created_at_ms")
    review, submitted = original["review"], original["submitted_request"]
    wire._exact(submitted, "submission_id review review_digest reviewed_by")
    wire._exact(
        review,
        "schema_version operation control_owner_id context_digest enrollment_digest control_digest expires_at_ms effect review_digest",
    )
    identifier = uuid.UUID(submitted["submission_id"])
    wire._require(
        str(identifier) == submitted["submission_id"] and job_id == "job-" + identifier.hex
    )
    wire._require(review["schema_version"] == "bluefire.file-access-control-review.v1")
    wire._identifier(submitted["reviewed_by"])
    wire._int(original["created_at_ms"], 1, 2**63 - 1)
    expected_context = _baseline_context_for(saved, protocol)
    wire._require(
        original["review_context"] == expected_context
        and review["context_digest"] == content_hash(expected_context)
        and review["operation"] == "baseline"
        and review["control_owner_id"] == saved["control_owner_id"]
        and review["control_digest"] == content_hash(saved)
        and review["enrollment_digest"] == original["enrollment_digest"] == content_hash(record)
        and submitted["review"]
        == {"operation": "baseline", "control_owner_id": saved["control_owner_id"]}
        and submitted["review_digest"] == review["review_digest"]
        and content_hash({key: value for key, value in review.items() if key != "review_digest"})
        == review["review_digest"]
    )
    wire._int(issued_at_ms, 1, 2**63 - 1 - 5000)
    wire._int(review["expires_at_ms"], 1, 2**63 - 1)
    wire._require(record["issued_at_ms"] <= original["created_at_ms"] <= issued_at_ms)
    expires = min(issued_at_ms + 5000, review["expires_at_ms"], record["expires_at_ms"])
    wire._require(issued_at_ms < expires)
    profile = receipt["private_profile"]
    expected = {
        "operation_job_id": job_id,
        "generation": record["generation"],
        "control_revision": saved["revision"],
        "credential_binding_digest": content_hash(record["credential_reference"]),
        "host": record["host"],
        "resource": record["resource"],
    }
    request_id = hashlib.sha256(f"{job_id}:{protocol.wire.operation}".encode("ascii")).hexdigest()[
        :32
    ]
    request = {
        "schema_version": protocol.wire.schema("operation"),
        "request_id": request_id,
        **expected,
    }
    approval = {
        "approved_by": submitted["reviewed_by"],
        "approved_at": _iso(issued_at_ms),
        "expires_at": _iso(expires),
        "request_hash": "",
    }
    manifest = {
        "schema_version": "bluefire.runner-manifest.v1",
        "request_id": "win-read-" + request_id,
        "run_id": job_id,
        "step_id": protocol.wire.operation,
        "behavior_id": (
            "identity.windows.file_read.v1"
            if protocol is _READER_SETUP
            else "identity.windows.file_read_pair.v2"
        ),
        "action_id": protocol.wire.action,
        "mode": "execute",
        "runner_id": profile["runner_id"],
        "runner_profile_id": profile["profile_id"],
        "platform": "windows",
        "requested_at": _iso(issued_at_ms),
        "expires_at": _iso(expires),
        "params": {"windows_file_read_request": request},
        "target_scope": profile["target_scope"],
        "required_capabilities": profile["capabilities"],
        "safety_tier": "controlled",
        "limits": profile["limits"],
        "cleanup_action_id": None,
        "policy_digest": profile["policy_digest"],
        "approval": approval,
        "evidence_refs": [],
        "request_hash": "",
    }
    manifest["request_hash"] = approval["request_hash"] = content_hash(manifest)
    task_id, transport = execution_task_identity(manifest, profile)
    pair = {
        "manifest": manifest,
        "profile": profile,
        "task_id": task_id,
        "transport_request_hash": transport,
    }
    wire._original(pair, expected, protocol=protocol.wire)
    return {
        "schema_version": protocol.schema("access-baseline-preparation"),
        "job_id": job_id,
        "control_owner_id": saved["control_owner_id"],
        "control_digest": content_hash(saved),
        "context_digest": review["context_digest"],
        "review_digest": review["review_digest"],
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires,
        "original": pair,
        "expected_binding": expected,
        "required_proofs": ["fresh_non_owner_read", "fresh_owner_read", "owned_process_cleanup"],
    }


def validate_preparation(value: Any, original: dict, imported: dict, *, now_ms: int) -> dict:
    row = _retained_preparation_for(value, original, imported, _READER_SETUP)
    wire._int(now_ms, 1, 2**63 - 1)
    if not row["issued_at_ms"] <= now_ms < row["expires_at_ms"]:
        raise ProductStoreError("The original Windows baseline preparation changed or expired.")
    return row


def _retained_preparation_for(
    value: Any, original: dict, imported: dict, protocol: _SetupProtocol
) -> dict:
    row = wire._exact(
        value,
        "schema_version job_id control_owner_id control_digest context_digest "
        "review_digest issued_at_ms expires_at_ms original expected_binding required_proofs",
    )
    expected = _build_preparation_for(
        row["job_id"], original, imported, row["issued_at_ms"], protocol
    )
    if not wire._same(row, expected):
        raise ProductStoreError("The original Windows baseline preparation changed or expired.")
    return row
