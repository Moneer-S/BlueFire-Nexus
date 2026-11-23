"""Original create-only elevated local setup; never runtime admission.

Only the explicit local CLI derives native/packaged/authenticated authority. Status
and the no-argument publisher remain unavailable. Existing objects are not adopted,
repaired, deleted or replayed. Blocking native calls require an external hard worker;
the cooperative original deadline is not a hard bound. Context is not enabled here.
"""

from __future__ import annotations

import hashlib
import math
import os
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, NoReturn, cast

from . import _windows_file_access_native_contract as contract
from . import windows_file_access_admission as enrollment
from .util import canonical_json_bytes, content_hash
from .windows_file_access_admission import (
    _ANCHOR_FIELDS as _ANCHOR_FIELDS,
)
from .windows_file_access_admission import (
    ANCHOR_ROOT as ANCHOR_ROOT,
)
from .windows_file_access_admission import (
    ANCHOR_SCHEMA as ANCHOR_SCHEMA,
)
from .windows_file_access_admission import (
    MAX_ANCHOR_BYTES as MAX_ANCHOR_BYTES,
)
from .windows_file_access_admission import (
    _anchor_document as _anchor_document,
)
from .windows_file_access_admission import (
    _anchor_paths as _anchor_paths,
)
from .windows_file_access_admission import (
    _capability as _capability,
)
from .windows_file_access_admission import (
    _match_anchor_record as _match_anchor_record,
)
from .windows_file_access_admission import (
    _private_profile as _private_profile,
)
from .windows_file_access_admission import (
    _source_document as _source_document,
)
from .windows_file_access_admission import (
    file_identity_wire as file_identity_wire,
)

_METADATA_ROOT = r"C:\ProgramData\BlueFire"
_RECORD_ROOT = _METADATA_ROOT + r"\EndpointAccess"
_INTENT_PATH = _METADATA_ROOT + r"\windows-file-intent.json"
_RECEIPT_PATH = _RECORD_ROOT + r"\setup-receipt.json"
_ACCOUNT_PATH = _RECORD_ROOT + r"\account-receipt.json"
_CREDENTIAL_PATH = _RECORD_ROOT + r"\reader.dpapi"
_PROFILE_PATH = _RECORD_ROOT + r"\private-profile.json"
_CONTENT = b'{"record_id":"endpoint-001","state":"ready"}\n'
_CAPABILITY_FAILURES = frozenset(
    {
        "invalid_request",
        "invalid_deadline",
        "deadline_expired",
        "timeout",
        "launch_failure",
        "capture_failure",
        "nonzero_exit",
        "stderr_nonempty",
        "output_oversize",
        "output_malformed",
        "contract_mismatch",
    }
)


class WindowsPairCapabilityError(contract.NativeWireError):
    """Bounded capability-query failure with no path or process details."""

    def __init__(self, category: str):
        if category not in _CAPABILITY_FAILURES:
            category = "invalid_request"
        self.diagnostic_category = category
        super().__init__("The packaged Windows pair capability query is unavailable.")


def publish_windows_file_access_setup() -> NoReturn:
    """Refuse publication until the actual protected setup producers exist.

    Future publication must consume an original approved privileged lifecycle, not
    caller-supplied host/image/receipt assertions. Every parent must be independently
    reviewed and protected; preexisting unreviewed objects cannot be adopted. The
    fixed record is CREATE_NEW/flush/freshly checked before the generation-specific
    CREATE_NEW anchor. Partial publication remains unavailable and is not repaired,
    deleted, replayed or relabeled complete automatically. No authority/deadline is
    renewed. Actual provisioning needs separate owner approval at runtime.
    """
    raise enrollment.WindowsEnrollmentUnavailable("windows_protected_setup_unavailable")


class WindowsFileSetupError(RuntimeError):
    """Sanitized failure with truthful partial mutation/publication classification."""

    def __init__(self, stage: str, *, bootstrap_mutated: bool, intent_persisted: bool):
        self.stage = stage
        self.bootstrap_mutated = bootstrap_mutated
        self.intent_persisted = intent_persisted
        super().__init__("Windows local setup is incomplete; retained state must not be replayed.")


def _source(lifecycle: Any, profile_id: str, backend: Any, gate: Any) -> dict[str, Any]:
    """Derive protected source identity and live authenticated channel, not assertions."""
    return _source_for(lifecycle, profile_id, backend, gate, enrollment._READER_SETUP)


def _query_capability_for(
    image_path: str | Path,
    version: str,
    original_deadline: float,
    protocol: enrollment._SetupProtocol,
) -> dict[str, Any]:
    """Query compiled support only; no setup or runtime admission is established.

    Temporary streams bound decoding, not subprocess disk writes. The supplied
    original monotonic deadline is never renewed by this read-only query.
    """
    try:
        enrollment._setup_protocol(protocol)
    except Exception:
        raise WindowsPairCapabilityError("invalid_request") from None
    if type(original_deadline) is not float or not math.isfinite(original_deadline):
        raise WindowsPairCapabilityError("invalid_deadline")
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        remaining = original_deadline - time.monotonic()
        if remaining <= 0:
            raise WindowsPairCapabilityError("deadline_expired")
        if remaining > 5:
            raise WindowsPairCapabilityError("invalid_deadline")
        try:
            result = subprocess.run(
                [os.fspath(image_path), protocol.command + "-capability"],
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=errors,
                timeout=remaining,
                check=False,
                shell=False,
                creationflags=0x08000000,
            )
        except subprocess.TimeoutExpired as exc:
            exc.diagnostic_category = "timeout"  # type: ignore[attr-defined]
            raise
        except OSError as exc:
            exc.diagnostic_category = "launch_failure"  # type: ignore[attr-defined]
            raise
        if time.monotonic() >= original_deadline:
            raise WindowsPairCapabilityError("deadline_expired")
        try:
            output.seek(0)
            errors.seek(0)
            if result.returncode != 0:
                raise WindowsPairCapabilityError("nonzero_exit")
            if errors.read(1) != b"":
                raise WindowsPairCapabilityError("stderr_nonempty")
            raw = output.read(1025)
        except WindowsPairCapabilityError:
            raise
        except OSError:
            raise WindowsPairCapabilityError("capture_failure") from None
        if len(raw) > 1024:
            raise WindowsPairCapabilityError("output_oversize")
        try:
            contract._document(raw, 1024)
        except contract.NativeWireError:
            raise WindowsPairCapabilityError("output_malformed") from None
        try:
            return enrollment._capability_for(raw, version, protocol)
        except (contract.NativeWireError, TypeError, ValueError, KeyError, RecursionError):
            raise WindowsPairCapabilityError("contract_mismatch") from None


def _source_for(
    lifecycle: Any, profile_id: str, backend: Any, gate: Any, protocol: enrollment._SetupProtocol
) -> dict[str, Any]:
    from .runner_bootstrap import load_runner_manifest
    from .runner_lifecycle import ManagedRunnerLifecycle

    enrollment._setup_protocol(protocol)
    contract._require(type(lifecycle) is ManagedRunnerLifecycle)
    contract._identifier(profile_id)
    gate.check()
    local = lifecycle._load_active_enrollment()
    bootstrap = lifecycle._load_bootstrap(local)
    contract._require(bootstrap.source == "packaged" and bootstrap.managed_binary)
    manifest = load_runner_manifest(platform_name="windows", architecture="x86_64")
    client, _ = lifecycle.client_for_profile(profile_id)
    transport = dict(client.transport_identity())
    gate.check()
    contract._require(
        transport["runner_binary_digest"] == bootstrap.binary_digest == "sha256:" + manifest.sha256
        and bootstrap.runner_version == manifest.runner_version
    )
    image_path = os.fspath(bootstrap.binary_path)
    contract._require(Path(image_path).name == "bluefire-runner.exe")
    before = backend.observe(image_path, directory=False, protected=False)
    contract._require(before["size"] == manifest.size and 1 <= manifest.size <= 64 * 1024 * 1024)
    digest = hashlib.sha256()
    descriptor = backend.held[-1]
    total = 0
    while True:
        gate.check()
        chunk = os.read(descriptor, min(65536, manifest.size + 1 - total))
        total += len(chunk)
        if not chunk or total > manifest.size:
            break
        digest.update(chunk)
    contract._require(
        total == manifest.size and "sha256:" + digest.hexdigest() == bootstrap.binary_digest
    )
    gate.check()
    capability = _query_capability_for(
        image_path, bootstrap.runner_version, gate.deadline, protocol
    )
    gate.check()
    contract._require(backend.observe(image_path, directory=False, protected=False) == before)
    contract._require(dict(client.transport_identity()) == transport)
    gate.check()
    image = {
        "schema_version": "bluefire.windows-file-native-image.v1",
        "image_name": "bluefire-runner.exe",
        "identity": before["identity"],
        "size_bytes": manifest.size,
        "sha256": bootstrap.binary_digest,
        "architecture": "x86_64",
        "worker_schema": protocol.wire.schema("request"),
        "read_schema": protocol.wire.proof,
    }
    source = {
        "source_profile_id": profile_id,
        "source_enrollment_generation": transport["enrollment_generation"],
        "transport": transport,
        "native_image": image,
        "capability": capability,
    }
    enrollment._source_document_for(source, protocol)
    return source


def _run_setup(
    backend: Any, source: dict[str, Any], owner: Any, gate: Any, *, generation: str, issued: int
) -> dict[str, Any]:
    """Private fake-test boundary; no public API accepts source or owner assertions."""
    return _run_setup_for(
        backend,
        source,
        owner,
        gate,
        generation=generation,
        issued=issued,
        protocol=enrollment._READER_SETUP,
    )


def _run_setup_for(
    backend: Any,
    source: dict[str, Any],
    owner: Any,
    gate: Any,
    *,
    generation: str,
    issued: int,
    protocol: enrollment._SetupProtocol,
) -> dict[str, Any]:
    from . import _windows_file_access_setup_native as write
    from .windows_file_access_policy import WindowsFileAccessPolicy

    expires = 0
    credential = None
    stage, bootstrap_mutated, intent_persisted = "preflight", False, False

    def current() -> None:
        gate.check()
        contract._require(issued <= time.time_ns() // 1_000_000 < issued + 5000)
        backend.current()

    try:
        generation = contract._hex(generation, 32)
        enrollment._source_document_for(source, protocol)
        issued = contract._int(issued, 1, (2**32 - 1) * 1000 - 900000)
        expires = issued + 900000
        profile = enrollment._private_profile_for(generation, protocol)
        current()
        root_fact = backend.observe("C:\\", directory=True, protected=False)
        backend.observe(r"C:\ProgramData", directory=True, protected=False)
        backend.missing_account(generation)
        for path in (_METADATA_ROOT, r"C:\BlueFire"):
            backend.absent(path, directory=True)
            current()
        stage = "bootstrap_storage"
        bootstrap_mutated = True  # Attempt may succeed before an ambiguous/late return.
        backend.directory(_METADATA_ROOT)
        current()
        intent = {
            "schema_version": protocol.schema("setup-intent"),
            "generation": generation,
            "issued_at_ms": issued,
            "expires_at_ms": expires,
            "owner_sid": owner.user_sid,
            "owner_token_id": f"{owner.token_id:016x}",
            "owner_process_id": owner.process_id,
            "owner_created_filetime": f"{owner.process_created_filetime:016x}",
            "source": source,
            "private_profile": profile,
            "scope": "fresh_disposable_local_host_create_only",
            "bootstrap_storage_precedes_intent": True,
        }
        stage = "original_intent"
        backend.publish(_INTENT_PATH, canonical_json_bytes(intent))
        intent_persisted = True
        current()
        backend.directory(_RECORD_ROOT)
        backend.directory(ANCHOR_ROOT)
        backend.directory(_anchor_paths(generation)[-2])
        credential = write._Credential()
        stage = "account_creation"
        reader_sid = backend.account(generation, credential, expires // 1000)
        current()
        policy = WindowsFileAccessPolicy(owner.user_sid, reader_sid)
        account_receipt = {
            "schema_version": "bluefire.windows-file-owned-account.v1",
            "generation": generation,
            "original_intent_digest": content_hash(intent),
            "account_name": "bf_" + generation[:16],
            "reader_sid": reader_sid,
            "owner_sid": owner.user_sid,
            "net_user_add_succeeded": True,
            "account_expires_seconds": expires // 1000,
            "cleanup_obligation": "retained_account_and_objects_not_deleted",
        }
        stage = "account_receipt"
        backend.publish(_ACCOUNT_PATH, canonical_json_bytes(account_receipt))
        current()
        host = {
            "runner_profile_id": profile["profile_id"],
            "profile_digest": profile["policy_digest"],
            "native_generation": content_hash(source["native_image"]),
            "host_id": content_hash(
                {
                    "schema_version": "bluefire.windows-local-account-authority.v1",
                    "local_owner_sid": owner.user_sid,
                }
            ),
            "channel_digest": content_hash(source["transport"]),
        }
        paths = (
            r"C:\BlueFire",
            r"C:\BlueFire\EndpointAccess",
            "C:\\BlueFire\\EndpointAccess\\" + generation,
        )
        ancestors = [root_fact["identity"]]
        stage = "resource_creation"
        for path in paths:
            ancestors.append(backend.directory(path, policy)["identity"])
            current()
        resource_file = backend.publish(paths[-1] + r"\records.jsonl", _CONTENT, policy)
        resource = {
            "owner_sid": owner.user_sid,
            "reader_sid": reader_sid,
            "ancestors": ancestors,
            "file_identity": resource_file["identity"],
            "size_bytes": len(_CONTENT),
            "sha256": "sha256:" + hashlib.sha256(_CONTENT).hexdigest(),
            "state": "readable",
        }
        row = {
            "schema_version": protocol.schema("access-enrollment"),
            "enrollment_id": "win-file-enrollment-" + generation,
            "resource_id": "win-file-resource-" + generation,
            "generation": generation,
            "issued_at_ms": issued,
            "expires_at_ms": expires,
            "setup_receipt_digest": "sha256:" + "0" * 64,
            "host": host,
            "resource": resource,
            "native_image": source["native_image"],
            "limits": protocol.limits(),
        }
        purpose = enrollment._purpose_for(row, protocol)
        stage = "credential_protection"
        opaque = credential.protect(purpose)
        credential.wipe()
        current()
        backend.publish(_CREDENTIAL_PATH, opaque)
        reference = {
            "schema_version": protocol.schema("reader-reference"),
            "reference": protocol.reference_prefix + generation,
            "secret_provider": "windows-dpapi-current-user.v1",
            "generation": generation,
            "reader_sid": reader_sid,
            "identity_receipt_digest": content_hash(account_receipt),
            "protected_sha256": "sha256:" + hashlib.sha256(opaque).hexdigest(),
            "purpose_digest": purpose,
        }
        row["credential_reference"] = reference
        stage = "protected_receipt"
        receipt = {
            "schema_version": protocol.schema("setup-receipt"),
            "original_intent_digest": content_hash(intent),
            "generation": generation,
            "issued_at_ms": issued,
            "expires_at_ms": expires,
            "source": source,
            "private_profile": profile,
            "account_receipt": account_receipt,
            "resource": resource,
            "native_image": source["native_image"],
            "credential_reference": reference,
            "account_cleanup_required": True,
            "context_available": False,
        }
        backend.verify_account(generation, reader_sid, expires // 1000)
        backend.verify_all()
        backend.publish(_PROFILE_PATH, canonical_json_bytes(profile))
        backend.publish(_RECEIPT_PATH, canonical_json_bytes(receipt))
        current()
        row["setup_receipt_digest"] = content_hash(receipt)
        enrollment._document_for(row, protocol)
        stage = "enrollment_publication"
        record = backend.publish(enrollment.ANCHOR_PATH, canonical_json_bytes(row))
        current()
        anchor = {
            "schema_version": ANCHOR_SCHEMA,
            "enrollment_id": row["enrollment_id"],
            "generation": generation,
            "host_id": host["host_id"],
            "record_identity": record["identity"],
            "enrollment_digest": content_hash(row),
            "setup_receipt_digest": content_hash(receipt),
            "image_sha256": source["native_image"]["sha256"],
            "credential_binding_digest": content_hash(reference),
        }
        _anchor_document(canonical_json_bytes(anchor))
        stage = "anchor_publication"
        backend.publish(_anchor_paths(generation)[-1], canonical_json_bytes(anchor))
        current()
        backend.verify_account(generation, reader_sid, expires // 1000)
        backend.verify_all()
        stage = "cleanup"
        backend.close()
        current()
        return {
            "schema_version": protocol.schema("local-setup-result"),
            "generation": generation,
            "setup_receipt_digest": content_hash(receipt),
            "publication": "complete",
            "context_available": False,
            "account_cleanup_required": True,
            "external_hard_deadline_required": True,
            "settled": False,
        }
    except Exception:
        raise WindowsFileSetupError(
            stage, bootstrap_mutated=bootstrap_mutated, intent_persisted=intent_persisted
        ) from None
    finally:
        if credential is not None:
            credential.wipe()
        try:
            backend.close()
        except Exception:
            raise WindowsFileSetupError(
                "cleanup", bootstrap_mutated=bootstrap_mutated, intent_persisted=intent_persisted
            ) from None


def _run_local_setup_child(
    profile_id: str, *, lifecycle: Any, original_issued_at_ms: int, original_deadline: float
) -> dict[str, Any]:
    """Private deriving producer, to be connected only to an owned setup child.

    The CLI confirmation is intent, not authorization. No owner, host, capability,
    receipt, path or verification flag is accepted. A newly built genuine package
    with private support is required; old packages fail before bootstrap mutation.
    No setup invocation is authorized merely by installing this source. Callers must
    separately approve provisioning and impose an external disposable hard deadline.
    """
    return _run_local_setup_child_for(
        profile_id,
        lifecycle=lifecycle,
        original_issued_at_ms=original_issued_at_ms,
        original_deadline=original_deadline,
        protocol=enrollment._READER_SETUP,
    )


def _run_local_pair_setup_child(
    profile_id: str, *, lifecycle: Any, original_issued_at_ms: int, original_deadline: float
) -> dict[str, Any]:
    return _run_local_setup_child_for(
        profile_id,
        lifecycle=lifecycle,
        original_issued_at_ms=original_issued_at_ms,
        original_deadline=original_deadline,
        protocol=enrollment._PAIR_SETUP,
    )


def _run_local_setup_child_for(
    profile_id: str,
    *,
    lifecycle: Any,
    original_issued_at_ms: int,
    original_deadline: float,
    protocol: enrollment._SetupProtocol,
) -> dict[str, Any]:
    from . import _windows_file_access_setup_native as write
    from .windows_file_access_enrollment_native import _Gate

    backend = None
    try:
        enrollment._setup_protocol(protocol)
        issued = contract._int(original_issued_at_ms, 1, (2**32 - 1) * 1000 - 900000)
        contract._require(issued <= time.time_ns() // 1_000_000 < issued + 5000)
        contract._require(type(original_deadline) is float)
        gate = _Gate(original_deadline, lambda: False)
        owner = write._elevated_owner(gate)
        backend = write._NativeSetup(gate, owner, issued)
        source = (
            _source(lifecycle, profile_id, backend, gate)
            if protocol is enrollment._READER_SETUP
            else _source_for(lifecycle, profile_id, backend, gate, protocol)
        )
        generation = secrets.token_hex(16)
        # The lifecycle owns all cleanup once mutation may begin. A second outer
        # close must not erase truthful partial-state classification on failure.
        transferred = backend
        backend = None
        if protocol is enrollment._READER_SETUP:
            return _run_setup(
                transferred, source, owner, gate, generation=generation, issued=issued
            )
        return _run_setup_for(
            transferred,
            source,
            owner,
            gate,
            generation=generation,
            issued=issued,
            protocol=protocol,
        )
    except WindowsFileSetupError:
        raise
    except Exception:
        raise WindowsFileSetupError(
            "authority", bootstrap_mutated=False, intent_persisted=False
        ) from None
    finally:
        if backend is not None:
            try:
                backend.close()
            except Exception:
                raise WindowsFileSetupError(
                    "cleanup", bootstrap_mutated=False, intent_persisted=False
                ) from None


def _load_receipt(backend: Any) -> bytes:
    """Fixed protected original receipts, not freshness/admission or settled access."""
    return _load_receipt_for(backend, enrollment._READER_SETUP)


def _load_pair_receipt(backend: Any) -> bytes:
    return _load_receipt_for(backend, enrollment._PAIR_SETUP)


def _load_receipt_for(backend: Any, protocol: enrollment._SetupProtocol) -> bytes:
    enrollment._setup_protocol(protocol)
    for path in ("C:\\", r"C:\ProgramData"):
        backend.observe(path, directory=True, protected=False)
    for path in (_METADATA_ROOT, _RECORD_ROOT):
        backend.observe(path, directory=True)
    intent = contract._document(backend.read_public(_INTENT_PATH, 16384), 16384)
    contract._exact(
        intent,
        "schema_version generation issued_at_ms expires_at_ms owner_sid owner_token_id owner_process_id owner_created_filetime source private_profile scope bootstrap_storage_precedes_intent",
    )
    contract._require(
        intent["schema_version"] == protocol.schema("setup-intent")
        and intent["scope"] == "fresh_disposable_local_host_create_only"
        and intent["bootstrap_storage_precedes_intent"] is True
    )
    generation = contract._hex(intent["generation"], 32)
    contract._require(intent["owner_sid"] == backend.owner.user_sid)
    contract._require(
        intent["private_profile"] == enrollment._private_profile_for(generation, protocol)
    )
    issued = contract._int(intent["issued_at_ms"], 1, 2**63 - 1 - 900000)
    contract._require(
        type(intent["expires_at_ms"]) is int and intent["expires_at_ms"] == issued + 900000
    )
    contract._hex(intent["owner_token_id"], 16)
    contract._hex(intent["owner_created_filetime"], 16)
    contract._int(intent["owner_process_id"], 1, 2**32 - 1)
    raw = backend.read_public(_RECEIPT_PATH, 16384)
    contract._require(type(raw) is bytes and len(raw) <= 16384)
    receipt = contract._document(raw, 16384)
    contract._exact(
        receipt,
        "schema_version original_intent_digest generation issued_at_ms expires_at_ms source private_profile account_receipt resource native_image credential_reference account_cleanup_required context_available",
    )
    contract._require(
        receipt["schema_version"] == protocol.schema("setup-receipt")
        and receipt["original_intent_digest"] == content_hash(intent)
        and receipt["account_cleanup_required"] is True
        and receipt["context_available"] is False
    )
    for key in ("generation", "issued_at_ms", "expires_at_ms", "source", "private_profile"):
        contract._require(receipt[key] == intent[key])
    account = contract._document(backend.read_public(_ACCOUNT_PATH, 4096), 4096)
    contract._exact(
        account,
        "schema_version generation original_intent_digest account_name reader_sid owner_sid net_user_add_succeeded account_expires_seconds cleanup_obligation",
    )
    contract._require(
        account == receipt["account_receipt"]
        and account["schema_version"] == "bluefire.windows-file-owned-account.v1"
        and account["generation"] == generation
        and account["original_intent_digest"] == content_hash(intent)
        and account["owner_sid"] == backend.owner.user_sid
        and account["net_user_add_succeeded"] is True
        and account["account_name"] == "bf_" + generation[:16]
        and type(account["account_expires_seconds"]) is int
        and account["account_expires_seconds"] == intent["expires_at_ms"] // 1000
        and account["cleanup_obligation"] == "retained_account_and_objects_not_deleted"
    )
    contract._resource(receipt["resource"])
    contract._require(account["reader_sid"] == receipt["resource"]["reader_sid"])
    contract._require(
        contract._document(backend.read_public(_PROFILE_PATH, 4096), 4096)
        == receipt["private_profile"]
    )
    source = receipt["source"]
    enrollment._source_document_for(source, protocol)
    contract._require(source["native_image"] == receipt["native_image"])
    reference = receipt["credential_reference"]
    host = {
        "runner_profile_id": receipt["private_profile"]["profile_id"],
        "profile_digest": receipt["private_profile"]["policy_digest"],
        "native_generation": content_hash(receipt["native_image"]),
        "host_id": content_hash(
            {
                "schema_version": "bluefire.windows-local-account-authority.v1",
                "local_owner_sid": backend.owner.user_sid,
            }
        ),
        "channel_digest": content_hash(source["transport"]),
    }
    enrollment._document_for(
        {
            "schema_version": protocol.schema("access-enrollment"),
            "enrollment_id": "win-file-enrollment-" + generation,
            "resource_id": "win-file-resource-" + generation,
            "generation": generation,
            "issued_at_ms": issued,
            "expires_at_ms": intent["expires_at_ms"],
            "setup_receipt_digest": content_hash(receipt),
            "host": host,
            "resource": receipt["resource"],
            "native_image": receipt["native_image"],
            "credential_reference": reference,
            "limits": protocol.limits(),
        },
        protocol,
    )
    contract._require(reference["identity_receipt_digest"] == content_hash(account))
    backend.verify_all()
    return cast(bytes, raw)


def read_windows_file_setup_receipt(*, deadline: float, cancelled: Any) -> bytes:
    """Read-only fixed protected provenance; expired original receipts may be read.

    This observation deadline never renews the receipt interval or enables context,
    account ownership recovery, setup replay, credentials or runtime execution.
    """
    return _read_setup_receipt_for(deadline, cancelled, enrollment._READER_SETUP)


def read_windows_file_pair_setup_receipt(*, deadline: float, cancelled: Any) -> bytes:
    """Read the fixed original paired receipt; never renew its interval."""
    return _read_setup_receipt_for(deadline, cancelled, enrollment._PAIR_SETUP)


def _read_setup_receipt_for(
    deadline: float, cancelled: Any, protocol: enrollment._SetupProtocol
) -> bytes:
    from . import _windows_file_access_setup_native as write
    from .windows_file_access_enrollment_native import _Gate
    from .windows_session_facts import current_process_principal

    gate = _Gate(deadline, cancelled)
    owner = current_process_principal()
    owner.validate()
    contract._require(owner.elevated is False)
    backend = write._NativeSetup(gate, owner, time.time_ns() // 1_000_000)
    try:
        return (
            _load_receipt(backend)
            if protocol is enrollment._READER_SETUP
            else _load_receipt_for(backend, protocol)
        )
    except Exception:
        raise WindowsFileSetupError(
            "receipt_observation", bootstrap_mutated=False, intent_persisted=False
        ) from None
    finally:
        backend.close()
        gate.check()
