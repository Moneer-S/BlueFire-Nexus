"""Concrete read-only post-setup observation, never task or credential admission."""

from __future__ import annotations

import hashlib
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from . import _windows_file_access_native_contract as contract
from . import _windows_file_access_setup_native as write
from . import windows_file_access_admission as admission
from . import windows_file_access_enrollment_native as native
from . import windows_file_access_enrollment_reader as reader
from . import windows_file_access_enrollment_setup as setup
from . import windows_file_access_handles as handles
from . import windows_session_facts as session
from .runner_bootstrap import load_runner_manifest
from .runner_lifecycle import ManagedRunnerLifecycle
from .util import canonical_json_bytes, content_hash
from .windows_file_access_dacl import verify_resource_dacl
from .windows_file_access_policy import WindowsFileAccessPolicy
from .windows_file_access_setup_child import _managed_root
from .windows_owner_acl import _handle_from_descriptor


@contextmanager
def _resource_metadata(
    row: dict[str, Any], gate: native._Gate, *, descriptor_sha256: str | None = None
) -> Iterator[str | None]:
    resource = row["resource"]
    policy = WindowsFileAccessPolicy(resource["owner_sid"], resource["reader_sid"])
    root = "C:\\BlueFire\\EndpointAccess\\" + row["generation"]
    paths = ("C:\\", r"C:\BlueFire", r"C:\BlueFire\EndpointAccess", root, root + r"\records.jsonl")
    identities = [*resource["ancestors"], resource["file_identity"]]
    held: list[int] = []
    facts = []
    selected_descriptor: str | None = None

    def check(descriptor: int, index: int):
        nonlocal selected_descriptor
        gate.check()
        value = handles.inspect_observation(descriptor, directory=index < 4)
        volume, file_id = native.file_identity_wire(*value.identity)
        contract._require(
            value.final_path == "\\\\?\\" + paths[index]
            and {"volume_serial": volume, "file_id": file_id} == identities[index]
            and (index < 4 or value.size == resource["size_bytes"])
        )
        if index:
            digest = verify_resource_dacl(
                _handle_from_descriptor(descriptor),
                policy,
                state="directory" if index < 4 else resource["state"],
            )
            if index == 4 and descriptor_sha256 is not None:
                contract._require(digest == descriptor_sha256)
            if index == 4:
                selected_descriptor = digest
        gate.check()
        return value

    try:
        for index, path in enumerate(paths):
            gate.check()
            descriptor = handles.open_observation(Path(path), directory=index < 4, data=False)
            held.append(descriptor)
            facts.append(check(descriptor, index))
        yield selected_descriptor
        for index, path in enumerate(paths):
            contract._require(check(held[index], index) == facts[index])
            gate.check()
            fresh = handles.open_observation(Path(path), directory=index < 4, data=False)
            held.append(fresh)
            contract._require(check(fresh, index) == facts[index])
    finally:
        failed = False
        for descriptor in reversed(held):
            try:
                os.close(descriptor)
            except Exception:
                failed = True
        contract._require(not failed)
        gate.check()


def _image_and_channel(
    backend: Any, receipt: dict[str, Any], gate: native._Gate, protocol=admission._READER_SETUP
):
    lifecycle = ManagedRunnerLifecycle(_managed_root())
    local = lifecycle._load_active_enrollment()
    bootstrap = lifecycle._load_bootstrap(local)
    source = receipt["source"]
    manifest = load_runner_manifest(platform_name="windows", architecture="x86_64")
    contract._require(
        bootstrap.source == "packaged"
        and bootstrap.managed_binary
        and bootstrap.binary_digest
        == source["native_image"]["sha256"]
        == "sha256:" + manifest.sha256
        and bootstrap.runner_version == manifest.runner_version
    )
    # The original actual-binary capability is reusable only for the identical
    # freshly pinned image. This observation never executes a capability query.
    admission._capability_for(
        canonical_json_bytes(source["capability"]), bootstrap.runner_version, protocol
    )
    client, _ = lifecycle.client_for_profile(source["source_profile_id"])
    gate.check()
    contract._require(dict(client.transport_identity()) == source["transport"])
    path = os.fspath(bootstrap.binary_path)
    contract._require(Path(path).name == "bluefire-runner.exe")
    facts = backend.observe(path, directory=False, protected=False)
    image = source["native_image"]
    contract._require(facts == {"identity": image["identity"], "size": image["size_bytes"]})
    contract._require(image["size_bytes"] == manifest.size)
    digest, total = hashlib.sha256(), 0
    descriptor = backend.held[-1]
    while total <= manifest.size:
        gate.check()
        chunk = os.read(descriptor, min(65536, manifest.size + 1 - total))
        if not chunk:
            break
        digest.update(chunk)
        total += len(chunk)
    contract._require(total == manifest.size and "sha256:" + digest.hexdigest() == image["sha256"])
    gate.check()
    return lifecycle, client


def observe(*, now_ms: int) -> tuple[bytes, bytes]:
    """Derive setup facts without decrypting credentials or reading generated data.

    This is a finite cooperative observation, not a worker hard deadline. Late
    APIs, changed facts or any uncertain handle closure never return verification.
    The original protected enrollment expiry is checked again after all cleanup.
    """
    return _observe_for(now_ms=now_ms, protocol=admission._READER_SETUP)


def observe_pair(
    *, now_ms: int, deadline: float | None = None, cancelled: Callable[[], bool] | None = None
) -> tuple[bytes, bytes]:
    return _observe_for(
        now_ms=now_ms, protocol=admission._PAIR_SETUP, deadline=deadline, cancelled=cancelled
    )


def observe_status(*, now_ms: int) -> tuple[bytes, bytes]:
    return _observe_for(now_ms=now_ms, protocol=None)


def observe_correction(
    *,
    now_ms: int,
    original_raw: bytes,
    original_receipt: bytes,
    target_resource: dict[str, Any],
    descriptor_sha256: str,
    deadline: float,
    cancelled: Callable[[], bool],
) -> tuple[bytes, bytes]:
    """Observe an explicit correction postimage without renewing the v2 setup."""
    return _observe_for(
        now_ms=now_ms,
        protocol=admission._PAIR_SETUP,
        deadline=deadline,
        cancelled=cancelled,
        correction=(original_raw, original_receipt, target_resource, descriptor_sha256),
    )


def observe_correction_preimage(
    *, now_ms: int, deadline: float, cancelled: Callable[[], bool]
) -> tuple[bytes, bytes, str]:
    descriptor: list[str] = []
    raw, receipt = _observe_for(
        now_ms=now_ms,
        protocol=admission._PAIR_SETUP,
        deadline=deadline,
        cancelled=cancelled,
        descriptor_out=descriptor,
    )
    contract._require(len(descriptor) == 1)
    return raw, receipt, descriptor[0]


def _observe_for(
    *,
    now_ms: int,
    protocol: admission._SetupProtocol | None,
    deadline: float | None = None,
    cancelled: Callable[[], bool] | None = None,
    correction: tuple[bytes, bytes, dict[str, Any], str] | None = None,
    descriptor_out: list[str] | None = None,
) -> tuple[bytes, bytes]:
    started = time.time_ns() // 1_000_000
    contract._require(sys.platform == "win32" and now_ms <= started < now_ms + 5000)
    maximum = time.monotonic() + 5.0
    if deadline is not None:
        contract._mono(deadline)
        maximum = min(maximum, deadline)
    gate = native._Gate(maximum, cancelled if cancelled is not None else lambda: False)
    owner = session.current_process_principal()
    owner.validate()
    contract._require(owner.elevated is False)
    write._require_local_machine(gate)
    if protocol is None:
        pair = reader._observe_selected_enrollment(deadline=gate.deadline, cancelled=gate.cancelled)
        protocol = admission._protocol_from_record(pair.record.raw_bytes)
    else:
        admission._setup_protocol(protocol)
        observe_record = (
            reader.observe_protected_enrollment_pair
            if protocol is admission._READER_SETUP
            else reader.observe_protected_pair_enrollment
        )
        pair = observe_record(deadline=gate.deadline, cancelled=gate.cancelled)
    observe_record = (
        reader.observe_protected_enrollment_pair
        if protocol is admission._READER_SETUP
        else reader.observe_protected_pair_enrollment
    )
    contract._require(pair.record.principal == owner)
    row = admission._document_for(pair.record.raw_bytes, protocol)
    contract._require(row["issued_at_ms"] <= started < row["expires_at_ms"])
    if correction is not None:
        contract._require(
            protocol is admission._PAIR_SETUP
            and pair.record.raw_bytes == correction[0]
            and correction[2] == {**row["resource"], "state": "metadata_only"}
        )
        contract._digest(correction[3])
    backend = write._NativeSetup(
        gate, owner, now_ms if protocol is admission._PAIR_SETUP else started
    )
    try:
        raw_receipt = (
            setup._load_receipt(backend)
            if protocol is admission._READER_SETUP
            else setup._load_receipt_for(backend, protocol)
        )
        receipt = contract._document(raw_receipt, 16384)
        if correction is not None:
            contract._require(raw_receipt == correction[1])
        contract._require(content_hash(receipt) == row["setup_receipt_digest"])
        for name in (
            "generation",
            "issued_at_ms",
            "expires_at_ms",
            "resource",
            "native_image",
            "credential_reference",
        ):
            contract._require(receipt[name] == row[name])
        expected_host = {
            "runner_profile_id": receipt["private_profile"]["profile_id"],
            "profile_digest": receipt["private_profile"]["policy_digest"],
            "native_generation": content_hash(row["native_image"]),
            "host_id": content_hash(
                {
                    "schema_version": "bluefire.windows-local-account-authority.v1",
                    "local_owner_sid": owner.user_sid,
                }
            ),
            "channel_digest": content_hash(receipt["source"]["transport"]),
        }
        contract._require(
            row["host"] == expected_host and row["resource"]["owner_sid"] == owner.user_sid
        )
        # Retain protected record and anchor handles throughout the remaining
        # join; the pair reader independently rechecks their full native facts.
        contract._require(
            backend.read_public(admission.ANCHOR_PATH, 16384) == pair.record.raw_bytes
        )
        anchor_paths = admission._anchor_paths(row["generation"])
        for path in anchor_paths[3:-1]:
            backend.observe(path, directory=True)
        contract._require(backend.read_public(anchor_paths[-1], 4096) == pair.anchor_bytes)
        opaque = backend.read_public(setup._CREDENTIAL_PATH, native._MAX_BUFFER)
        contract._require(
            "sha256:" + hashlib.sha256(opaque).hexdigest()
            == row["credential_reference"]["protected_sha256"]
        )
        expires = receipt["account_receipt"]["account_expires_seconds"]
        backend.verify_account(row["generation"], row["resource"]["reader_sid"], expires)
        resource_check = (
            _resource_metadata(row, gate)
            if correction is None
            else _resource_metadata(
                {**row, "resource": correction[2]}, gate, descriptor_sha256=correction[3]
            )
        )
        with resource_check as descriptor_digest:
            lifecycle, client = _image_and_channel(backend, receipt, gate, protocol)
            backend.verify_all()
            contract._require(
                observe_record(deadline=gate.deadline, cancelled=gate.cancelled) == pair
            )
            backend.verify_account(row["generation"], row["resource"]["reader_sid"], expires)
            again, _ = lifecycle.client_for_profile(receipt["source"]["source_profile_id"])
            contract._require(
                dict(again.transport_identity())
                == dict(client.transport_identity())
                == receipt["source"]["transport"]
            )
            backend.current()
    finally:
        backend.close()
        gate.check()
    contract._require(session.current_process_principal() == owner)
    gate.check()
    contract._require(
        started
        <= time.time_ns() // 1_000_000
        < min(
            (now_ms if protocol is admission._PAIR_SETUP else started) + 5000, row["expires_at_ms"]
        )
    )
    if descriptor_out is not None:
        descriptor_digest = contract._digest(descriptor_digest)
        descriptor_out.append(descriptor_digest)
    return canonical_json_bytes(row), canonical_json_bytes(receipt)
