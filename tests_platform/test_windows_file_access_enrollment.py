"""Declared synthetic setup facts only; no native or authenticated enrollment."""

from __future__ import annotations

import copy
import hashlib
import io
import json
from contextlib import nullcontext
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_enrollment as module
from bluefire.file_access_contract import FileAccessContractError
from bluefire.util import canonical_json_bytes, content_hash
from bluefire.windows_session_facts import WindowsPrincipalFacts
from tests_platform.test_windows_file_access_native_wire import fixture

NOW_MS = 100000


def declared_candidate():
    _, expected = fixture()
    generation = expected["generation"]
    image = {
        "schema_version": "bluefire.windows-file-native-image.v1",
        "image_name": "bluefire-runner.exe",
        "identity": {"volume_serial": "fedcba9876543210", "file_id": "9" * 32},
        "size_bytes": 1024,
        "sha256": "sha256:" + "6" * 64,
        "architecture": "x86_64",
        "worker_schema": "bluefire.windows-file-worker-request.v1",
        "read_schema": "bluefire.windows-fixed-read.v1",
    }
    host = copy.deepcopy(expected["host"])
    host["native_generation"] = content_hash(image)
    row = {
        "schema_version": module.SCHEMA,
        "enrollment_id": "win-file-enrollment-" + generation,
        "resource_id": "win-file-resource-" + generation,
        "generation": generation,
        "issued_at_ms": NOW_MS - 1,
        "expires_at_ms": NOW_MS + 1000,
        "setup_receipt_digest": "sha256:" + "7" * 64,
        "host": host,
        "resource": copy.deepcopy(expected["resource"]),
        "native_image": image,
        "credential_reference": {
            "schema_version": "bluefire.windows-file-reader-reference.v1",
            "reference": "secret-ref:windows-file-reader-" + generation,
            "secret_provider": "windows-dpapi-current-user.v1",
            "generation": generation,
            "reader_sid": expected["resource"]["reader_sid"],
            "identity_receipt_digest": "sha256:" + "1" * 64,
            "protected_sha256": "sha256:" + "2" * 64,
            "purpose_digest": "",
        },
        "limits": {"max_reads": 1, "max_read_bytes": 1048576, "per_request_ms": 5000},
    }
    row["credential_reference"]["purpose_digest"] = module._purpose(row)
    return row


def declared_snapshots(row, candidate):
    record = {"volume_serial": "fedcba9876543210", "file_id": "8" * 32}
    anchor = {
        "schema_version": "bluefire.windows-file-setup-anchor.v1",
        "enrollment_id": row["enrollment_id"],
        "generation": row["generation"],
        "host_id": row["host"]["host_id"],
        "record_identity": record,
        "enrollment_digest": candidate.consistency_digest,
        "setup_receipt_digest": row["setup_receipt_digest"],
        "image_sha256": row["native_image"]["sha256"],
        "credential_binding_digest": content_hash(row["credential_reference"]),
    }
    observations = {
        name: copy.deepcopy(row[name])
        for name in ("host", "resource", "native_image", "credential_reference")
    }
    observations["account_name"] = candidate.reader_account
    observations["account_sid"] = row["resource"]["reader_sid"]
    owner = WindowsPrincipalFacts(4001, 555, row["resource"]["owner_sid"], 11, 22, 33, 2, False)
    return anchor, record, observations, owner


def test_candidate_derives_fixed_path_account_and_never_claims_verification():
    row = declared_candidate()
    candidate = module.parse_windows_enrollment_candidate(row, now_ms=NOW_MS)
    assert (
        candidate.resource_path
        == r"C:\BlueFire\EndpointAccess\0123456789abcdef0123456789abcdef\records.jsonl"
    )
    assert candidate.reader_account == "bf_0123456789abcdef"
    assert candidate.consistency_digest == content_hash(row)
    assert not hasattr(candidate, "verified") and not hasattr(candidate, "available")
    with pytest.raises(FrozenInstanceError):
        candidate._raw = b"changed"
    row["resource"]["reader_sid"] = "S-1-5-21-101-202-303-1003"
    assert candidate.consistency_digest != content_hash(row)


@pytest.mark.parametrize(
    "fault",
    [
        "unknown",
        "generation",
        "path",
        "account",
        "sid_alias",
        "same_sid",
        "sid_authority",
        "image_name",
        "image_arch",
        "image_hash",
        "credential_generation",
        "credential_sid",
        "provider",
        "password",
        "float",
        "bool",
        "oversize",
    ],
)
def test_closed_candidate_refuses_malformed_scope_identity_image_or_private_data(fault):
    row = declared_candidate()
    if fault == "unknown":
        row["verified"] = True
    elif fault == "generation":
        row["generation"] = "0" * 32
    elif fault == "path":
        row["resource"]["path"] = r"C:\other\records.jsonl"
    elif fault == "account":
        row["credential_reference"]["account"] = "Administrator"
    elif fault == "sid_alias":
        row["resource"]["reader_sid"] = "S-1-5-21-0101-202-303-1002"
    elif fault == "same_sid":
        row["resource"]["reader_sid"] = row["resource"]["owner_sid"]
    elif fault == "sid_authority":
        row["resource"]["reader_sid"] = "S-1-5-21-101-202-304-1002"
    elif fault == "image_name":
        row["native_image"]["image_name"] = "caller.exe"
    elif fault == "image_arch":
        row["native_image"]["architecture"] = "unknown"
    elif fault == "image_hash":
        row["native_image"]["sha256"] = "sha256:" + "3" * 64
    elif fault == "credential_generation":
        row["credential_reference"]["generation"] = "0" * 32
    elif fault == "credential_sid":
        row["credential_reference"]["reader_sid"] = row["resource"]["owner_sid"]
    elif fault == "provider":
        row["credential_reference"]["secret_provider"] = "plaintext"
    elif fault == "password":
        row["credential_reference"]["password"] = "synthetic"
    elif fault == "float":
        row["resource"]["size_bytes"] = 13.0
    elif fault == "bool":
        row["limits"]["max_reads"] = True
    else:
        row["host"]["runner_profile_id"] = "x" * (module.MAX_ENROLLMENT_BYTES + 1)
    with pytest.raises(FileAccessContractError) as error:
        module.parse_windows_enrollment_candidate(row, now_ms=NOW_MS)
    assert error.value.__cause__ is None and error.value.__suppress_context__
    assert "synthetic" not in str(error.value)


@pytest.mark.parametrize("now", [NOW_MS - 2, NOW_MS + 1000, True, 1.0])
def test_stale_future_or_noninteger_candidate_time_refused(now):
    with pytest.raises(FileAccessContractError):
        module.parse_windows_enrollment_candidate(declared_candidate(), now_ms=now)


@pytest.mark.parametrize(
    "payload",
    [
        b"\xff",
        b"\xef\xbb\xbf{}",
        b'{"generation":1,"generation":2}',
        b"{}".decode().encode("utf-16"),
    ],
)
def test_candidate_requires_bounded_strict_utf8_and_unique_json_keys(payload):
    with pytest.raises(FileAccessContractError):
        module.parse_windows_enrollment_candidate(payload, now_ms=NOW_MS)


def test_matching_declared_fake_snapshots_still_cannot_enable_runtime(monkeypatch):
    from bluefire import _windows_file_access_enrollment_observe as observation

    def unavailable(**kwargs):
        raise RuntimeError("No concrete producer in this pure consistency test")

    monkeypatch.setattr(observation, "observe", unavailable)
    row = declared_candidate()
    candidate = module.parse_windows_enrollment_candidate(row, now_ms=NOW_MS)
    anchor, record, observations, owner = declared_snapshots(row, candidate)
    assert (
        module._match_candidate_observations(
            candidate,
            anchor_bytes=canonical_json_bytes(anchor),
            record_identity=record,
            owner=owner,
            observed_bytes=canonical_json_bytes(observations),
        )
        is None
    )
    with pytest.raises(module.WindowsEnrollmentUnavailable):
        module.read_windows_file_access_enrollment(now_ms=NOW_MS)
    with pytest.raises(TypeError):
        module.read_windows_file_access_enrollment(now_ms=NOW_MS, verified=True)


@pytest.mark.parametrize(
    "fault",
    [
        "anchor_hash",
        "anchor_generation",
        "anchor_host",
        "anchor_image",
        "anchor_credential",
        "anchor_extra",
        "record_high_volume",
        "record_high_file",
        "resource",
        "account",
        "owner",
        "elevated",
        "native_image",
        "channel",
    ],
)
def test_declared_anchor_and_native_snapshot_drift_is_refused_without_trust_claim(fault):
    row = declared_candidate()
    candidate = module.parse_windows_enrollment_candidate(row, now_ms=NOW_MS)
    anchor, record, observations, owner = declared_snapshots(row, candidate)
    if fault == "anchor_hash":
        anchor["enrollment_digest"] = "sha256:" + "0" * 64
    elif fault == "anchor_generation":
        anchor["generation"] = "0" * 32
    elif fault == "anchor_host":
        anchor["host_id"] = "sha256:" + "0" * 64
    elif fault == "anchor_image":
        anchor["image_sha256"] = "sha256:" + "0" * 64
    elif fault == "anchor_credential":
        anchor["credential_binding_digest"] = "sha256:" + "0" * 64
    elif fault == "anchor_extra":
        anchor["verified"] = True
    elif fault == "record_high_volume":
        record = {**record, "volume_serial": "7edcba9876543210"}
    elif fault == "record_high_file":
        record = {**record, "file_id": "7" + "8" * 31}
    elif fault == "resource":
        observations["resource"]["file_identity"]["file_id"] = "f" * 32
    elif fault == "account":
        observations["account_name"] = "bf_0000000000000000"
    elif fault == "owner":
        owner = WindowsPrincipalFacts(
            4001, 555, row["resource"]["reader_sid"], 11, 22, 33, 2, False
        )
    elif fault == "elevated":
        owner = WindowsPrincipalFacts(4001, 555, row["resource"]["owner_sid"], 11, 22, 33, 2, True)
    elif fault == "native_image":
        observations["native_image"]["identity"]["file_id"] = "f" * 32
    else:
        observations["host"]["channel_digest"] = "sha256:" + "0" * 64
    with pytest.raises(FileAccessContractError):
        module._match_candidate_observations(
            candidate,
            anchor_bytes=canonical_json_bytes(anchor),
            record_identity=record,
            owner=owner,
            observed_bytes=canonical_json_bytes(observations),
        )


def test_full_width_resource_and_image_ids_remain_hex_strings():
    row = declared_candidate()
    row["resource"]["file_identity"]["file_id"] = "fedcba98765432100123456789abcdef"
    candidate = module.parse_windows_enrollment_candidate(row, now_ms=NOW_MS)
    stored = json.loads(candidate._raw)
    assert stored["resource"]["file_identity"]["volume_serial"] == "fedcba9876543210"
    assert stored["resource"]["file_identity"]["file_id"] == "fedcba98765432100123456789abcdef"
    assert stored["native_image"]["identity"] == row["native_image"]["identity"]


@pytest.fixture
def observed_setup(monkeypatch):
    """Actual joining code over fake setup/files/account/channel boundaries only."""
    from bluefire import _windows_file_access_enrollment_observe as observe
    from tests_platform.test_windows_file_access_setup_lifecycle import (
        GENERATION,
        ISSUED,
        FakeBackend,
        FakeCredential,
        FakeGate,
        source_facts,
    )

    state = {"wall": ISSUED, "mono": 10.0, "fault": None, "pairs": 0, "channels": 0}
    monkeypatch.setattr(observe.time, "time_ns", lambda: state["wall"] * 1000000)
    monkeypatch.setattr(observe.time, "monotonic", lambda: state["mono"])
    monkeypatch.setattr(observe, "sys", SimpleNamespace(platform="win32"))
    backend = FakeBackend(FakeGate())
    image = b"synthetic packaged image, never executed"
    source = source_facts()
    source["native_image"]["size_bytes"] = len(image)
    source["native_image"]["sha256"] = "sha256:" + hashlib.sha256(image).hexdigest()
    source["transport"]["runner_binary_digest"] = source["native_image"]["sha256"]
    monkeypatch.setattr(observe.write, "_Credential", lambda: FakeCredential(backend))
    observe.setup._run_setup(
        backend, source, backend.owner, backend.gate, generation=GENERATION, issued=ISSUED
    )
    backend.closed = 0
    backend.owner = replace(backend.owner, elevated=False)
    row = module._document(backend.files[module.ANCHOR_PATH])
    pair = SimpleNamespace(
        record=SimpleNamespace(
            raw_bytes=backend.files[module.ANCHOR_PATH], principal=backend.owner
        ),
        anchor_bytes=backend.files[observe.setup._anchor_paths(GENERATION)[-1]],
    )
    state.update(wall=ISSUED + 1, owner=backend.owner)

    def pair_observer(**kwargs):
        assert kwargs["deadline"] == 15.0
        state["pairs"] += 1
        if state["fault"] == "pair" and state["pairs"] == 2:
            return SimpleNamespace(record=pair.record, anchor_bytes=b"changed")
        return pair

    monkeypatch.setattr(observe.reader, "observe_protected_enrollment_pair", pair_observer)
    monkeypatch.setattr(observe.session, "current_process_principal", lambda: state["owner"])
    monkeypatch.setattr(observe.write, "_NativeSetup", lambda *args: backend)
    monkeypatch.setattr(observe.write, "_require_local_machine", lambda gate: gate.check())
    monkeypatch.setattr(observe, "_resource_metadata", lambda row, gate: nullcontext())
    fixed_root = Path(r"C:\Users\actual\AppData\Local\BlueFire Nexus")
    monkeypatch.setattr(observe, "_managed_root", lambda: fixed_root)
    image_path = r"C:\Program Files\BlueFire\bluefire-runner.exe"
    backend.files[image_path] = image
    backend.identities[image_path] = source["native_image"]["identity"]
    backend.held = []
    original_observe, original_close = backend.observe, backend.close
    stream = io.BytesIO(image)

    def file_observer(path, **kwargs):
        if path == image_path:
            backend.held.append(550)
        return original_observe(path, **kwargs)

    def close():
        original_close()
        if state["fault"] == "expiry":
            state["wall"] = row["expires_at_ms"]
        elif state["fault"] == "rollback":
            state["wall"] -= 1
        elif state["fault"] == "owner":
            state["owner"] = replace(backend.owner, token_id=999)

    backend.observe, backend.close = file_observer, close
    bootstrap = SimpleNamespace(
        source="packaged",
        managed_binary=True,
        binary_digest=source["native_image"]["sha256"],
        runner_version="0.1.0",
        binary_path=Path(image_path),
    )

    class Lifecycle:
        def __init__(self, root):
            assert root == fixed_root

        def _load_active_enrollment(self):
            return "synthetic independently enrolled source"

        def _load_bootstrap(self, local):
            assert local == "synthetic independently enrolled source"
            return bootstrap

        def client_for_profile(self, profile):
            assert profile == "existing-source"
            state["channels"] += 1
            if state["fault"] == "late":
                state["mono"] = 15.0
            transport = copy.deepcopy(source["transport"])
            if state["fault"] == "channel" and state["channels"] == 2:
                transport["server_fingerprint"] = "sha256:" + "f" * 64
            return SimpleNamespace(transport_identity=lambda: transport), None

    def read(descriptor, maximum):
        assert descriptor == 550
        data = stream.read(maximum)
        return data.replace(b"synthetic", b"different") if state["fault"] == "image" else data

    monkeypatch.setattr(observe, "ManagedRunnerLifecycle", Lifecycle)
    monkeypatch.setattr(
        observe,
        "load_runner_manifest",
        lambda **kwargs: SimpleNamespace(
            sha256=source["native_image"]["sha256"][7:],
            size=len(image),
            runner_version="0.1.0",
        ),
    )
    monkeypatch.setattr(observe, "os", SimpleNamespace(fspath=str, read=read))
    return observe, state, backend, row, bootstrap


def test_concrete_join_returns_immutable_setup_only_with_original_expiry(observed_setup):
    _, state, backend, row, _ = observed_setup
    checked = module.read_windows_file_access_enrollment(now_ms=state["wall"])
    assert type(checked) is module.VerifiedWindowsSetup
    assert checked.summary() == {
        "enrollment_id": row["enrollment_id"],
        "enrollment_digest": content_hash(row),
        "expires_at_ms": row["expires_at_ms"],
        "verification": "protected_setup_only",
    }
    assert state["pairs"] == state["channels"] == 2 and backend.closed == 1
    assert "S-1-" not in repr(checked) and "secret-ref" not in str(checked.summary())
    with pytest.raises(FrozenInstanceError):
        checked._raw = b"caller data"
    with pytest.raises(TypeError):
        module.VerifiedWindowsSetup()


@pytest.mark.parametrize(
    "fault",
    [
        "pair",
        "channel",
        "late",
        "image",
        "expiry",
        "rollback",
        "owner",
        "cleanup",
        "blob",
        "account",
        "bootstrap",
        "elevated",
    ],
)
def test_concrete_join_refuses_drift_expiry_cleanup_or_unsupported_source(observed_setup, fault):
    observe, state, backend, row, bootstrap = observed_setup
    state["fault"] = fault
    if fault == "cleanup":
        backend.fail = "cleanup"
    elif fault == "blob":
        backend.files[observe.setup._CREDENTIAL_PATH] += b"changed"
    elif fault == "account":
        backend.fail = "verify_account"
    elif fault == "bootstrap":
        bootstrap.source = "environment_override"
    elif fault == "elevated":
        state["owner"] = replace(backend.owner, elevated=True)
    with pytest.raises(module.WindowsEnrollmentUnavailable) as caught:
        module.read_windows_file_access_enrollment(now_ms=state["wall"])
    assert "synthetic" not in str(caught.value) and caught.value.__cause__ is None
    assert backend.closed == (0 if fault == "elevated" else 1)


@pytest.mark.parametrize("fault", [None, "identity", "descriptor", "close", "late"])
def test_metadata_join_never_requests_generated_file_data_and_closes_every_handle(
    monkeypatch, fault
):
    from bluefire import _windows_file_access_enrollment_observe as observe

    row = declared_candidate()
    objects, closed, policies = {}, [], []
    late = [False]
    identities = [*row["resource"]["ancestors"], row["resource"]["file_identity"]]
    paths = (
        "C:\\",
        r"C:\BlueFire",
        r"C:\BlueFire\EndpointAccess",
        "C:\\BlueFire\\EndpointAccess\\" + row["generation"],
        "C:\\BlueFire\\EndpointAccess\\" + row["generation"] + r"\records.jsonl",
    )

    def open_metadata(path, *, directory, data):
        assert data is False
        index = paths.index(str(path))
        assert directory is (index < 4)
        descriptor = 100 + len(objects)
        objects[descriptor] = index
        return descriptor

    def facts(descriptor, *, directory):
        index = objects[descriptor]
        identity = identities[index]
        full_identity = (
            int(identity["volume_serial"], 16),
            int.from_bytes(bytes.fromhex(identity["file_id"]), "little"),
        )
        if fault == "identity" and index == 4 and len(objects) == 10:
            full_identity = full_identity[0], full_identity[1] ^ (1 << 127)
        return SimpleNamespace(
            identity=full_identity,
            final_path="\\\\?\\" + paths[index],
            size=0 if directory else row["resource"]["size_bytes"],
        )

    monkeypatch.setattr(observe.handles, "open_observation", open_metadata)
    monkeypatch.setattr(observe.handles, "inspect_observation", facts)
    monkeypatch.setattr(observe, "_handle_from_descriptor", lambda descriptor: descriptor)

    def dacl(descriptor, policy, state):
        policies.append(state)
        if fault == "descriptor" and policies.count(row["resource"]["state"]) == 2:
            raise RuntimeError("synthetic descriptor changed")

    def close(descriptor):
        closed.append(descriptor)
        if fault == "close" and descriptor == 100:
            raise OSError("synthetic ambiguous close")

    def current():
        if late[0]:
            raise RuntimeError("synthetic original deadline")

    monkeypatch.setattr(observe, "verify_resource_dacl", dacl)
    monkeypatch.setattr(observe, "os", SimpleNamespace(close=close))
    with pytest.raises(Exception) if fault else nullcontext():
        with observe._resource_metadata(row, SimpleNamespace(check=current)):
            assert len(objects) == 5
            late[0] = fault == "late"
    assert len(objects) == len(closed) and set(closed) == set(objects)
    if not fault:
        assert len(objects) == 10 and policies.count(row["resource"]["state"]) == 3


@pytest.mark.parametrize("offset", [-5000, 1])
def test_status_observation_does_not_accept_stale_or_future_caller_clock(
    observed_setup, monkeypatch, offset
):
    observe, state, backend, _, _ = observed_setup
    monkeypatch.setattr(
        observe.session, "current_process_principal", lambda: pytest.fail("No native query")
    )
    with pytest.raises(module.WindowsEnrollmentUnavailable):
        module.read_windows_file_access_enrollment(now_ms=state["wall"] + offset)
    assert backend.closed == state["pairs"] == state["channels"] == 0


def test_post_setup_join_rechecks_local_machine_role_before_observing_pair(
    observed_setup, monkeypatch
):
    observe, state, backend, _, _ = observed_setup
    monkeypatch.setattr(
        observe.write,
        "_require_local_machine",
        lambda gate: (_ for _ in ()).throw(RuntimeError("synthetic DC refusal")),
    )
    with pytest.raises(module.WindowsEnrollmentUnavailable):
        module.read_windows_file_access_enrollment(now_ms=state["wall"])
    assert backend.closed == state["pairs"] == state["channels"] == 0
