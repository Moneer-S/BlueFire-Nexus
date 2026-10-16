"""Real correction joins with synthetic native metadata, accounts and DPAPI only."""

from __future__ import annotations

import copy
import io
import struct
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_correction_admission as admission
from bluefire import windows_file_access_correction_credential as module
from bluefire import windows_file_access_correction_observation as observation
from bluefire import windows_file_access_enrollment as enrollment
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_windows_file_access_enrollment import observed_setup as observed_setup
from tests_platform.test_windows_file_access_pair_observation import pair_observed as pair_observed
from tests_platform.test_windows_file_access_setup_lifecycle import ISSUED

DESCRIPTOR = "sha256:" + "a" * 64


@pytest.fixture
def correction(pair_observed, monkeypatch):
    native, state, backend, record = pair_observed
    image = next(path for path in backend.files if path.endswith("bluefire-runner.exe"))
    streams = {}
    old_observe = backend.observe

    def observe_file(path, **kwargs):
        result = old_observe(path, **kwargs)
        if path == image:
            streams[backend.held[-1]] = io.BytesIO(backend.files[path])
        return result

    backend.observe = observe_file
    monkeypatch.setattr(
        native, "os", SimpleNamespace(fspath=str, read=lambda fd, size: streams[fd].read(size))
    )
    checked_setup = enrollment.read_windows_file_pair_enrollment(
        now_ms=state["wall"], deadline=14.0
    )
    state.update(resource_state="readable", descriptor=DESCRIPTOR, metadata=[])

    @contextmanager
    def metadata(row, gate, *, descriptor_sha256=None):
        gate.check()
        state["metadata"].append(row["resource"]["state"])
        assert row["resource"]["state"] == state["resource_state"]
        if descriptor_sha256 is not None:
            assert state["descriptor"] == descriptor_sha256
        yield state["descriptor"]
        gate.check()

    monkeypatch.setattr(native, "_resource_metadata", metadata)
    binding = {
        "schema_version": admission.BINDING_SCHEMA,
        "operation_job_id": "job-" + "b" * 32,
        "control_owner_id": admission.common._control_id_for(record, admission.common._PAIR_SETUP),
        "prior_control_digest": "sha256:" + "c" * 64,
        "baseline_digest": "sha256:" + "d" * 64,
        "enrollment_digest": content_hash(record),
        "protected_receipt_digest": content_hash(
            admission.pair.checked_provenance(checked_setup)[1]
        ),
        "generation": record["generation"],
        "control_revision": 3,
        "previous_descriptor_sha256": DESCRIPTOR,
        "target_resource": {**record["resource"], "state": "metadata_only"},
        "issued_at_ms": ISSUED + 2,
        "expires_at_ms": ISSUED + 10002,
    }
    state["wall"] = ISSUED + 3
    value = observation.CorrectionObservationInput(
        checked_setup, canonical_json_bytes(binding), DESCRIPTOR
    )
    state["resource_state"] = "metadata_only"
    checked = observation.observe_correction_postimage(
        value, now_ms=state["wall"], deadline=14.0, cancelled=lambda: False
    )
    original_context, expected = admission.build_retest_original(
        binding, checked_setup, issued_at_ms=state["wall"], reviewed_by="owner-review"
    )
    original = module.wire.validate_correction_original_reservation(
        original_context, expected_binding=expected
    )

    def utc():
        return datetime.fromtimestamp(state["wall"] / 1000, timezone.utc)

    packet = module.wire.prepare_correction_packet(
        original,
        challenge="f" * 64,
        clock=utc(),
        monotonic_now=state["mono"],
        original_monotonic_deadline=14.0,
    )
    cancelled = threading.Event()
    events, decrypted, wiped = [], [], []
    control = SimpleNamespace(fault=None)

    def event(name):
        events.append(name)
        if control.fault == name:
            raise RuntimeError("synthetic private failure")

    def revalidate():
        event("claim")

    def ready():
        event("fresh-committed-ready")

    class Provider:
        provider_id = "windows-dpapi-current-user.v1"

        def unprotect(self, purpose, opaque):
            event("decrypt")
            assert purpose == module.pair._purpose(record) == backend.purpose
            assert opaque == backend.files[module.setup._CREDENTIAL_PATH]
            decrypted.append(purpose)
            if control.fault == "late-provider":
                state["wall"] = binding["expires_at_ms"]
            elif control.fault == "cancel-provider":
                cancelled.set()
            elif control.fault == "owner-provider":
                state["owner"] = replace(backend.owner, token_id=999)
            return b"A\0b\0"

    def backend_factory(gate, owner, issued):
        assert owner == backend.owner and issued == ISSUED + 3
        backend.gate = gate
        return backend

    old_wipe = module._wipe

    def wipe(value):
        old_wipe(value)
        if value is not None:
            wiped.append(value)

    monkeypatch.setattr(module, "_utc", utc)
    monkeypatch.setattr(module.native_setup, "_NativeSetup", backend_factory)
    monkeypatch.setattr(module, "WindowsDPAPISecretProvider", Provider)
    monkeypatch.setattr(module, "_wipe", wipe)
    producer = module.CorrectionBeginProducer(
        checked,
        original,
        packet,
        revalidate_original=revalidate,
        require_ready_allowance=ready,
        cancellation_event=cancelled,
    )
    prefix = module.wire.correction_begin_prefix(packet, clock=utc(), monotonic_now=state["mono"])
    return SimpleNamespace(**locals())


def test_real_postimage_reobserved_and_one_new_ready_releases_one_v3_frame(correction):
    c = correction
    before = c.state["pairs"]
    result = c.producer(c.prefix)
    try:
        assert result[4:12] == b"BFWFBEG3"
        assert result[4:160] == c.prefix
        assert result[160:] == b"\x02\0A\0b\0"
        assert struct.unpack_from("<I", result)[0] == len(result) - 4
        assert c.state["pairs"] == before + 2 and len(c.decrypted) == 1
        assert c.events.count("claim") == c.events.count("fresh-committed-ready") == 4
        assert c.producer.credential_cleanup == "verified"
        assert c.wiped and all(not any(value) for value in c.wiped)
        assert "S-1-" not in repr(c.producer)
        before_events = list(c.events)
        with pytest.raises(module.WindowsCorrectionCredentialError):
            c.producer(c.prefix)
        assert c.events == before_events
        assert (
            c.checked._raw == c.checked_setup._raw
            and c.checked._receipt == c.checked_setup._receipt
        )
    finally:
        result[:] = b"\0" * len(result)


@pytest.mark.parametrize(
    "fault",
    [
        "claim",
        "fresh-committed-ready",
        "descriptor",
        "account",
        "pair",
        "channel",
        "cleanup",
        "decrypt",
        "late-provider",
        "cancel-provider",
        "owner-provider",
    ],
)
def test_refusal_is_private_consumed_and_never_retries(correction, fault):
    c = correction
    c.control.fault = fault
    c.state["pairs"] = c.state["channels"] = 0
    if fault == "descriptor":
        c.state["descriptor"] = "sha256:" + "0" * 64
    elif fault in ("pair", "channel"):
        c.state["fault"] = fault
    elif fault in ("account", "cleanup"):
        c.backend.fail = "verify_account" if fault == "account" else "cleanup"
    with pytest.raises(module.WindowsCorrectionCredentialError) as error:
        c.producer(c.prefix)
    assert error.value.__cause__ is None and error.value.__suppress_context__
    assert "synthetic" not in str(error.value)
    assert all(not any(value) for value in c.wiped)
    if fault in ("claim", "fresh-committed-ready"):
        assert c.producer.credential_cleanup == "not_started" and c.state["pairs"] == 0
    elif fault in ("descriptor", "account", "pair", "channel", "cleanup", "decrypt"):
        assert c.producer.credential_cleanup == "unknown"
    else:
        assert c.producer.credential_cleanup == "verified"
    before = (list(c.events), len(c.decrypted), c.backend.closed)
    with pytest.raises(module.WindowsCorrectionCredentialError):
        c.producer(c.prefix)
    assert before == (c.events, len(c.decrypted), c.backend.closed)


def test_preimage_is_current_readable_descriptor_without_setup_reinterpretation(correction):
    c = correction
    c.state["resource_state"] = "readable"
    digest = observation.observe_correction_preimage(
        c.checked_setup, now_ms=c.state["wall"], deadline=14.0, cancelled=lambda: False
    )
    assert digest == DESCRIPTOR
    c.state["resource_state"] = "metadata_only"
    with pytest.raises(observation.WindowsCorrectionObservationError):
        observation.observe_correction_preimage(
            c.checked_setup, now_ms=c.state["wall"], deadline=14.0, cancelled=lambda: False
        )
    with pytest.raises(enrollment.WindowsEnrollmentUnavailable):
        enrollment.read_windows_file_pair_enrollment(now_ms=c.state["wall"], deadline=14.0)
    with pytest.raises(TypeError):
        observation.VerifiedWindowsCorrectionPostimage()
    with pytest.raises(module.wire.NativeWireError):
        module.pair.checked_provenance(c.checked)


@pytest.mark.parametrize(
    "fault",
    ["receipt", "resource", "expiry", "noncanonical", "descriptor", "deadline", "cancelled"],
)
def test_postimage_rejects_mutated_binding_and_stale_native_observation(correction, fault):
    c = correction
    binding = copy.deepcopy(c.binding)
    deadline = 14.0

    def cancelled():
        return fault == "cancelled"

    descriptor = DESCRIPTOR
    if fault == "receipt":
        binding["protected_receipt_digest"] = "sha256:" + "0" * 64
    elif fault == "resource":
        binding["target_resource"]["sha256"] = "sha256:" + "0" * 64
    elif fault == "expiry":
        c.state["wall"] = binding["expires_at_ms"]
    elif fault == "descriptor":
        descriptor = "sha256:" + "0" * 64
    elif fault == "deadline":
        deadline = c.state["mono"]
    raw = canonical_json_bytes(binding) + (b" " if fault == "noncanonical" else b"")
    with pytest.raises(observation.WindowsCorrectionObservationError):
        observation.observe_correction_postimage(
            observation.CorrectionObservationInput(c.checked_setup, raw, descriptor),
            now_ms=c.state["wall"],
            deadline=deadline,
            cancelled=cancelled,
        )


def test_stop_and_wrong_prefix_do_not_decrypt_or_reobserve(correction):
    c = correction
    c.producer.request_stop()
    assert not c.cancelled.is_set()
    before = c.state["pairs"]
    with pytest.raises(module.WindowsCorrectionCredentialError):
        c.producer(c.prefix)
    assert c.events == c.decrypted == [] and c.state["pairs"] == before


@pytest.mark.parametrize(
    "fault", ["record", "receipt", "credential", "source_image", "source_channel"]
)
def test_original_protected_setup_drift_refuses_before_decrypt(correction, fault):
    c = correction
    if fault == "record":
        c.backend.files[admission.common.ANCHOR_PATH] += b"changed"
    elif fault == "receipt":
        c.backend.files[module.setup._RECEIPT_PATH] += b"changed"
    elif fault == "credential":
        c.backend.files[module.setup._CREDENTIAL_PATH] += b"changed"
    elif fault == "source_image":
        c.backend.files[c.image] = c.backend.files[c.image].replace(b"synthetic", b"different")
    else:
        c.state["fault"] = "channel"
        c.state["channels"] = 0
    with pytest.raises(module.WindowsCorrectionCredentialError):
        c.producer(c.prefix)
    assert c.decrypted == [] and c.producer.credential_cleanup == "unknown"


@pytest.mark.parametrize("fault", [None, "descriptor", "cleanup"])
def test_concrete_metadata_postimage_pins_digest_and_never_opens_data(monkeypatch, fault):
    from bluefire import _windows_file_access_enrollment_observe as native
    from tests_platform.test_windows_file_access_enrollment import declared_candidate

    row = declared_candidate()
    row["resource"]["state"] = "metadata_only"
    identities = [*row["resource"]["ancestors"], row["resource"]["file_identity"]]
    root = "C:\\BlueFire\\EndpointAccess\\" + row["generation"]
    paths = ("C:\\", r"C:\BlueFire", r"C:\BlueFire\EndpointAccess", root, root + r"\records.jsonl")
    opened, closed, states = {}, [], []

    def open_metadata(path, *, directory, data):
        assert data is False
        index = paths.index(str(path))
        assert directory is (index < 4)
        descriptor = 100 + len(opened)
        opened[descriptor] = index
        return descriptor

    def facts(descriptor, *, directory):
        index = opened[descriptor]
        expected = identities[index]
        return SimpleNamespace(
            identity=(
                int(expected["volume_serial"], 16),
                int.from_bytes(bytes.fromhex(expected["file_id"]), "little"),
            ),
            final_path="\\\\?\\" + paths[index],
            size=0 if directory else row["resource"]["size_bytes"],
        )

    def dacl(descriptor, policy, *, state):
        states.append(state)
        return (
            "sha256:" + "0" * 64
            if fault == "descriptor" and opened[descriptor] == 4
            else DESCRIPTOR
        )

    def close(descriptor):
        closed.append(descriptor)
        if fault == "cleanup" and descriptor == 100:
            raise OSError("synthetic closure ambiguity")

    monkeypatch.setattr(native.handles, "open_observation", open_metadata)
    monkeypatch.setattr(native.handles, "inspect_observation", facts)
    monkeypatch.setattr(native, "_handle_from_descriptor", lambda value: value)
    monkeypatch.setattr(native, "verify_resource_dacl", dacl)
    monkeypatch.setattr(native, "os", SimpleNamespace(close=close))

    def observe():
        with native._resource_metadata(
            row, SimpleNamespace(check=lambda: None), descriptor_sha256=DESCRIPTOR
        ) as digest:
            assert digest == DESCRIPTOR

    if fault is None:
        observe()
        assert len(opened) == 10 and states.count("metadata_only") == 3
    else:
        with pytest.raises(module.wire.NativeWireError):
            observe()
    assert len(opened) == len(closed) and set(opened) == set(closed)
