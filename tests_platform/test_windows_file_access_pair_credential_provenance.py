"""Real paired provenance joins over fake protected files and native effects.

The Ready callback is a captured test allowance, not a durable store proof.
No provenance validator, candidate parser, receipt loader or wire validator is
replaced. OS identity/files and DPAPI are synthetic and never invoked.
"""

from __future__ import annotations

import io
import json
import struct
import threading
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_pair_credential as module
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_windows_file_access_enrollment import observed_setup as observed_setup
from tests_platform.test_windows_file_access_pair_observation import pair_observed as pair_observed
from tests_platform.test_windows_file_access_pair_provenance import original_review
from tests_platform.test_windows_file_access_setup_lifecycle import ISSUED


@pytest.fixture
def provenance_begin(pair_observed, monkeypatch):
    observe, state, backend, record = pair_observed
    image_path = next(path for path in backend.files if path.endswith("bluefire-runner.exe"))
    streams = {}
    original_observe = backend.observe

    def observed_file(path, **kwargs):
        result = original_observe(path, **kwargs)
        if path == image_path:
            streams[backend.held[-1]] = io.BytesIO(backend.files[path])
        return result

    def read_image(descriptor, maximum):
        value = streams[descriptor].read(maximum)
        return value.replace(b"synthetic", b"different") if state["fault"] == "image" else value

    backend.observe = observed_file
    monkeypatch.setattr(observe, "os", SimpleNamespace(fspath=str, read=read_image))
    checked = module.enrollment.read_windows_file_pair_enrollment(
        now_ms=state["wall"], deadline=14.0
    )
    assert type(checked) is module.admission.VerifiedWindowsPairSetup
    imported = module.admission.import_document(checked, now_ms=state["wall"])
    reviewed = original_review(imported)
    prepared = module.admission.build_preparation(
        "job-aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa", reviewed, imported, issued_at_ms=ISSUED + 2
    )
    state["wall"] = ISSUED + 3
    state["pairs"] = state["channels"] = 0

    def utc():
        return datetime.fromtimestamp(state["wall"] / 1000, timezone.utc)

    original = module.wire.validate_pair_original_reservation(
        prepared["original"], expected_binding=prepared["expected_binding"]
    )
    packet = module.wire.prepare_pair_packet(
        original,
        challenge="f" * 64,
        clock=utc(),
        monotonic_now=state["mono"],
        original_monotonic_deadline=14.0,
    )
    cancellation = threading.Event()
    events, unprotected, factories, wiped = [], [], [], []
    control = SimpleNamespace(allowance=True, after_decrypt=None)
    opaque = backend.files[module.setup._CREDENTIAL_PATH]

    def native_backend(gate, owner, issued):
        assert owner == backend.owner and issued == prepared["issued_at_ms"]
        assert gate.deadline == packet._deadline == 14.0
        gate.check()
        backend.gate = gate
        factories.append((issued, gate.deadline))
        return backend

    class Provider:
        provider_id = "windows-dpapi-current-user.v1"

        def unprotect(self, purpose, ciphertext):
            assert purpose == module.admission._purpose(record)
            assert purpose == backend.purpose and ciphertext == opaque
            unprotected.append((purpose, ciphertext))
            if control.after_decrypt == "expired":
                state["wall"] = prepared["expires_at_ms"]
            elif control.after_decrypt == "cancelled":
                cancellation.set()
            return b"A\0b\0"

    def revalidate():
        events.append("original")
        module.admission.validate_preparation(prepared, reviewed, imported, now_ms=state["wall"])

    def fake_ready_allowance():
        # This callback deliberately makes no claim about SQLite Ready consumption.
        events.append("captured-test-ready-allowance")
        if not control.allowance:
            raise RuntimeError("Synthetic Ready allowance was refused")

    original_wipe = module._wipe

    def capture_wipe(value):
        original_wipe(value)
        if value is not None:
            wiped.append(value)

    monkeypatch.setattr(module, "_utc", utc)
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: state["mono"]))
    monkeypatch.setattr(module.native, "time", SimpleNamespace(monotonic=lambda: state["mono"]))
    monkeypatch.setattr(module.native_setup, "_NativeSetup", native_backend)
    monkeypatch.setattr(module, "WindowsDPAPISecretProvider", Provider)
    monkeypatch.setattr(module, "_wipe", capture_wipe)
    producer = module.PairBeginProducer(
        checked,
        original,
        packet,
        revalidate_original=revalidate,
        require_ready_allowance=fake_ready_allowance,
        cancellation_event=cancellation,
    )
    prefix = module.wire.pair_begin_prefix(packet, clock=utc(), monotonic_now=state["mono"])
    return SimpleNamespace(
        state=state,
        backend=backend,
        record=record,
        checked=checked,
        imported=imported,
        reviewed=reviewed,
        prepared=prepared,
        original=original,
        packet=packet,
        producer=producer,
        prefix=prefix,
        events=events,
        unprotected=unprotected,
        factories=factories,
        wiped=wiped,
        cancellation=cancellation,
        control=control,
    )


def test_real_provenance_through_original_pair_releases_one_private_frame(provenance_begin):
    value = provenance_begin
    assert value.imported["setup_receipt"] == json.loads(value.checked._receipt)
    assert value.imported["enrollment"] == value.record
    assert (
        value.prepared["original"]["profile"] == value.imported["setup_receipt"]["private_profile"]
    )
    assert value.prepared["expected_binding"]["credential_binding_digest"] == content_hash(
        value.record["credential_reference"]
    )
    frame = value.producer(value.prefix)
    try:
        assert type(frame) is bytearray
        assert struct.unpack_from("<I", frame)[0] == len(frame) - 4
        assert frame[4:12] == b"BFWFBEG2" and frame[4:128] == value.prefix
        assert frame[128:] == b"\x02\0A\0b\0"
        assert len(value.unprotected) == 1 and value.state["pairs"] == value.state["channels"] == 2
        assert value.factories == [(ISSUED + 2, 14.0), (ISSUED + 2, 14.0)]
        assert value.producer.credential_cleanup == "verified"
        assert (
            value.events.count("original")
            == value.events.count("captured-test-ready-allowance")
            == 4
        )
        assert value.wiped and all(not any(buffer) for buffer in value.wiped)
        before = (list(value.events), len(value.unprotected), value.backend.closed)
        with pytest.raises(module.WindowsPairCredentialError):
            value.producer(value.prefix)
        assert (value.events, len(value.unprotected), value.backend.closed) == before
    finally:
        frame[:] = b"\0" * len(frame)


@pytest.mark.parametrize(
    "fault", ["record", "receipt", "credential", "source_channel", "source_image", "purpose"]
)
def test_changed_protected_setup_or_live_source_never_decrypts(provenance_begin, fault):
    value = provenance_begin
    if fault == "record":
        value.backend.files[module.admission.common.ANCHOR_PATH] = b"changed protected record"
    elif fault == "receipt":
        value.backend.files[module.setup._RECEIPT_PATH] = b"changed protected receipt"
    elif fault == "credential":
        value.backend.files[module.setup._CREDENTIAL_PATH] = b"changed protected ciphertext"
    elif fault == "source_channel":
        value.state["fault"] = "channel"
    elif fault == "source_image":
        value.state["fault"] = "image"
    else:
        receipt = json.loads(value.backend.files[module.setup._RECEIPT_PATH])
        receipt["credential_reference"]["purpose_digest"] = "sha256:" + "e" * 64
        value.backend.files[module.setup._RECEIPT_PATH] = canonical_json_bytes(receipt)
    with pytest.raises(module.WindowsPairCredentialError):
        value.producer(value.prefix)
    assert value.unprotected == [] and value.producer.credential_cleanup == "unknown"
    before = (list(value.events), value.backend.closed)
    with pytest.raises(module.WindowsPairCredentialError):
        value.producer(value.prefix)
    assert (value.events, value.backend.closed) == before and value.unprotected == []


@pytest.mark.parametrize(
    "fault", ["expired", "rollback", "deadline", "cancelled", "ready", "original_review"]
)
def test_original_admission_and_interval_are_not_renewed(provenance_begin, fault):
    value = provenance_begin
    if fault == "expired":
        value.state["wall"] = value.prepared["expires_at_ms"]
    elif fault == "rollback":
        value.state["wall"] = value.prepared["issued_at_ms"] - 1
    elif fault == "deadline":
        value.state["mono"] = value.packet._deadline
    elif fault == "cancelled":
        value.cancellation.set()
    elif fault == "ready":
        value.control.allowance = False
    else:
        value.reviewed["submitted_request"]["reviewed_by"] = "changed-actor"
    with pytest.raises(module.WindowsPairCredentialError):
        value.producer(value.prefix)
    assert value.unprotected == [] and value.factories == []
    assert value.producer.credential_cleanup == "not_started"
    before = list(value.events)
    with pytest.raises(module.WindowsPairCredentialError):
        value.producer(value.prefix)
    assert value.events == before


@pytest.mark.parametrize("late", ["expired", "cancelled"])
def test_late_provider_result_is_wiped_and_cannot_repeat_unprotect(provenance_begin, late):
    value = provenance_begin
    value.control.after_decrypt = late
    with pytest.raises(module.WindowsPairCredentialError):
        value.producer(value.prefix)
    assert len(value.unprotected) == 1
    assert value.wiped and all(not any(buffer) for buffer in value.wiped)
    assert value.producer.credential_cleanup == "verified"
    before = (list(value.events), value.backend.closed)
    with pytest.raises(module.WindowsPairCredentialError):
        value.producer(value.prefix)
    assert len(value.unprotected) == 1 and (value.events, value.backend.closed) == before
