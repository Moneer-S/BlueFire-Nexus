"""Synthetic Begin boundary only; no OS provider, account or file access."""

from __future__ import annotations

import copy
import hashlib
import struct
import threading
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_pair_credential as module
from bluefire.util import canonical_json_bytes, content_hash
from bluefire.windows_session_facts import WindowsPrincipalFacts
from tests_platform import test_windows_file_access_pair_wire as pair


@pytest.fixture
def boundary(monkeypatch):
    context, expected = pair.fixture()
    opaque = b"opaque synthetic envelope, never passed to an OS provider"
    reference = {"protected_sha256": "sha256:" + hashlib.sha256(opaque).hexdigest()}
    expected.update(control_revision=1, credential_binding_digest=content_hash(reference))
    context["manifest"]["params"]["windows_file_read_request"].update(expected)
    pair.v1.reseal(context)
    original = module.wire.validate_pair_original_reservation(context, expected_binding=expected)
    packet = module.wire.prepare_pair_packet(
        original,
        challenge="f" * 64,
        clock=pair.v1.NOW,
        monotonic_now=100.0,
        original_monotonic_deadline=104.0,
    )
    issued = module._milliseconds(module.wire._time(context["manifest"]["requested_at"]))
    record = {
        "generation": expected["generation"],
        "host": expected["host"],
        "resource": expected["resource"],
        "credential_reference": reference,
        "issued_at_ms": issued - 1000,
        "expires_at_ms": issued + 900000,
    }
    receipt = {"private_profile": context["profile"]}
    checked = object.__new__(module.admission.VerifiedWindowsPairSetup)
    object.__setattr__(checked, "_raw", canonical_json_bytes(record))
    object.__setattr__(checked, "_receipt", canonical_json_bytes(receipt))
    owner = WindowsPrincipalFacts(4001, 555, record["resource"]["owner_sid"], 11, 22, 33, 2, False)
    state = SimpleNamespace(
        now=pair.v1.NOW,
        mono=100.0,
        events=[],
        failure=None,
        checked=checked,
        record=record,
        receipt=receipt,
        original=original,
        packet=packet,
        owner=owner,
        cancellation=threading.Event(),
        plaintext=b"A\0b\0",
        wiped=[],
        issued=issued,
    )

    def event(name):
        state.events.append(name)
        if state.failure == name:
            raise RuntimeError("synthetic private exception must not escape")

    class Backend:
        def read_public(self, path, maximum):
            assert path == module.setup._CREDENTIAL_PATH and maximum == module.native._MAX_BUFFER
            event("ciphertext")
            return b"changed" if state.failure == "ciphertext_digest" else opaque

        def verify_all(self):
            event("verify")

        def close(self):
            event("close")

    class Provider:
        provider_id = "windows-dpapi-current-user.v1"

        def unprotect(self, purpose, value):
            assert purpose == "synthetic-purpose" and value == opaque
            event("unprotect")
            if state.failure == "late_provider":
                state.mono = 104.0
            if state.failure == "cancel_provider":
                state.cancellation.set()
            if state.failure == "owner_provider":
                state.owner = replace(owner, token_id=99)
            return state.plaintext

    def fresh(**kwargs):
        assert kwargs["now_ms"] == issued and kwargs["deadline"] == packet._deadline
        assert kwargs["cancelled"]() is state.cancellation.is_set()
        event("fresh")
        return state.checked

    def backend(gate, observed_owner, original_issued):
        assert (
            gate.deadline == packet._deadline
            and observed_owner == owner
            and original_issued == issued
        )
        gate.check()
        event("backend")
        return Backend()

    def load_receipt(value):
        assert isinstance(value, Backend)
        event("receipt")
        return b"changed" if state.failure == "receipt_changed" else checked._receipt

    def checked_provenance(value):
        assert type(value) is module.admission.VerifiedWindowsPairSetup
        return copy.deepcopy(record), copy.deepcopy(receipt)

    def revalidate():
        event("admission")

    def allowance():
        event("allowance")

    wipe = module._wipe

    def captured_wipe(value):
        wipe(value)
        if value is not None:
            state.wiped.append(value)

    monkeypatch.setattr(module, "_utc", lambda: state.now)
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: state.mono))
    monkeypatch.setattr(module.native, "time", SimpleNamespace(monotonic=lambda: state.mono))
    monkeypatch.setattr(module.admission, "checked_provenance", checked_provenance)
    monkeypatch.setattr(module.admission, "_purpose", lambda row: "synthetic-purpose")
    monkeypatch.setattr(module.enrollment, "read_windows_file_pair_enrollment", fresh)
    monkeypatch.setattr(module.setup, "_load_pair_receipt", load_receipt)
    monkeypatch.setattr(module.native_setup, "_NativeSetup", backend)
    monkeypatch.setattr(module.session, "current_process_principal", lambda: state.owner)
    monkeypatch.setattr(module, "WindowsDPAPISecretProvider", Provider)
    monkeypatch.setattr(module, "_wipe", captured_wipe)
    state.producer = module.PairBeginProducer(
        checked,
        original,
        packet,
        revalidate_original=revalidate,
        require_ready_allowance=allowance,
        cancellation_event=state.cancellation,
    )
    state.prefix = module.wire.pair_begin_prefix(packet, clock=state.now, monotonic_now=state.mono)
    state.revalidate, state.allowance = revalidate, allowance
    return state


def test_private_begin_uses_original_interval_and_committed_allowance(boundary):
    state = boundary
    result = state.producer(state.prefix)
    assert type(result) is bytearray
    assert struct.unpack_from("<I", result)[0] == len(result) - 4
    assert result[4:128] == state.prefix and result[128:] == b"\x02\0A\0b\0"
    assert state.events == [
        "admission",
        "allowance",
        "fresh",
        "backend",
        "receipt",
        "ciphertext",
        "verify",
        "admission",
        "allowance",
        "unprotect",
        "verify",
        "admission",
        "allowance",
        "close",
        "admission",
        "allowance",
    ]
    assert state.producer.credential_cleanup == "verified"
    assert state.wiped and all(not any(value) for value in state.wiped)
    assert "A\0b" not in repr(state.producer) and "S-1-" not in repr(state.producer)
    before = list(state.events)
    with pytest.raises(module.WindowsPairCredentialError):
        state.producer(state.prefix)
    assert state.events == before
    result[:] = b"\0" * len(result)


def test_owned_stop_does_not_mutate_the_external_cancellation_event(boundary):
    state = boundary
    state.producer.request_stop()
    assert not state.cancellation.is_set()
    with pytest.raises(module.WindowsPairCredentialError):
        state.producer(state.prefix)
    assert state.events == [] and state.producer.credential_cleanup == "not_started"


@pytest.mark.parametrize(
    "fault",
    [
        "admission",
        "allowance",
        "fresh",
        "backend",
        "receipt",
        "receipt_changed",
        "ciphertext",
        "ciphertext_digest",
        "verify",
        "unprotect",
        "close",
        "late_provider",
        "cancel_provider",
        "owner_provider",
    ],
)
def test_failures_never_release_a_frame_or_reuse_the_allowance(boundary, fault):
    state = boundary
    state.failure = fault
    with pytest.raises(module.WindowsPairCredentialError) as error:
        state.producer(state.prefix)
    assert error.value.__cause__ is None and error.value.__suppress_context__
    assert "synthetic private" not in str(error.value)
    assert all(not any(value) for value in state.wiped)
    if fault in ("admission", "allowance"):
        assert "fresh" not in state.events and state.producer.credential_cleanup == "not_started"
    elif fault in ("fresh", "backend", "unprotect", "close"):
        assert state.producer.credential_cleanup == "unknown"
    else:
        assert state.producer.credential_cleanup == "verified"
    if fault not in ("admission", "allowance", "fresh", "backend"):
        assert "close" in state.events
    before = list(state.events)
    state.failure = None
    with pytest.raises(module.WindowsPairCredentialError):
        state.producer(state.prefix)
    assert state.events == before


@pytest.mark.parametrize(
    "fault", ["cancelled", "deadline", "expired", "rollback", "prefix", "v1", "bytes"]
)
def test_refuse_before_any_native_boundary(boundary, fault):
    state = boundary
    if fault == "cancelled":
        state.cancellation.set()
    elif fault == "deadline":
        state.mono = 104.0
    elif fault == "expired":
        state.now += timedelta(seconds=5)
    elif fault == "rollback":
        state.now -= timedelta(seconds=5)
    elif fault == "prefix":
        state.prefix[-1] ^= 1
    elif fault == "v1":
        state.prefix[:8] = b"BFWFBEG1"
    else:
        state.prefix = bytes(state.prefix)
    with pytest.raises(module.WindowsPairCredentialError):
        state.producer(state.prefix)
    assert state.events == [] and state.producer.credential_cleanup == "not_started"


@pytest.mark.parametrize(
    "plaintext", [b"", b"a", b"\0\0", b"\0\xd8", b"\0\xdc", b"\0\xd8A\0", b"A\0" * 257]
)
def test_invalid_utf16_is_refused_without_decoding_password_strings(boundary, plaintext):
    state = boundary
    state.plaintext = plaintext
    with pytest.raises(module.WindowsPairCredentialError):
        state.producer(state.prefix)
    assert "close" in state.events and state.producer.credential_cleanup == "verified"
    assert all(not any(value) for value in state.wiped)


@pytest.mark.parametrize("plaintext", [b"A\0", b"A\0" * 256, b"\0\xd8\0\xdc"])
def test_native_utf16_limits_and_surrogate_pairs_are_preserved(boundary, plaintext):
    state = boundary
    state.plaintext = plaintext
    result = state.producer(state.prefix)
    assert struct.unpack_from("<H", result, 128)[0] == len(plaintext) // 2
    assert result[130:] == plaintext
    result[:] = b"\0" * len(result)


@pytest.mark.parametrize(
    "fault", ["generation", "host", "resource", "credential", "profile", "issued", "expiry", "type"]
)
def test_constructor_requires_exact_setup_and_original_binding(boundary, fault):
    state = boundary
    checked = state.checked
    if fault == "generation":
        state.record["generation"] = "f" * 32
    elif fault == "host":
        state.record["host"]["channel_digest"] = pair.v1.digest("1")
    elif fault == "resource":
        state.record["resource"]["size_bytes"] += 1
    elif fault == "credential":
        state.record["credential_reference"]["protected_sha256"] = pair.v1.digest("1")
    elif fault == "profile":
        state.receipt["private_profile"]["profile_id"] = "different"
    elif fault == "issued":
        state.record["issued_at_ms"] = state.issued + 1
    elif fault == "expiry":
        state.record["expires_at_ms"] = state.issued + 1
    else:
        checked = SimpleNamespace(_raw=checked._raw, _receipt=checked._receipt)
    with pytest.raises(module.WindowsPairCredentialError):
        module.PairBeginProducer(
            checked,
            state.original,
            state.packet,
            revalidate_original=state.revalidate,
            require_ready_allowance=state.allowance,
            cancellation_event=state.cancellation,
        )
    assert state.events == []


@pytest.mark.parametrize("field", ["_raw", "_receipt"])
def test_changed_fresh_protected_snapshot_never_decrypts(boundary, field):
    state = boundary
    changed = object.__new__(module.admission.VerifiedWindowsPairSetup)
    for name in ("_raw", "_receipt"):
        object.__setattr__(
            changed, name, b"changed" if name == field else getattr(state.checked, name)
        )
    state.checked = changed
    with pytest.raises(module.WindowsPairCredentialError):
        state.producer(state.prefix)
    assert state.events == ["admission", "allowance", "fresh"]
    assert state.producer.credential_cleanup == "unknown"
