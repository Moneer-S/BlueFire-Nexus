"""Synthetic correction wire proof only; no enrollment or native effects."""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import replace
from datetime import timedelta

import pytest

from bluefire import windows_file_access_native_wire as wire
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_windows_file_access_native_wire as v1
from tests_platform import test_windows_file_access_pair_wire as pair


def fixture():
    context, expected = pair.fixture()
    profile, manifest = context["profile"], context["manifest"]
    profile.update(
        profile_id="synthetic.windows-correction",
        allowed_actions=[wire.CORRECTION_ACTION],
        capabilities=[wire.CORRECTION_CAPABILITY],
        policy_digest="",
    )
    profile["policy_digest"] = content_hash(profile)
    expected["host"].update(
        profile_digest=profile["policy_digest"], runner_profile_id=profile["profile_id"]
    )
    expected.update(control_revision=2, correction_binding_digest=v1.digest("1"))
    expected["resource"]["state"] = "metadata_only"
    operation = "read_generated_pair_correction"
    request_id = hashlib.sha256(f"{v1.JOB}:{operation}".encode("ascii")).hexdigest()[:32]
    manifest.update(
        request_id="win-read-" + request_id,
        step_id=operation,
        behavior_id="identity.windows.file_read_pair_correction.v3",
        action_id=wire.CORRECTION_ACTION,
        required_capabilities=[wire.CORRECTION_CAPABILITY],
        policy_digest=profile["policy_digest"],
        runner_profile_id=profile["profile_id"],
    )
    manifest["params"]["windows_file_read_request"] = dict(
        expected, schema_version="bluefire.windows-file-worker-operation.v3", request_id=request_id
    )
    v1.reseal(context)
    return context, expected


def prepared():
    context, expected = fixture()
    original = wire.validate_correction_original_reservation(context, expected_binding=expected)
    packet = wire.prepare_correction_packet(
        original,
        challenge="f" * 64,
        clock=v1.NOW,
        monotonic_now=100.0,
        original_monotonic_deadline=104.0,
    )
    return original, packet, wire.validate_correction_retained_packet(original, packet._raw)


def envelopes(retained, reader="data_access_denied"):
    ready, terminal = pair.envelopes(retained, reader)
    request = json.loads(retained._raw)["manifest"]["params"]["windows_file_read_request"]
    ready.update(
        schema_version="bluefire.windows-file-worker-ready.v3",
        correction_binding_digest=request["correction_binding_digest"],
    )
    terminal.update(
        schema_version="bluefire.windows-file-worker-result.v3",
        operation="read_generated_pair_correction",
        correction_binding_digest=request["correction_binding_digest"],
    )
    terminal["result"]["schema_version"] = "bluefire.windows-fixed-read-pair-correction.v3"
    return ready, terminal


def project(original, retained, ready, terminal, *, code=0, clock=v1.NOW):
    return wire.validate_correction_terminal(
        original,
        retained,
        canonical_json_bytes(ready),
        canonical_json_bytes(terminal),
        clock=clock,
        returncode=code,
    )


@pytest.mark.parametrize("reader", ["allowed", "data_access_denied"])
def test_correction_retains_fresh_observation_not_correction_causation(reader):
    original, packet, retained = prepared()
    ready, terminal = envelopes(retained, reader)
    wire.validate_correction_ready(retained, canonical_json_bytes(ready))
    result = project(original, retained, ready, terminal)
    assert result.outcome == result.reader_outcome == reader
    assert result.owner_outcome == "allowed" and result.local_cleanup == "verified"
    assert result.observation_complete and not result.settled
    assert not result.independent_observation and result.owned_job_cleanup == "unverified"
    prefix = wire.correction_begin_prefix(packet, clock=v1.NOW, monotonic_now=100.0)
    assert len(prefix) == 156 and prefix[:8] == b"BFWFBEG3"
    assert prefix[124:156] == bytes.fromhex("1" * 64)
    assert struct.unpack("<I", prefix[88:92])[0] == 2
    frame = wire.correction_public_frame(packet, clock=v1.NOW, monotonic_now=100.0)
    assert struct.unpack("<I", frame[:4])[0] == len(packet._raw)


@pytest.mark.parametrize(
    "value", [None, True, "", "1" * 64, "sha256:" + "A" * 64, "sha256:" + "1" * 63]
)
def test_correction_digest_requires_strict_sha256_even_when_resealed(value):
    context, expected = fixture()
    request = context["manifest"]["params"]["windows_file_read_request"]
    expected["correction_binding_digest"] = request["correction_binding_digest"] = value
    v1.reseal(context)
    with pytest.raises(wire.NativeWireError):
        wire.validate_correction_original_reservation(context, expected_binding=expected)


@pytest.mark.parametrize(
    "state,revision", [("readable", 2), ("metadata_only", 1), ("metadata_only", True)]
)
def test_correction_requires_metadata_only_and_new_revision(state, revision):
    context, expected = fixture()
    request = context["manifest"]["params"]["windows_file_read_request"]
    expected["control_revision"] = request["control_revision"] = revision
    expected["resource"]["state"] = request["resource"]["state"] = state
    v1.reseal(context)
    with pytest.raises(wire.NativeWireError):
        wire.validate_correction_original_reservation(context, expected_binding=expected)


@pytest.mark.parametrize("location", ["request", "expected"])
@pytest.mark.parametrize("change", ["missing", "different", "extra"])
def test_correction_expected_digest_is_separate_exact_premise(location, change):
    context, expected = fixture()
    request = context["manifest"]["params"]["windows_file_read_request"]
    selected = request if location == "request" else expected
    if change == "missing":
        del selected["correction_binding_digest"]
    elif change == "different":
        selected["correction_binding_digest"] = v1.digest("2")
    else:
        selected["correction_authorized"] = True
    v1.reseal(context)
    with pytest.raises(wire.NativeWireError):
        wire.validate_correction_original_reservation(context, expected_binding=expected)


@pytest.mark.parametrize("envelope", ["ready", "terminal"])
@pytest.mark.parametrize("change", ["missing", "different", "extra"])
def test_correction_ready_and_terminal_bind_durable_claim_digest(envelope, change):
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    selected = ready if envelope == "ready" else terminal
    if change == "missing":
        del selected["correction_binding_digest"]
    elif change == "different":
        selected["correction_binding_digest"] = v1.digest("2")
    else:
        selected["correction_authorized"] = True
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(schema_version="bluefire.windows-fixed-read-pair.v2"),
        lambda r: r.update(resource_pair_rechecked=False),
        lambda r: r.update(independent_observation=True),
        lambda r: r["owner"].update(outcome="unknown"),
        lambda r: r["owner"].update(original_owner_verified=False),
        lambda r: r["owner"].update(no_thread_token_verified=False),
        lambda r: r["owner"].update(observed_sha256=v1.digest("0")),
        lambda r: r["owner"].update(bytes_read=0),
        lambda r: r["reader"].update(effective_reader_verified=False),
        lambda r: r["reader"].update(bytes_read=1),
        lambda r: r["reader"].update(observed_sha256=v1.digest("e")),
        lambda r: r["reader"]["cleanup"].update(handles_released=False),
        lambda r: r["cleanup"].update(controller_restored=False),
    ],
)
def test_correction_denial_requires_owner_contents_rechecks_and_cleanup(mutate):
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    mutate(terminal["result"])
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal)


def test_correction_late_or_cleanup_unknown_proof_never_completes():
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    terminal["observed_at"] = None
    terminal["result"].update(outcome="unknown", issue="deadline", failed_stage="complete")
    result = project(original, retained, ready, terminal, code=4, clock=v1.NOW + timedelta(days=1))
    assert result.reader_outcome == "data_access_denied" and result.owner_outcome == "allowed"
    assert not result.observation_complete
    terminal["result"].update(issue="cleanup_unknown", failed_stage="cleanup")
    terminal["result"]["cleanup"].update(handles_released=False, owned_process_exit_required=True)
    assert project(original, retained, ready, terminal, code=4).local_cleanup == "unknown"
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal, code=0)


def test_correction_cannot_upgrade_or_downgrade_other_protocol_objects():
    original, packet, retained = prepared()
    for old in (v1, pair):
        context, expected = old.fixture()
        with pytest.raises(wire.NativeWireError):
            wire.validate_correction_original_reservation(context, expected_binding=expected)
        old_original, old_packet, _ = old.prepared()
        with pytest.raises(wire.NativeWireError):
            wire.validate_correction_retained_packet(old_original, old_packet._raw)
        with pytest.raises(wire.NativeWireError):
            wire.correction_begin_prefix(old_packet, clock=v1.NOW, monotonic_now=100.0)
    for validate in (wire.validate_retained_packet, wire.validate_pair_retained_packet):
        with pytest.raises(wire.NativeWireError):
            validate(original, packet._raw)
    for prefix in (wire.begin_prefix, wire.pair_begin_prefix):
        with pytest.raises(wire.NativeWireError):
            prefix(packet, clock=v1.NOW, monotonic_now=100.0)
    with pytest.raises(wire.NativeWireError):
        replace(original, _protocol=replace(original._protocol))
    ready, terminal = envelopes(retained)
    terminal["schema_version"] = "bluefire.windows-file-worker-result.v2"
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal)


def test_correction_original_deadline_not_renewed_and_expired_history_not_replayable():
    original, packet, retained = prepared()
    ready, terminal = envelopes(retained)
    later = v1.NOW + timedelta(days=1)
    assert project(original, retained, ready, terminal, clock=later).observation_complete
    for clock, mono in [(later, 100.0), (v1.NOW, 104.0), (v1.NOW - timedelta(seconds=2), 100.0)]:
        with pytest.raises(wire.NativeWireError):
            wire.correction_begin_prefix(packet, clock=clock, monotonic_now=mono)
    with pytest.raises(wire.NativeWireError):
        wire.prepare_correction_packet(
            original,
            challenge="f" * 64,
            clock=later,
            monotonic_now=100.0,
            original_monotonic_deadline=104.0,
        )


def test_correction_begin_is_independently_derived_and_binds_both_digests():
    _, packet, _ = prepared()
    row = json.loads(packet._raw)
    request = row["manifest"]["params"]["windows_file_read_request"]
    canonical = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    digest = hashlib.sha256(canonical).digest()
    assert request["request_id"] == "4f5df61ef6fafc566b35369cf50ef092"
    assert (
        row["profile"]["policy_digest"]
        == "sha256:72aecfbdf7e8df622b04b07beb601014b3c9da2fec669427ecebd96a6ad40326"
    )
    assert (
        row["manifest"]["request_hash"]
        == "sha256:d8f39eafe5f3d9e176e87b9872a29bfd95cc21b40010776aa9d866db3506d674"
    )
    assert (
        row["request_hash"]
        == "sha256:69fc121218f93b9d8bddb6e72ca69ee6c357bbd1609de8d5a48273b7715972ae"
    )
    assert digest.hex() == "856f3cba47b3b3e4d6d6df62323055b3496ce448dc53469971ff9db92338bfbc"
    assert len(canonical) == 3813
    prefix = (
        b"BFWFBEG3"
        + bytes.fromhex(row["challenge"])
        + digest
        + bytes.fromhex(request["generation"])
        + struct.pack("<I", request["control_revision"])
        + bytes.fromhex(request["credential_binding_digest"][7:])
        + bytes.fromhex(request["correction_binding_digest"][7:])
    )
    assert wire.correction_begin_prefix(packet, clock=v1.NOW, monotonic_now=100.0) == prefix
    assert packet._original._protocol is wire._CORRECTION


def test_correction_errors_remain_bounded_unknown_and_version_specific():
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    terminal["result"] = dict(
        schema_version="bluefire.windows-file-worker-error.v3",
        code="begin_invalid",
        possible_effects=False,
    )
    terminal["observed_at"] = None
    result = project(original, retained, ready, terminal, code=4)
    assert result.outcome == "unknown" and result.reader_outcome is None
    assert result.local_cleanup == "unknown" and not result.settled
    terminal["result"]["schema_version"] = "bluefire.windows-file-worker-error.v2"
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal, code=4)


def test_correction_aggregate_stdout_budget_still_counts_both_prefixes():
    context, expected = fixture()
    context["profile"]["limits"]["max_stdout_bytes"] = 1024
    context["manifest"]["limits"]["max_stdout_bytes"] = 1024
    context["profile"]["policy_digest"] = ""
    context["profile"]["policy_digest"] = content_hash(context["profile"])
    expected["host"]["profile_digest"] = context["profile"]["policy_digest"]
    context["manifest"]["params"]["windows_file_read_request"]["host"] = expected["host"]
    context["manifest"]["policy_digest"] = context["profile"]["policy_digest"]
    v1.reseal(context)
    original = wire.validate_correction_original_reservation(context, expected_binding=expected)
    packet = wire.prepare_correction_packet(
        original,
        challenge="f" * 64,
        clock=v1.NOW,
        monotonic_now=100.0,
        original_monotonic_deadline=104.0,
    )
    retained = wire.validate_correction_retained_packet(original, packet._raw)
    ready, terminal = envelopes(retained)
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal)


@pytest.mark.parametrize(
    "raw",
    [b'{"x":1,"x":2}', b'{"x":1.0}', b"\xef\xbb\xbf{}", b"\xff", b"{}" * 40000],
    ids=["duplicate", "float", "bom", "invalid_utf8", "oversize"],
)
def test_correction_keeps_strict_bounded_public_parser(raw):
    original, _, _ = prepared()
    with pytest.raises(wire.NativeWireError):
        wire.validate_correction_retained_packet(original, raw)
