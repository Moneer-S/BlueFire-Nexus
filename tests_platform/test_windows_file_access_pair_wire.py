"""Pure synthetic paired protocol tests; no enrollment, secrets or native calls."""

from __future__ import annotations

import copy
import hashlib
import json
import struct
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta

import pytest

from bluefire import windows_file_access_native_wire as wire
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform import test_windows_file_access_native_wire as v1


def fixture():
    context, expected = v1.fixture()
    profile, manifest = context["profile"], context["manifest"]
    profile.update(
        profile_id="synthetic.windows-pair",
        allowed_actions=[wire.PAIR_ACTION],
        capabilities=[wire.PAIR_CAPABILITY],
        policy_digest="",
    )
    profile["policy_digest"] = content_hash(profile)
    expected["host"]["profile_digest"] = profile["policy_digest"]
    expected["host"]["runner_profile_id"] = profile["profile_id"]
    request_id = hashlib.sha256(f"{v1.JOB}:read_generated_pair".encode("ascii")).hexdigest()[:32]
    manifest.update(
        request_id="win-read-" + request_id,
        step_id="read_generated_pair",
        behavior_id="identity.windows.file_read_pair.v2",
        action_id=wire.PAIR_ACTION,
        required_capabilities=[wire.PAIR_CAPABILITY],
        policy_digest=profile["policy_digest"],
        runner_profile_id=profile["profile_id"],
    )
    manifest["params"]["windows_file_read_request"] = dict(
        expected, schema_version="bluefire.windows-file-worker-operation.v2", request_id=request_id
    )
    v1.reseal(context)
    return context, expected


def prepared():
    context, expected = fixture()
    original = wire.validate_pair_original_reservation(context, expected_binding=expected)
    packet = wire.prepare_pair_packet(
        original,
        challenge="f" * 64,
        clock=v1.NOW,
        monotonic_now=100.0,
        original_monotonic_deadline=104.0,
    )
    return original, packet, wire.validate_pair_retained_packet(original, packet._raw)


def envelopes(retained, reader="allowed"):
    ready, terminal = v1.envelopes(retained, outcome=reader)
    ready["schema_version"] = "bluefire.windows-file-worker-ready.v2"
    reader_proof = terminal["result"]
    owner = dict(
        schema_version="bluefire.windows-fixed-owner-read.v2",
        outcome="allowed",
        issue=None,
        failed_stage=None,
        data_open_attempted=True,
        bytes_read=13,
        observed_sha256=v1.digest("e"),
        original_owner_verified=True,
        no_thread_token_verified=True,
        resource_rechecked=True,
    )
    terminal.update(
        schema_version="bluefire.windows-file-worker-result.v2",
        operation="read_generated_pair",
        result=dict(
            schema_version="bluefire.windows-fixed-read-pair.v2",
            request_id=reader_proof["request_id"],
            outcome=reader,
            issue=None,
            failed_stage=None,
            reader=reader_proof,
            owner=owner,
            resource_pair_rechecked=True,
            independent_observation=False,
            cleanup=copy.deepcopy(reader_proof["cleanup"]),
        ),
    )
    return ready, terminal


def project(original, retained, ready, terminal, *, code=0, clock=v1.NOW):
    return wire.validate_pair_terminal(
        original,
        retained,
        canonical_json_bytes(ready),
        canonical_json_bytes(terminal),
        clock=clock,
        returncode=code,
    )


@pytest.mark.parametrize("reader", ["allowed", "data_access_denied"])
def test_pair_complete_distinguishes_allowed_and_denied_without_settlement(reader):
    original, packet, retained = prepared()
    ready, terminal = envelopes(retained, reader)
    result = project(original, retained, ready, terminal)
    assert result.outcome == result.reader_outcome == reader
    assert result.owner_outcome == "allowed" and result.observation_complete
    assert not result.settled and not result.independent_observation
    assert result.owned_job_cleanup == "unverified" and result.local_cleanup == "verified"
    prefix = wire.pair_begin_prefix(packet, clock=v1.NOW, monotonic_now=100.0)
    assert len(prefix) == 124 and prefix[:8] == b"BFWFBEG2"
    frame = wire.pair_public_frame(packet, clock=v1.NOW, monotonic_now=100.0)
    assert struct.unpack("<I", frame[:4])[0] == len(frame[4:])
    with pytest.raises(FrozenInstanceError):
        result.settled = True


@pytest.mark.parametrize(
    "issue,stage",
    [
        ("native_failure", "owner_read"),
        ("deadline", "owner_context"),
        ("cancelled", "owner_context"),
    ],
)
def test_pair_reader_allowed_owner_failure_keeps_actual_exit4_partial(issue, stage):
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    result = terminal["result"]
    result.update(outcome="unknown", issue=issue, failed_stage=stage, resource_pair_rechecked=False)
    result["owner"].update(
        outcome="unknown",
        issue=issue,
        failed_stage=stage,
        bytes_read=0,
        observed_sha256=None,
        resource_rechecked=False,
    )
    partial = project(original, retained, ready, terminal, code=4)
    assert partial.reader_outcome == "allowed" and partial.owner_outcome == "unknown"
    assert partial.outcome == "unknown" and not partial.observation_complete and not partial.settled
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal, code=0)


def test_pair_late_null_timestamp_retains_phases_but_never_completes():
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    terminal["result"].update(outcome="unknown", issue="deadline", failed_stage="complete")
    terminal["observed_at"] = None
    result = project(original, retained, ready, terminal, code=4, clock=v1.NOW + timedelta(days=1))
    assert result.reader_outcome == result.owner_outcome == "allowed"
    assert not result.observation_complete
    terminal["result"].update(outcome="allowed", issue=None, failed_stage=None)
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal, clock=v1.NOW + timedelta(days=1))


def test_pair_reader_failure_requires_owner_not_attempted_and_keeps_skipped_shape():
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    result = terminal["result"]
    result.update(
        outcome="unknown",
        issue="native_failure",
        failed_stage="logon",
        resource_pair_rechecked=False,
    )
    result["reader"].update(
        outcome="unknown",
        issue="native_failure",
        failed_stage="logon",
        data_open_attempted=False,
        bytes_read=0,
        observed_sha256=None,
        effective_reader_verified=False,
        resource_rechecked=False,
    )
    result["owner"].update(
        outcome="unknown",
        data_open_attempted=False,
        bytes_read=0,
        observed_sha256=None,
        original_owner_verified=False,
        no_thread_token_verified=False,
        resource_rechecked=False,
    )
    assert project(original, retained, ready, terminal, code=4).owner_outcome == "unknown"
    result["owner"]["data_open_attempted"] = True
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal, code=4)


def test_pair_outer_cleanup_failure_does_not_erase_actual_completed_reads():
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    terminal["result"].update(outcome="unknown", issue="cleanup_unknown", failed_stage="cleanup")
    terminal["result"]["cleanup"].update(handles_released=False, owned_process_exit_required=True)
    result = project(original, retained, ready, terminal, code=4)
    assert result.reader_outcome == result.owner_outcome == "allowed"
    assert result.local_cleanup == "unknown" and not result.settled


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.update(resource_pair_rechecked=False),
        lambda r: r.update(independent_observation=0),
        lambda r: r.update(extra=True),
        lambda r: r["owner"].update(outcome="data_access_denied"),
        lambda r: r["owner"].update(original_owner_verified=False),
        lambda r: r["owner"].update(no_thread_token_verified=False),
        lambda r: r["owner"].update(bytes_read=True),
        lambda r: r["owner"].update(observed_sha256=v1.digest("f")),
        lambda r: r["reader"].update(effective_reader_verified=False),
        lambda r: r["reader"].update(request_id="0" * 32),
        lambda r: r["cleanup"].update(controller_restored=False),
    ],
)
def test_pair_malformed_or_uncorroborated_success_refused(mutate):
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    mutate(terminal["result"])
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal)


def test_pair_expired_history_does_not_allow_new_dispatch_or_begin():
    original, packet, retained = prepared()
    ready, terminal = envelopes(retained)
    later = v1.NOW + timedelta(days=1)
    assert project(original, retained, ready, terminal, clock=later).observation_complete
    for clock, mono in [(later, 100.0), (v1.NOW - timedelta(seconds=2), 100.0), (v1.NOW, 104.0)]:
        with pytest.raises(wire.NativeWireError):
            wire.pair_begin_prefix(packet, clock=clock, monotonic_now=mono)
    with pytest.raises(wire.NativeWireError):
        wire.prepare_pair_packet(
            original,
            challenge="f" * 64,
            clock=later,
            monotonic_now=100.0,
            original_monotonic_deadline=104.0,
        )


def test_pair_does_not_accept_or_upgrade_v1_original_expected_or_objects():
    old_context, old_expected = v1.fixture()
    context, expected = fixture()
    with pytest.raises(wire.NativeWireError):
        wire.validate_pair_original_reservation(old_context, expected_binding=old_expected)
    with pytest.raises(wire.NativeWireError):
        wire.validate_pair_original_reservation(context, expected_binding=old_expected)
    with pytest.raises(wire.NativeWireError):
        wire.validate_original_reservation(context, expected_binding=expected)
    old, old_packet, old_retained = v1.prepared()
    original, packet, retained = prepared()
    for validate, claim, raw in [
        (wire.validate_retained_packet, original, packet._raw),
        (wire.validate_pair_retained_packet, old, old_packet._raw),
        (wire.validate_pair_retained_packet, original, old_packet._raw),
    ]:
        with pytest.raises(wire.NativeWireError):
            validate(claim, raw)
    for prefix, selected in [(wire.begin_prefix, packet), (wire.pair_begin_prefix, old_packet)]:
        with pytest.raises(wire.NativeWireError):
            prefix(selected, clock=v1.NOW, monotonic_now=100.0)
    old_ready, _ = v1.envelopes(old_retained)
    with pytest.raises(wire.NativeWireError):
        wire.validate_pair_ready(retained, canonical_json_bytes(old_ready))


@pytest.mark.parametrize(
    "field,value",
    [
        ("action_id", wire.ACTION),
        ("step_id", "read_generated"),
        ("behavior_id", "identity.windows.file_read.v1"),
        ("required_capabilities", [wire.CAPABILITY]),
        ("expires_at", "2026-10-12T12:00:06Z"),
    ],
)
def test_pair_even_resealed_wrong_original_scope_refuses(field, value):
    context, expected = fixture()
    context["manifest"][field] = value
    v1.reseal(context)
    with pytest.raises(wire.NativeWireError):
        wire.validate_pair_original_reservation(context, expected_binding=expected)


@pytest.mark.parametrize(
    "raw",
    [b'{"x":1,"x":2}', b'{"x":1.0}', b"\xef\xbb\xbf{}", b"\xff", b"{}" * 40000],
    ids=["duplicate", "float", "bom", "invalid_utf8", "oversize"],
)
def test_pair_bounded_strict_public_decoding(raw):
    original, _, _ = prepared()
    with pytest.raises(wire.NativeWireError):
        wire.validate_pair_retained_packet(original, raw)


def test_pair_ready_and_terminal_bindings_and_prefix_inclusive_budget():
    context, expected = fixture()
    context["profile"]["limits"]["max_stdout_bytes"] = 1024
    context["manifest"]["limits"]["max_stdout_bytes"] = 1024
    context["profile"]["policy_digest"] = ""
    context["profile"]["policy_digest"] = content_hash(context["profile"])
    expected["host"]["profile_digest"] = context["profile"]["policy_digest"]
    context["manifest"]["params"]["windows_file_read_request"]["host"] = expected["host"]
    context["manifest"]["policy_digest"] = context["profile"]["policy_digest"]
    v1.reseal(context)
    original = wire.validate_pair_original_reservation(context, expected_binding=expected)
    packet = wire.prepare_pair_packet(
        original,
        challenge="f" * 64,
        clock=v1.NOW,
        monotonic_now=100.0,
        original_monotonic_deadline=104.0,
    )
    retained = wire.validate_pair_retained_packet(original, packet._raw)
    ready, terminal = envelopes(retained)
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal)
    ready["readiness_scope"] = "authenticated"
    with pytest.raises(wire.NativeWireError):
        wire.validate_pair_ready(retained, canonical_json_bytes(ready))


@pytest.mark.parametrize("mono", [float("inf"), float("nan"), -1, True])
def test_pair_monotonic_values_are_finite_original_premises(mono):
    original, _, _ = prepared()
    with pytest.raises(wire.NativeWireError):
        wire.prepare_pair_packet(
            original,
            challenge="f" * 64,
            clock=v1.NOW,
            monotonic_now=mono,
            original_monotonic_deadline=104.0,
        )


def test_pair_resource_full_width_and_readable_only():
    context, expected = fixture()
    assert expected["resource"]["ancestors"][0]["volume_serial"] == "fedcba9876543210"
    original = wire.validate_pair_original_reservation(context, expected_binding=expected)
    assert (
        json.loads(original._raw)["manifest"]["params"]["windows_file_read_request"]["resource"]
        == expected["resource"]
    )
    context["manifest"]["params"]["windows_file_read_request"]["resource"][
        "state"
    ] = "metadata_only"
    expected["resource"]["state"] = "metadata_only"
    v1.reseal(context)
    with pytest.raises(wire.NativeWireError):
        wire.validate_pair_original_reservation(context, expected_binding=expected)


def test_pair_literal_independent_stdlib_hashes_and_begin_golden():
    # Independent stdlib derivation of the exact Rust pair fixture, no wire imports.
    context, _ = fixture()
    original, packet, _ = prepared()
    request = context["manifest"]["params"]["windows_file_read_request"]
    assert request["request_id"] == "e11879634b2ce0543febffcd6aff102e"
    assert (
        context["profile"]["policy_digest"]
        == "sha256:ade6357ac6f629cef9adee176e85655ce43d12787606e6ac4295c35b2dd66b48"
    )
    assert (
        context["manifest"]["request_hash"]
        == "sha256:b175fa5328f1dd3db384e91120bc3c12a08aac277aabe523a358c3cc9ff13185"
    )
    assert (
        context["transport_request_hash"]
        == "sha256:d127eb80abfc673b4d236b33d439f06782c6f33cd9625fa5cffbb18a677eee14"
    )
    assert (
        content_hash(json.loads(packet._raw))
        == "sha256:a46b6399401f059407cc138c1281626acbb15f1f451731575a58fc70101f9db1"
    )
    assert wire.pair_begin_prefix(packet, clock=v1.NOW, monotonic_now=100.0).hex() == (
        "4246574642454732ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "a46b6399401f059407cc138c1281626acbb15f1f451731575a58fc70101f9db1"
        "0123456789abcdef0123456789abcdef07000000"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    assert original._protocol.version == 2
    assert len(packet._raw) == 3622
    assert wire.pair_public_frame(packet, clock=v1.NOW, monotonic_now=100.0)[:4].hex() == "260e0000"


def test_pair_reader_cleanup_unknown_cannot_be_upgraded_by_outer_clean():
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    result = terminal["result"]
    result.update(
        outcome="unknown",
        issue="native_failure",
        failed_stage="owner_context",
        resource_pair_rechecked=False,
    )
    result["reader"].update(outcome="unknown", issue="cleanup_unknown", failed_stage="cleanup")
    result["reader"]["cleanup"].update(handles_released=False, owned_process_exit_required=True)
    result["owner"].update(
        outcome="unknown",
        issue=None,
        failed_stage=None,
        data_open_attempted=False,
        bytes_read=0,
        observed_sha256=None,
        original_owner_verified=False,
        no_thread_token_verified=False,
        resource_rechecked=False,
    )
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal, code=4)


def test_pair_protocol_selection_is_closed_and_not_inferred_from_public_input():
    original, packet, _ = prepared()
    with pytest.raises(wire.NativeWireError):
        replace(original, _protocol=replace(original._protocol))
    with pytest.raises(wire.NativeWireError):
        replace(original, _protocol=2)
    changed = json.loads(packet._raw)
    changed["schema_version"] = wire.REQUEST_SCHEMA
    with pytest.raises(wire.NativeWireError):
        wire.validate_pair_retained_packet(original, canonical_json_bytes(changed))


@pytest.mark.parametrize(
    "part", ["ready_schema", "terminal_schema", "operation", "binding", "timestamp", "error_code"]
)
def test_pair_envelope_drift_and_unbounded_diagnostics_refused(part):
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    if part == "ready_schema":
        ready["schema_version"] = wire.READY_SCHEMA
    elif part == "terminal_schema":
        terminal["schema_version"] = wire.RESULT_SCHEMA
    elif part == "operation":
        terminal["operation"] = "read_generated"
    elif part == "binding":
        terminal["packet_digest"] = v1.digest("0")
    elif part == "timestamp":
        terminal["observed_at"] = "2026-10-12T12:00:05.000000Z"
    else:
        terminal["result"] = dict(
            schema_version="bluefire.windows-file-worker-error.v2",
            code="arbitrary secret-bearing message",
            possible_effects=True,
        )
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal, code=4 if part == "error_code" else 0)


def test_pair_protocol_error_has_no_fabricated_phase_observations():
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    terminal.update(
        observed_at=None,
        result=dict(
            schema_version="bluefire.windows-file-worker-error.v2",
            code="deadline",
            possible_effects=False,
        ),
    )
    result = project(original, retained, ready, terminal, code=4)
    assert result.reader_outcome is result.owner_outcome is None
    assert not result.observation_complete and not result.settled
