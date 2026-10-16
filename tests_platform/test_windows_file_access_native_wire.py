"""Pure Rust-wire fixtures; no launcher, native reader or credential provider."""

from __future__ import annotations

import copy
import struct
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from bluefire import windows_file_access_native_wire as wire
from bluefire.execution_contracts import execution_task_identity
from bluefire.util import canonical_json_bytes, content_hash

GENERATION = "0123456789abcdef0123456789abcdef"
JOB = "job-abcdef0123456789abcdef0123456789"
REQUEST_ID = "e2f7d90bd8dea87e68adf95b7af07cdb"
PROFILE_HASH = "sha256:40e4c924a48d362a28a53c0d806a3028126d07653c025bfa5e0de971be76248d"
MANIFEST_HASH = "sha256:9953af0ea0f009aa6e4ff36ce320cc4956e59551b77abf9aaa3bcc4b44add22e"
TRANSPORT_HASH = "sha256:a3a22e5e8a62d08477284b88cf4939208fee9c95afba076d66f18f4a56fd678c"
PACKET_HASH = "sha256:80475057ae804011ecd7445eeb6cb03a3def98fea876b16bb06d7465240e7565"
PREFIX_HEX = (
    "4246574642454731ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    "80475057ae804011ecd7445eeb6cb03a3def98fea876b16bb06d7465240e7565"
    "0123456789abcdef0123456789abcdef07000000"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)
READY_BYTES = (
    b'{"challenge":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","control_revision":7,"credential_binding_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    b'"generation":"0123456789abcdef0123456789abcdef","packet_digest":"sha256:80475057ae804011ecd7445eeb6cb03a3def98fea876b16bb06d7465240e7565","readiness_scope":"protocol_only",'
    b'"request_hash":"sha256:a3a22e5e8a62d08477284b88cf4939208fee9c95afba076d66f18f4a56fd678c","schema_version":"bluefire.windows-file-worker-ready.v1",'
    b'"task_id":"execute-a3a22e5e8a62d08477284b88cf4939208fee9c95afba076d66f18f4a56fd678c"}'
)
TERMINAL_BYTES = (
    b'{"challenge":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","control_revision":7,"credential_binding_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
    b'"generation":"0123456789abcdef0123456789abcdef","observed_at":"2026-10-12T12:00:01.000000Z","operation":"read_generated","packet_digest":"sha256:80475057ae804011ecd7445eeb6cb03a3def98fea876b16bb06d7465240e7565",'
    b'"request_hash":"sha256:a3a22e5e8a62d08477284b88cf4939208fee9c95afba076d66f18f4a56fd678c","result":{"bytes_read":13,"cleanup":{"controller_restored":true,"handles_released":true,"impersonation_reverted":true,"owned_process_exit_required":false},'
    b'"data_open_attempted":true,"effective_reader_verified":true,"failed_stage":null,"independent_observation":false,"issue":null,"observed_sha256":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",'
    b'"outcome":"allowed","request_id":"e2f7d90bd8dea87e68adf95b7af07cdb","resource_rechecked":true,"schema_version":"bluefire.windows-fixed-read.v1"},"schema_version":"bluefire.windows-file-worker-result.v1",'
    b'"task_id":"execute-a3a22e5e8a62d08477284b88cf4939208fee9c95afba076d66f18f4a56fd678c"}'
)
NOW = datetime(2026, 10, 12, 12, 0, 1, tzinfo=timezone.utc)


def digest(char):
    return "sha256:" + char * 64


def fixture():
    # This is the exact synthetic Rust worker fixture, with independently
    # derived literal hashes above (Node standard-library derivation by root).
    limits = dict(
        timeout_ms=5000,
        max_stdout_bytes=8192,
        max_stderr_bytes=1024,
        max_artifact_bytes=1,
        max_files=1,
    )
    profile = dict(
        schema_version="bluefire.runner-profile.v1",
        profile_id="synthetic.windows-reader",
        runner_id="bluefire-rust-runner.v1",
        platform="windows",
        sandbox_root=f"C:\\BlueFire\\EndpointAccess\\{GENERATION}",
        allowed_actions=[wire.ACTION],
        control_blocked_actions=[],
        capabilities=[wire.CAPABILITY],
        max_safety_tier="controlled",
        approval_required_at_or_above="safe",
        target_scope=dict(filesystem=[], network=[]),
        limits=limits,
        policy_digest="",
    )
    profile["policy_digest"] = content_hash(profile)
    identities = [dict(volume_serial="fedcba9876543210", file_id=f"{i:032x}") for i in range(1, 6)]
    expected = dict(
        operation_job_id=JOB,
        generation=GENERATION,
        control_revision=7,
        credential_binding_digest=digest("a"),
        host=dict(
            runner_profile_id=profile["profile_id"],
            profile_digest=profile["policy_digest"],
            native_generation=digest("b"),
            host_id=digest("c"),
            channel_digest=digest("d"),
        ),
        resource=dict(
            owner_sid="S-1-5-21-101-202-303-1001",
            reader_sid="S-1-5-21-101-202-303-1002",
            ancestors=identities[:4],
            file_identity=identities[4],
            size_bytes=13,
            sha256=digest("e"),
            state="readable",
        ),
    )
    request = dict(
        schema_version="bluefire.windows-file-worker-operation.v1",
        request_id=REQUEST_ID,
        **expected,
    )
    manifest = dict(
        schema_version="bluefire.runner-manifest.v1",
        request_id=f"win-read-{REQUEST_ID}",
        run_id=JOB,
        step_id="read_generated",
        behavior_id="identity.windows.file_read.v1",
        action_id=wire.ACTION,
        mode="execute",
        runner_id=profile["runner_id"],
        runner_profile_id=profile["profile_id"],
        platform="windows",
        requested_at="2026-10-12T12:00:00Z",
        expires_at="2026-10-12T12:00:05Z",
        params=dict(windows_file_read_request=request),
        target_scope=dict(filesystem=[], network=[]),
        required_capabilities=[wire.CAPABILITY],
        safety_tier="controlled",
        limits=limits,
        cleanup_action_id=None,
        policy_digest=profile["policy_digest"],
        approval=dict(
            approved_by="synthetic-reviewer",
            approved_at="2026-10-12T12:00:00Z",
            expires_at="2026-10-12T12:00:05Z",
            request_hash="",
        ),
        evidence_refs=[],
        request_hash="",
    )
    seal = content_hash(manifest)
    manifest["request_hash"] = manifest["approval"]["request_hash"] = seal
    task, transport = execution_task_identity(manifest, profile)
    return dict(
        manifest=manifest, profile=profile, task_id=task, transport_request_hash=transport
    ), copy.deepcopy(expected)


def reseal(context):
    manifest = context["manifest"]
    manifest["request_hash"] = manifest["approval"]["request_hash"] = ""
    seal = content_hash(manifest)
    manifest["request_hash"] = manifest["approval"]["request_hash"] = seal
    context["task_id"], context["transport_request_hash"] = execution_task_identity(
        manifest, context["profile"]
    )


def prepared():
    context, expected = fixture()
    original = wire.validate_original_reservation(context, expected_binding=expected)
    packet = wire.prepare_packet(
        original,
        challenge="f" * 64,
        clock=NOW,
        monotonic_now=100.0,
        original_monotonic_deadline=104.0,
    )
    return original, packet, wire.validate_retained_packet(original, packet._raw)


def envelopes(retained, outcome="allowed"):
    packet = wire._document(retained._raw)
    request = packet["manifest"]["params"]["windows_file_read_request"]
    binding = dict(
        challenge=packet["challenge"],
        packet_digest=content_hash(packet),
        task_id=packet["task_id"],
        request_hash=packet["request_hash"],
        generation=request["generation"],
        control_revision=request["control_revision"],
        credential_binding_digest=request["credential_binding_digest"],
    )
    ready = dict(binding, schema_version=wire.READY_SCHEMA, readiness_scope="protocol_only")
    proof = dict(
        schema_version=wire.PROOF_SCHEMA,
        request_id=request["request_id"],
        outcome=outcome,
        issue=None,
        failed_stage=None,
        data_open_attempted=True,
        bytes_read=13 if outcome == "allowed" else 0,
        observed_sha256=digest("e") if outcome == "allowed" else None,
        effective_reader_verified=True,
        resource_rechecked=True,
        independent_observation=False,
        cleanup=dict(
            handles_released=True,
            impersonation_reverted=True,
            controller_restored=True,
            owned_process_exit_required=False,
        ),
    )
    if outcome == "unknown":
        proof.update(issue="native_failure", failed_stage="data_open", resource_rechecked=False)
    terminal = dict(
        binding,
        schema_version=wire.RESULT_SCHEMA,
        operation="read_generated",
        observed_at="2026-10-12T12:00:01.000000Z",
        result=proof,
    )
    return ready, terminal


def project(original, retained, ready, terminal, *, clock=NOW, code=0):
    return wire.validate_terminal(
        original,
        retained,
        canonical_json_bytes(ready),
        canonical_json_bytes(terminal),
        clock=clock,
        returncode=code,
    )


def test_literal_rust_fixture_hashes_public_frame_and_begin_prefix():
    context, _ = fixture()
    assert context["profile"]["policy_digest"] == PROFILE_HASH
    assert context["manifest"]["request_hash"] == MANIFEST_HASH
    assert context["transport_request_hash"] == TRANSPORT_HASH
    assert context["task_id"] == "execute-" + TRANSPORT_HASH[7:]
    original, packet, retained = prepared()
    assert content_hash(wire._document(retained._raw)) == PACKET_HASH
    assert len(retained._raw) == 3598
    public = wire.public_frame(packet, clock=NOW, monotonic_now=100.0)
    assert public[:4].hex() == "0e0e0000"
    assert struct.unpack("<I", public[:4])[0] == 3598
    assert public[4:] == retained._raw
    prefix = wire.begin_prefix(packet, clock=NOW, monotonic_now=100.0)
    assert len(prefix) == 124 and prefix.hex() == PREFIX_HEX
    # These same fixed payload bytes are asserted against Rust run_checked's
    # envelope serialization using an actual synthetic production ReadProof.
    wire.validate_ready(retained, READY_BYTES)
    projected = wire.validate_terminal(
        original, retained, READY_BYTES, TERMINAL_BYTES, clock=NOW, returncode=0
    )
    assert projected.outcome == "allowed" and projected.observation_complete
    assert projected.settled is False and projected.owned_job_cleanup == "unverified"
    assert projected.independent_observation is False
    assert projected._terminal == TERMINAL_BYTES


def test_original_saved_identity_is_verified_not_replaced():
    for key in ("task_id", "transport_request_hash"):
        context, expected = fixture()
        context[key] = "execute-" + "0" * 64 if key == "task_id" else digest("0")
        with pytest.raises(wire.NativeWireError):
            wire.validate_original_reservation(context, expected_binding=expected)


@pytest.mark.parametrize("fault", range(8))
def test_altered_seals_scope_and_separately_supplied_binding_refuse(fault):
    context, expected = fixture()
    request = context["manifest"]["params"]["windows_file_read_request"]
    if fault == 0:
        context["manifest"]["request_hash"] = digest("0")
    elif fault == 1:
        context["profile"]["policy_digest"] = digest("0")
    elif fault == 2:
        request["control_revision"] = 8
        reseal(context)
    elif fault == 3:
        request["resource"]["file_identity"]["file_id"] = "80000000000000000000000000000001"
        reseal(context)
    elif fault == 4:
        expected["host"]["host_id"] = digest("0")
    elif fault == 5:
        request["resource"]["path"] = "C:\\other"
        expected["resource"]["path"] = "C:\\other"
        reseal(context)
    elif fault == 6:
        context["manifest"]["limits"] = dict(context["manifest"]["limits"], max_files=True)
        reseal(context)
    else:
        context["manifest"]["run_id"] = "job-" + "0" * 32
        reseal(context)
    with pytest.raises(wire.NativeWireError):
        wire.validate_original_reservation(context, expected_binding=expected)


def test_duplicate_float_int_unknown_fields_and_identity_aliases_refuse():
    context, expected = fixture()
    raw = canonical_json_bytes(context)
    for invalid in (
        raw.replace(b'"control_revision":7', b'"control_revision":7,"control_revision":7'),
        raw.replace(b'"control_revision":7', b'"control_revision":7.0'),
        raw + b" {}",
    ):
        with pytest.raises(wire.NativeWireError):
            wire.validate_original_reservation(invalid, expected_binding=expected)
    for reader in (
        "S-1-5-21-0101-202-303-1002",
        "S-1-5-21-101-202-303-999",
        "S-1-5-21-101-202-303-1001",
    ):
        changed, binding = fixture()
        changed["manifest"]["params"]["windows_file_read_request"]["resource"]["reader_sid"] = (
            binding["resource"]["reader_sid"]
        ) = reader
        reseal(changed)
        with pytest.raises(wire.NativeWireError):
            wire.validate_original_reservation(changed, expected_binding=binding)
    changed, binding = fixture()
    changed["manifest"]["params"]["windows_file_read_request"]["resource"]["file_identity"][
        "volume_serial"
    ] = binding["resource"]["file_identity"]["volume_serial"] = 0xFEDCBA9876543210
    reseal(changed)
    with pytest.raises(wire.NativeWireError):
        wire.validate_original_reservation(changed, expected_binding=binding)


@pytest.mark.parametrize(
    "encoding",
    ["utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be", "utf-8-sig"],
)
def test_non_utf8_or_bom_public_documents_refuse(encoding):
    context, expected = fixture()
    raw = canonical_json_bytes(context).decode("utf-8").encode(encoding)
    with pytest.raises(wire.NativeWireError):
        wire.validate_original_reservation(raw, expected_binding=expected)


def test_invalid_json_timestamp_and_huge_numbers_have_sanitized_errors():
    context, expected = fixture()
    for raw in (
        b'{"private":"untrusted diagnostic"',
        b"\xffprivate",
        b'{"large":' + b"9" * 5000 + b"}",
    ):
        with pytest.raises(wire.NativeWireError) as caught:
            wire.validate_original_reservation(raw, expected_binding=expected)
        assert caught.value.__cause__ is None and caught.value.__suppress_context__
        assert "private" not in str(caught.value) and "untrusted" not in str(caught.value)
    context["manifest"]["requested_at"] = "2026-13-12T12:00:00Z"
    context["manifest"]["approval"]["approved_at"] = context["manifest"]["requested_at"]
    reseal(context)
    with pytest.raises(wire.NativeWireError) as caught:
        wire.validate_original_reservation(context, expected_binding=expected)
    assert caught.value.__cause__ is None and caught.value.__suppress_context__


def test_full_width_identities_remain_distinct_and_raw_types_immutable():
    context, expected = fixture()
    request = context["manifest"]["params"]["windows_file_read_request"]
    request["resource"]["file_identity"]["file_id"] = expected["resource"]["file_identity"][
        "file_id"
    ] = "80000000000000000000000000000001"
    reseal(context)
    original = wire.validate_original_reservation(context, expected_binding=expected)
    assert b'"volume_serial":"fedcba9876543210"' in original._raw
    assert b'"file_id":"80000000000000000000000000000001"' in original._raw
    context["task_id"] = "changed"
    assert b"changed" not in original._raw
    with pytest.raises(FrozenInstanceError):
        original._raw = b"changed"
    with pytest.raises(wire.NativeWireError):
        wire.OriginalReservation({}, canonical_json_bytes(expected))


def test_expired_original_historical_terminal_validates_without_dispatch():
    original, packet, retained = prepared()
    ready, terminal = envelopes(retained)
    later = NOW + timedelta(hours=1)
    assert project(original, retained, ready, terminal, clock=later).observation_complete
    context, expected = fixture()
    restored = wire.validate_original_reservation(context, expected_binding=expected)
    assert wire.validate_retained_packet(restored, retained._raw)._raw == retained._raw
    for operation in (
        lambda: wire.prepare_packet(
            original,
            challenge="f" * 64,
            clock=later,
            monotonic_now=105,
            original_monotonic_deadline=104,
        ),
        lambda: wire.begin_prefix(packet, clock=later, monotonic_now=105),
        lambda: wire.public_frame(packet, clock=later, monotonic_now=105),
    ):
        with pytest.raises(wire.NativeWireError):
            operation()


def test_rollback_and_invalid_monotonic_inputs_never_renew_begin_budget():
    original, packet, _ = prepared()
    for clock, mono in ((NOW - timedelta(seconds=2), 101), (NOW, 104)):
        with pytest.raises(wire.NativeWireError):
            wire.begin_prefix(packet, clock=clock, monotonic_now=mono)
    for value in (True, float("nan"), float("inf"), -1, "100"):
        with pytest.raises(wire.NativeWireError):
            wire.prepare_packet(
                original,
                challenge="f" * 64,
                clock=NOW,
                monotonic_now=value,
                original_monotonic_deadline=104,
            )


def test_exact_ready_protocol_only_binding_and_remaining_limits():
    original, _, retained = prepared()
    ready, _ = envelopes(retained)
    wire.validate_ready(retained, canonical_json_bytes(ready))
    for field, value in (
        ("readiness_scope", "authenticated"),
        ("control_revision", 8),
        ("pid", 1234),
        ("packet_digest", digest("0")),
    ):
        altered = dict(ready, **{field: value})
        with pytest.raises(wire.NativeWireError):
            wire.validate_ready(retained, canonical_json_bytes(altered))
    for remaining in (True, 0, 5001):
        altered = wire._document(retained._raw)
        altered["remaining_ms"] = remaining
        with pytest.raises(wire.NativeWireError):
            wire.validate_retained_packet(original, canonical_json_bytes(altered))


@pytest.mark.parametrize(
    "outcome,code", [("allowed", 0), ("data_access_denied", 0), ("unknown", 4)]
)
def test_native_outcomes_project_without_job_closure_or_causal_success(outcome, code):
    original, _, retained = prepared()
    ready, terminal = envelopes(retained, outcome)
    result = project(original, retained, ready, terminal, code=code)
    assert result.outcome == outcome
    assert result.observation_complete is (outcome != "unknown")
    assert result.settled is False and result.independent_observation is False
    assert result.owned_job_cleanup == "unverified"
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal, code=4 if code == 0 else 0)


@pytest.mark.parametrize("fault", range(12))
def test_malformed_native_proof_never_fabricates_success(fault):
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    proof = terminal["result"]
    field, value = [
        ("bytes_read", True),
        ("bytes_read", 12),
        ("observed_sha256", digest("0")),
        ("issue", "native_failure"),
        ("failed_stage", "read"),
        ("effective_reader_verified", False),
        ("resource_rechecked", False),
        ("data_open_attempted", False),
        ("independent_observation", True),
        ("record_count", 1),
        ("request_id", "0" * 32),
        ("outcome", "success"),
    ][fault]
    proof[field] = value
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal)


def test_cleanup_unknown_error_literals_and_no_arbitrary_diagnostics():
    original, _, retained = prepared()
    ready, terminal = envelopes(retained, "unknown")
    proof = terminal["result"]
    proof.update(issue="cleanup_unknown", failed_stage="cleanup")
    proof["cleanup"].update(handles_released=False, owned_process_exit_required=True)
    assert project(original, retained, ready, terminal, code=4).local_cleanup == "unknown"
    proof["issue"] = "secret path or diagnostic"
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal, code=4)
    terminal.update(
        observed_at=None,
        result=dict(schema_version=wire.ERROR_SCHEMA, code="deadline", possible_effects=True),
    )
    assert (
        project(original, retained, ready, terminal, clock=NOW + timedelta(hours=1), code=4).outcome
        == "unknown"
    )
    terminal["result"]["code"] = "arbitrary"
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal, code=4)


@pytest.mark.parametrize(
    "observed",
    [
        None,
        "2026-10-12T12:00:01Z",
        "2026-10-12T12:00:05.000000Z",
        "2026-10-12T11:59:59.000000Z",
        "2026-10-12T12:00:02.000000Z",
        "2026-10-12T12:00:01.000000+00:00",
    ],
)
def test_native_terminal_timestamp_is_canonical_original_and_not_future(observed):
    original, _, retained = prepared()
    ready, terminal = envelopes(retained)
    terminal["observed_at"] = observed
    with pytest.raises(wire.NativeWireError):
        project(original, retained, ready, terminal)


def test_aggregate_ready_terminal_payloads_and_both_prefixes_are_bounded():
    aggregate_size = len(READY_BYTES) + len(TERMINAL_BYTES) + 2 * 4
    assert len(READY_BYTES) <= wire.READY_MAX
    assert len(TERMINAL_BYTES) <= wire.TERMINAL_MAX
    assert aggregate_size == 1777

    for max_stdout_bytes, accepted in ((aggregate_size - 1, False), (aggregate_size, True)):
        context, expected = fixture()
        context["profile"]["limits"]["max_stdout_bytes"] = context["manifest"]["limits"][
            "max_stdout_bytes"
        ] = max_stdout_bytes
        context["profile"]["policy_digest"] = ""
        seal = content_hash(context["profile"])
        context["profile"]["policy_digest"] = context["manifest"]["policy_digest"] = seal
        context["manifest"]["params"]["windows_file_read_request"]["host"]["profile_digest"] = (
            expected["host"]["profile_digest"]
        ) = seal
        reseal(context)
        original = wire.validate_original_reservation(context, expected_binding=expected)
        packet = wire.prepare_packet(
            original,
            challenge="f" * 64,
            clock=NOW,
            monotonic_now=100,
            original_monotonic_deadline=104,
        )
        retained = wire.validate_retained_packet(original, packet._raw)
        ready, terminal = envelopes(retained)
        ready_bytes, terminal_bytes = canonical_json_bytes(ready), canonical_json_bytes(terminal)
        assert len(ready_bytes) <= max_stdout_bytes and len(terminal_bytes) <= max_stdout_bytes
        assert len(ready_bytes) + len(terminal_bytes) + 8 == aggregate_size

        if not accepted:
            with pytest.raises(wire.NativeWireError):
                wire.validate_terminal(
                    original, retained, ready_bytes, terminal_bytes, clock=NOW, returncode=0
                )
            continue

        projected = wire.validate_terminal(
            original, retained, ready_bytes, terminal_bytes, clock=NOW, returncode=0
        )
        assert projected.outcome == "allowed" and projected.observation_complete
        assert projected.settled is False and projected.owned_job_cleanup == "unverified"
        assert projected.independent_observation is False
