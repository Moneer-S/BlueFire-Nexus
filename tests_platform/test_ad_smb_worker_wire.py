"""Synthetic saved tasks only; no worker, credential provider or network calls."""

import struct
from copy import deepcopy
from datetime import timedelta
from pathlib import Path

import pytest

from bluefire import ad_smb_results as results
from bluefire import ad_smb_worker_wire as wire
from bluefire.ad_smb_channel import AdSmbHostChannel
from bluefire.ad_smb_contract import AdSmbError, document
from bluefire.execution_contracts import execution_task_identity
from bluefire.runner_contracts import seal_profile
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_ad_smb_channel import channel_row
from tests_platform.test_ad_smb_contract import NOW, pin
from tests_platform.test_ad_smb_jobs import FakeExecutor


def fixture(phase="inspect", index=0, *, limits=None):
    fake = FakeExecutor()
    role = "client" if phase in {"baseline", "retest"} else "member"
    profile = deepcopy(fake.profiles[role])
    profile["limits"] = {
        "timeout_ms": 60000,
        "max_stdout_bytes": wire.TERMINAL_MAX,
        "max_stderr_bytes": 65536,
        "max_artifact_bytes": 1048576,
        "max_files": 2,
    }
    if limits is not None:
        profile["limits"] = limits
    fake.profiles[role] = seal_profile(profile)
    row = channel_row(role)
    row.update(
        scope_digest=fake.scope.digest,
        profile_id=profile["profile_id"],
        profile_digest=fake.profiles[role]["policy_digest"],
    )
    channel = AdSmbHostChannel.from_mapping(fake.scope, row)
    fake.selected[role].update(
        profile_digest=channel.to_dict()["profile_digest"], channel_digest=channel.digest
    )
    request = results.request_for(
        {"job_id": "job-" + "a" * 32, "request": {"environment": fake.selected}},
        phase,
        "job-" + "b" * 32,
        index,
        NOW.isoformat(),
        (NOW + timedelta(seconds=30)).isoformat(),
        {"review_digest": pin("c"), "change": None},
        "reviewer",
    )
    return fake.original(request), channel


def packet(phase="inspect", **changes):
    context, channel = fixture(phase)
    kwargs = dict(
        challenge="f" * 64,
        credential_binding_digest=pin("9") if phase == "baseline" else None,
        expected_upn_sha256=pin("b") if phase == "baseline" else None,
        prior_local_authentication_ids=[],
        clock=NOW + timedelta(seconds=1),
    )
    kwargs.update(changes)
    return wire.prepare_packet(context, channel, **kwargs)


def rebind_context(context, **changes):
    context = deepcopy(context)
    request = context["manifest"]["params"]["ad_smb_request"]
    request.update(changes)
    manifest = results.execution_manifest(request, context["profile"])
    task, request_hash = execution_task_identity(manifest, context["profile"])
    context.update(
        manifest=manifest,
        task_id=task,
        transport_request_hash=request_hash,
        request_digest=content_hash(request),
    )
    return context


def ready_row(value, pid=123):
    public = value.to_dict()
    return {
        "schema_version": "bluefire.ad-smb-worker-ready.v1",
        "challenge": public["challenge"],
        "packet_digest": value.digest,
        "task_id": public["task_id"],
        "request_hash": public["request_hash"],
        "pid": pid,
    }


def terminal_row(value):
    row = ready_row(value)
    del row["pid"]
    row.update(
        schema_version="bluefire.ad-smb-worker-result.v1",
        operation=value.request["step"],
        result={
            "schema_version": "bluefire.ad-smb-worker-error.v1",
            "code": "native_unavailable",
            "possible_effects": False,
        },
    )
    return row


def test_exact_packet_frame_and_original_deadline():
    value = packet()
    framed = value.public_frame()
    assert struct.unpack_from("<I", framed)[0] == len(framed) - 4
    assert value.to_dict()["remaining_ms"] == 29000
    detached = value.to_dict()
    detached["remaining_ms"] = 60000
    assert value.to_dict()["remaining_ms"] == 29000
    wire.ready(value, canonical_json_bytes(ready_row(value)), 123)
    assert (
        wire.terminal(value, canonical_json_bytes(terminal_row(value)))["result"][
            "possible_effects"
        ]
        is False
    )


@pytest.mark.parametrize("field", list(ready_row(packet())))
def test_ready_binds_every_field(field):
    value = packet()
    row = ready_row(value)
    row[field] = None
    with pytest.raises(AdSmbError):
        wire.ready(value, canonical_json_bytes(row), 123)


@pytest.mark.parametrize("field", list(terminal_row(packet())))
def test_terminal_binds_every_field(field):
    value = packet()
    row = terminal_row(value)
    row[field] = None
    with pytest.raises(AdSmbError):
        wire.terminal(value, canonical_json_bytes(row))


@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "1000", 60001])
def test_profile_timeout_strict(value):
    context, channel = fixture()
    context["profile"]["limits"]["timeout_ms"] = value
    with pytest.raises(AdSmbError):
        wire.prepare_packet(
            context,
            channel,
            challenge="a" * 64,
            credential_binding_digest=None,
            expected_upn_sha256=None,
            prior_local_authentication_ids=[],
            clock=NOW,
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"challenge": "A" * 64},
        {"credential_binding_digest": pin("a")},
        {"expected_upn_sha256": pin("b")},
        {"prior_local_authentication_ids": ["0" * 16]},
        {"clock": NOW - timedelta(seconds=1)},
        {"clock": NOW + timedelta(seconds=30)},
    ],
)
def test_member_refuses_changed_binding_or_window(kwargs):
    with pytest.raises(AdSmbError):
        packet(**kwargs)


@pytest.mark.parametrize(
    "ids",
    [["0" * 16], ["0" * 16] * 2, ["A" * 16], ["1" * 15], [f"{i:016x}" for i in range(6)], [True]],
)
def test_reader_contexts_are_closed(ids):
    with pytest.raises(AdSmbError):
        packet("baseline", prior_local_authentication_ids=ids)


def test_duplicate_nonfinite_oversized_and_extra_fields_refused():
    value = packet()
    for raw in [
        b'{"pid":1,"pid":2}',
        b'{"pid":NaN}',
        b" " * (wire.READY_MAX + 1),
        canonical_json_bytes({**ready_row(value), "secret": "not-retained"}),
    ]:
        with pytest.raises(AdSmbError):
            wire.ready(value, raw, 123)
    row = terminal_row(value)
    row["result"]["code"] = "raw error details"
    with pytest.raises(AdSmbError):
        wire.terminal(value, canonical_json_bytes(row))


def test_member_begin_has_no_private_fields_and_wrong_role_refused():
    value = packet()
    private = wire.begin_prefix(value, reader=False)
    assert len(private) == 73 and private[:8] == b"BFADBEG1" and private[-1] == 0
    with pytest.raises(AdSmbError):
        wire.begin_prefix(value, reader=True)
    assert content_hash(value.to_dict()) == value.digest


@pytest.mark.parametrize(
    "key,bad",
    [
        (key, bad)
        for key in sorted(wire.LIMIT_KEYS)
        for bad in (True, 0, -1, "1", 1.5, 2**40)
        if not (key == "timeout_ms" and isinstance(bad, str))
    ],
)
def test_resealed_profiles_still_enforce_five_native_limits(key, bad):
    limits = deepcopy(fixture()[0]["profile"]["limits"])
    limits[key] = bad
    context, channel = fixture(limits=limits)
    with pytest.raises(AdSmbError):
        wire.prepare_packet(
            context,
            channel,
            challenge="f" * 64,
            credential_binding_digest=None,
            expected_upn_sha256=None,
            prior_local_authentication_ids=[],
            clock=NOW,
        )


def test_malformed_timeout_is_sanitized_even_before_original_rederivation():
    context, channel = fixture()
    context["profile"]["limits"]["timeout_ms"] = "synthetic-private-text"
    context["profile"] = seal_profile(context["profile"])
    with pytest.raises(AdSmbError) as error:
        wire.prepare_packet(
            context,
            channel,
            challenge="f" * 64,
            credential_binding_digest=None,
            expected_upn_sha256=None,
            prior_local_authentication_ids=[],
            clock=NOW,
        )
    assert "synthetic-private-text" not in str(error.value)


def test_historical_four_key_fixture_is_not_upgraded_to_native_contract():
    context, channel = fixture(
        limits={"timeout_ms": 60000, "output_bytes": 65536, "files": 2, "bytes": 1024}
    )
    with pytest.raises(AdSmbError):
        wire.prepare_packet(
            context,
            channel,
            challenge="f" * 64,
            credential_binding_digest=None,
            expected_upn_sha256=None,
            prior_local_authentication_ids=[],
            clock=NOW,
        )


def test_terminal_escaped_expansion_respects_actual_serialized_bound():
    value = packet()
    public = value.to_dict()
    public["manifest"]["limits"]["max_stdout_bytes"] = 1024
    value = wire.WorkerPacket(canonical_json_bytes(public))
    row = terminal_row(value)
    row["result"] = {"raw_audit": "\0" * 256}
    assert len(canonical_json_bytes(row)) > 1024
    with pytest.raises(AdSmbError):
        wire.terminal(value, canonical_json_bytes(row))


def test_native_golden_fixture_is_exact_actual_python_sealed_packet():
    raw = (
        Path(__file__).parents[1] / "runner/tests/fixtures/ad_smb_worker_request.json"
    ).read_bytes()
    value = packet("baseline")
    assert document(raw, limit=wire.PUBLIC_MAX) == value.to_dict()
    assert value.digest == "sha256:3395fb37c27839c82d5a02142c1885164c9eb9ef82ea461c45d9d64f905b8631"


def test_reader_bundle_digest_must_match_saved_environment():
    with pytest.raises(AdSmbError):
        packet("baseline", credential_binding_digest=pin("a"))


@pytest.mark.parametrize("elapsed", [0, 1])
def test_audit_requires_nonempty_original_interval(elapsed):
    context, channel = fixture("audit")
    context = rebind_context(context, requested_at=(NOW + timedelta(seconds=elapsed)).isoformat())
    kwargs = dict(
        challenge="f" * 64,
        credential_binding_digest=None,
        expected_upn_sha256=None,
        prior_local_authentication_ids=[],
        clock=NOW + timedelta(seconds=2),
    )
    if elapsed == 0:
        with pytest.raises(AdSmbError):
            wire.prepare_packet(context, channel, **kwargs)
    else:
        assert wire.prepare_packet(context, channel, **kwargs).request["step"] == "collect_audit"


@pytest.mark.parametrize(
    "field,value",
    [("code", []), ("code", "raw failure"), ("possible_effects", 1), ("possible_effects", None)],
)
def test_worker_error_fields_are_closed_and_sanitized(field, value):
    public = packet()
    row = terminal_row(public)
    row["result"][field] = value
    with pytest.raises(AdSmbError):
        wire.terminal(public, canonical_json_bytes(row))
