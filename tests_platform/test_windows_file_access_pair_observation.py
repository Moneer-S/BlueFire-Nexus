"""Paired protected observation against fake files/accounts/channel APIs only."""

from types import SimpleNamespace

import pytest

from bluefire import windows_file_access_admission as v1
from bluefire import windows_file_access_context as context
from bluefire import windows_file_access_enrollment as enrollment
from bluefire import windows_file_access_enrollment_reader as reader
from bluefire import windows_file_access_enrollment_setup as setup
from bluefire import windows_file_access_pair_admission as pair
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_windows_file_access_enrollment import observed_setup as observed_setup
from tests_platform.test_windows_file_access_enrollment_reader import install_pair
from tests_platform.test_windows_file_access_pair_provenance import (
    lifecycle as lifecycle,
)
from tests_platform.test_windows_file_access_pair_provenance import (
    pair_source,
)
from tests_platform.test_windows_file_access_pair_provenance import (
    paired as paired,
)
from tests_platform.test_windows_file_access_setup_lifecycle import GENERATION, ISSUED


def anchor(row):
    return {
        "schema_version": "bluefire.windows-file-setup-anchor.v1",
        "enrollment_id": row["enrollment_id"],
        "generation": row["generation"],
        "host_id": row["host"]["host_id"],
        "record_identity": {
            "volume_serial": "fedcba9876543210",
            "file_id": "05000000000000000000000000000080",
        },
        "enrollment_digest": content_hash(row),
        "setup_receipt_digest": row["setup_receipt_digest"],
        "image_sha256": row["native_image"]["sha256"],
        "credential_binding_digest": content_hash(row["credential_reference"]),
    }


@pytest.mark.parametrize("selected", [False, True])
def test_pair_record_uses_same_held_ancestry_and_complete_cleanup(paired, monkeypatch, selected):
    _, checked, _ = paired
    fake = install_pair(monkeypatch)
    fake.raw = checked._raw
    fake.anchor_raw = canonical_json_bytes(anchor(pair._document(checked._raw)))
    fake.wall[0] = ISSUED + 1
    call = (
        reader._observe_selected_enrollment
        if selected
        else reader.observe_protected_pair_enrollment
    )
    result = call(deadline=104.0, cancelled=lambda: False)
    assert result.record.raw_bytes == checked._raw and result.anchor_bytes == fake.anchor_raw
    assert set(fake.closed) == set(fake.objects)
    assert not hasattr(result, "verified")


@pytest.mark.parametrize(
    "fault",
    [
        "anchor_missing",
        "anchor_fresh_identity",
        "anchor_fresh_descriptor",
        "late_record_drift",
        "anchor_read_deadline",
        "cleanup",
    ],
)
def test_selected_pair_keeps_existing_race_deadline_and_cleanup_refusals(
    paired, monkeypatch, fault
):
    _, checked, _ = paired
    fake = install_pair(monkeypatch, fault=fault)
    fake.raw = checked._raw
    fake.anchor_raw = canonical_json_bytes(anchor(pair._document(checked._raw)))
    fake.wall[0] = ISSUED + 1
    with pytest.raises(reader.WindowsEnrollmentRecordError):
        reader._observe_selected_enrollment(deadline=104.0, cancelled=lambda: False)
    assert fake.closed


@pytest.mark.parametrize("version", [1, 3])
def test_explicit_pair_reader_never_falls_back(paired, monkeypatch, version):
    _, checked, _ = paired
    fake = install_pair(monkeypatch)
    if version == 3:
        row = pair._document(checked._raw)
        row["schema_version"] = "bluefire.windows-file-access-enrollment.v3"
        fake.raw = canonical_json_bytes(row)
    fake.wall[0] = ISSUED + 1 if version == 3 else fake.wall[0]
    with pytest.raises(reader.WindowsEnrollmentRecordError):
        reader.observe_protected_pair_enrollment(deadline=104.0, cancelled=lambda: False)
    assert set(fake.closed) == set(fake.objects)


@pytest.fixture
def pair_observed(observed_setup, monkeypatch):
    observe, state, backend, old, bootstrap = observed_setup
    source = pair_source()
    source["native_image"] = {
        **old["native_image"],
        "worker_schema": "bluefire.windows-file-worker-request.v2",
        "read_schema": "bluefire.windows-fixed-read-pair.v2",
    }
    source["transport"]["runner_binary_digest"] = source["native_image"]["sha256"]
    image_path = str(bootstrap.binary_path)
    image = backend.files[image_path]
    backend.files = {image_path: image}
    backend.directories.clear()
    setup._run_setup_for(
        backend,
        source,
        backend.owner,
        backend.gate,
        generation=GENERATION,
        issued=ISSUED,
        protocol=v1._PAIR_SETUP,
    )
    backend.closed = 0
    raw = backend.files[v1.ANCHOR_PATH]
    record = pair._document(raw)
    observed = SimpleNamespace(
        record=SimpleNamespace(raw_bytes=raw, principal=backend.owner),
        anchor_bytes=backend.files[setup._anchor_paths(GENERATION)[-1]],
    )
    state["deadlines"] = []

    def read_pair(**kwargs):
        state["deadlines"].append(kwargs["deadline"])
        assert kwargs["cancelled"]() is False
        state["pairs"] += 1
        if state["fault"] == "pair" and state["pairs"] == 2:
            return SimpleNamespace(record=observed.record, anchor_bytes=b"changed")
        return observed

    monkeypatch.setattr(observe.reader, "observe_protected_pair_enrollment", read_pair)
    monkeypatch.setattr(observe.reader, "_observe_selected_enrollment", read_pair)
    return observe, state, backend, record


def test_pair_fresh_join_keeps_original_deadline_and_setup_only_type(pair_observed):
    _, state, backend, row = pair_observed
    checked = enrollment.read_windows_file_pair_enrollment(
        now_ms=ISSUED, deadline=12.0, cancelled=lambda: False
    )
    assert type(checked) is pair.VerifiedWindowsPairSetup
    assert checked.summary()["expires_at_ms"] == row["expires_at_ms"]
    assert state["deadlines"] == [12.0, 12.0]
    assert backend.closed == 1 and state["channels"] == 2
    assert pair.checked_provenance(checked)[0] == row
    with pytest.raises(v1.wire.NativeWireError):
        v1.checked_provenance(checked)


@pytest.mark.parametrize(
    "fault", ["pair", "channel", "image", "late", "expiry", "rollback", "owner"]
)
def test_pair_fresh_join_never_promotes_changed_facts(pair_observed, fault):
    _, state, _, _ = pair_observed
    state["fault"] = fault
    with pytest.raises(v1.WindowsEnrollmentUnavailable):
        enrollment.read_windows_file_pair_enrollment(now_ms=ISSUED, deadline=12.0)


@pytest.mark.parametrize(
    "deadline,cancelled",
    [(10.0, False), (9.0, False), (12.0, True), (True, False), (float("nan"), False)],
)
def test_pair_original_deadline_or_cancellation_refuses_before_observation(
    pair_observed, deadline, cancelled
):
    _, state, backend, _ = pair_observed
    with pytest.raises(v1.WindowsEnrollmentUnavailable):
        enrollment.read_windows_file_pair_enrollment(
            now_ms=ISSUED, deadline=deadline, cancelled=lambda: cancelled
        )
    assert state["pairs"] == 0 and state["channels"] == 0 and backend.closed == 0


def test_pair_original_wall_interval_is_not_renewed(pair_observed):
    _, state, _, _ = pair_observed
    state["wall"] = ISSUED + 5000
    with pytest.raises(v1.WindowsEnrollmentUnavailable):
        enrollment.read_windows_file_pair_enrollment(now_ms=ISSUED, deadline=12.0)
    assert state["pairs"] == 0


def test_pair_selected_status_is_reviewable_without_immediate_operation(pair_observed):
    _, state, _, row = pair_observed
    status = context.status(SimpleNamespace(), state["wall"])
    assert status["available"] is True and status["allowed_operations"] == []
    assert status["problem"] is None
    assert status["setup"]["enrollment_digest"] == content_hash(row)
    assert "S-1-" not in str(status) and "secret-ref" not in str(status)
    with pytest.raises(v1.WindowsEnrollmentUnavailable):
        context.execution(None, object())


def test_v1_selected_status_keeps_v1_type_and_original_summary(observed_setup, monkeypatch):
    observe, state, _, row, _ = observed_setup
    monkeypatch.setattr(
        observe.reader,
        "_observe_selected_enrollment",
        observe.reader.observe_protected_enrollment_pair,
    )
    checked = enrollment.read_windows_file_setup_status(now_ms=state["wall"])
    assert type(checked) is v1.VerifiedWindowsSetup
    assert checked.summary()["enrollment_digest"] == content_hash(row)


def test_pair_selected_status_refuses_expired_or_changed_setup(pair_observed):
    _, state, _, _ = pair_observed
    state["fault"] = "pair"
    status = context.status(SimpleNamespace(), state["wall"])
    assert "setup" not in status and status["available"] is False
    assert status["allowed_operations"] == []
