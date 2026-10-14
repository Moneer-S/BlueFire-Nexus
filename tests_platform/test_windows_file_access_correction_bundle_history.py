"""Synthetic archive history, not automatic correction-bundle production.

Actual SQLite correction projections supply the public snapshots. RunStore
archives retain them as history only; importing that archive cannot reconstruct
the protected observer, durable admission, or one-use credential producer.
"""

from __future__ import annotations

import io
import json
import threading
import zipfile
from copy import deepcopy
from types import SimpleNamespace

import pytest

from bluefire import product_store_windows_correction as journal
from bluefire import run_bundle_export as exporter
from bluefire import windows_file_access_correction_contract as domain
from bluefire import windows_file_access_correction_credential as credential
from bluefire import windows_file_access_correction_projection as projection
from bluefire import windows_file_access_native_wire as wire
from bluefire.file_access_control import FileAccessControl
from bluefire.product_store import ProductStore
from bluefire.product_store_errors import ProductStoreError
from bluefire.run_store import RunStore, RunStoreError
from bluefire.util import canonical_json_bytes, content_hash
from tests_platform.test_windows_file_access_baseline_publication import at_ms
from tests_platform.test_windows_file_access_correction_connected import (
    connected as connected,
)
from tests_platform.test_windows_file_access_correction_connected import (
    forbidden,
    no_new_work,
    submit,
)
from tests_platform.test_windows_file_access_correction_connected import (
    lifecycle as lifecycle,
)
from tests_platform.test_windows_file_access_correction_connected import (
    paired as paired,
)
from tests_platform.test_windows_file_access_correction_connected import (
    reviewed as reviewed,
)
from tests_platform.test_windows_file_access_correction_connected import (
    saved as saved,
)


def _archive_history(tmp_path, history, *, name="history"):
    store = RunStore(tmp_path / name)
    handle = store.create_run(
        scenario={"synthetic_fixture": "public-correction-history-only"},
        plan={},
        policy={},
        profile={},
    )
    store.finalize(
        handle.run_id,
        result={
            "mode": "simulate",
            "status": "completed",
            "synthetic_history_only": True,
            "automatic_correction_bundle": False,
            "correction_history": history,
        },
        evidence=[],
        detections=[],
    )
    return store, handle.run_id, exporter.export_run_bundle(store, handle.run_id)


def _import_archive(tmp_path, source, run_id, blob, *, name="imported"):
    destination = tmp_path / name
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        expected = {
            f"{run_id}/{path.name}": path.read_bytes()
            for path in (source.root / run_id).iterdir()
            if path.is_file()
        }
        assert set(archive.namelist()) == set(expected)
        for member, original in expected.items():
            assert archive.read(member) == original
            path = destination / run_id / member.split("/")[1]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.read(member))
    imported = RunStore(destination)
    assert imported.validate_bundle(run_id)["valid"]
    return imported


def _completed_history(value, fault):
    initial = value.service.file_access_control(value.owner)
    baseline_job = value.value.saved["job"]
    baseline_records = value.store.file_access_operation_records(baseline_job)
    assert baseline_records["outcome"]["state"] == "complete"
    value.state.fault = fault
    _, job_id, terminal = submit(value)
    public = value.service.file_access_operation(job_id)
    records = value.store.file_access_operation_records(job_id)
    task = records["tasks"][0]["task"]
    assert task["manifest"]["action_id"] == wire.CORRECTION_ACTION
    assert task["step_id"] == "read_generated_pair_correction"
    expected_state = "complete" if fault is None else "unknown"
    assert records["outcome"]["state"] == expected_state
    assert terminal["state"] == ("completed" if fault is None else "failed")
    history = {
        "baseline_job_id": baseline_job,
        "baseline_outcome_digest": baseline_records["outcome_digest"],
        "baseline_control": initial,
        "correction_job_id": job_id,
        "correction_outcome_digest": records["outcome_digest"],
        "correction_binding_digest": records["preparation"]["binding_digest"],
        "correction_task_id": task["task_id"],
        "correction_transport_request_hash": task["transport_request_hash"],
        "operation": public,
    }
    assert public["reconciliation"]["outcome_digest"] == history["correction_outcome_digest"]
    no_new_work(value)
    return history, records


@pytest.mark.parametrize("fault", [None, "allowed_reader"], ids=["hardened", "unknown"])
def test_v3_public_history_roundtrip_preserves_references_without_fresh_authority(
    connected, tmp_path, fault
):
    value = connected
    history, original_records = _completed_history(value, fault)
    source, run_id, blob = _archive_history(tmp_path, history)
    imported = _import_archive(tmp_path, source, run_id, blob)
    restored = imported.get_run(run_id)["correction_history"]
    assert restored == history
    assert restored["baseline_control"]["revision"] == 2
    assert restored["baseline_control"]["baseline"]["independent_observation"] is False
    current = restored["operation"]["control"]
    assert current["schema_version"] == "bluefire.windows-file-access-control.v3"
    assert current["allowed_operations"] == []
    assert current["account_object_cleanup"] == "required"
    if fault is None:
        assert current["status"] == "hardened" and current["revision"] == 3
        assert current["retest"]["non_owner"] == "data_access_denied"
        assert current["retest"]["owner"] == "allowed"
        assert current["retest"]["independent_observation"] is False
    else:
        assert current["status"] == "uncertain" and current["revision"] == 2
        assert current["resource"]["protection"] == "unknown"
        assert current["retest"] is None and current["correction"] is None
    raw = canonical_json_bytes(restored)
    for private_field in (
        b"reader_sid",
        b"owner_sid",
        b"credential_reference",
        b"packet_bytes",
        b"private_profile",
    ):
        assert private_field not in raw

    expires = current["expires_at_ms"]
    historical = projection.projection(value.store, value.owner, clock=at_ms(expires))
    assert historical["status"] == current["status"]
    assert historical["allowed_operations"] == []
    assert (
        value.store.file_access_operation_records(history["correction_job_id"]) == original_records
    )
    assert len(value.state.controls) == len(value.state.launches) == 1
    assert all(not any(buffer) for buffer in value.state.buffers)

    fresh = ProductStore(tmp_path / "fresh-authority.db")
    control = FileAccessControl(SimpleNamespace(product_store=fresh), clock=lambda: expires)
    with pytest.raises(ProductStoreError):
        control.control(value.owner)
    with fresh._connection() as connection, pytest.raises(ProductStoreError):
        journal.validate_review(
            fresh,
            connection,
            restored["baseline_control"],
            {"previous_descriptor_sha256": "sha256:" + "7" * 64},
            now_ms=expires,
        )
    with pytest.raises(credential.WindowsCorrectionCredentialError):
        credential.CorrectionBeginProducer(
            restored["operation"]["control"],
            None,
            None,
            revalidate_original=forbidden,
            require_ready_allowance=forbidden,
            cancellation_event=threading.Event(),
        )
    with pytest.raises(wire.NativeWireError):
        domain.observation_input(restored["operation"]["control"])
    assert fresh.list_file_access_controls() == []


def test_resealed_unknown_archive_label_cannot_mint_hardened_authority(connected, tmp_path):
    value = connected
    history, original_records = _completed_history(value, "allowed_reader")
    forged = deepcopy(history)
    forged["operation"]["control"]["status"] = "hardened"
    forged["operation"]["control"]["revision"] = 3
    forged["operation"]["control"]["resource"]["protection"] = "metadata_only"
    forged["operation"]["reconciliation"]["state"] = "complete"
    source, run_id, blob = _archive_history(tmp_path, forged, name="self-hashed-labels")
    imported = _import_archive(tmp_path, source, run_id, blob)
    restored = imported.get_run(run_id)["correction_history"]
    assert restored == forged and content_hash(restored) != content_hash(history)
    # A valid generic archive hash is not a correction proof or an import grant.
    with pytest.raises(wire.NativeWireError):
        domain.observation_input(restored["operation"]["control"])
    actual = projection.projection(value.store, value.owner, clock=at_ms(value.state.wall))
    assert actual["status"] == "uncertain" and actual["revision"] == 2
    assert actual["resource"]["protection"] == "unknown"
    assert actual["allowed_operations"] == []
    assert (
        value.store.file_access_operation_records(history["correction_job_id"]) == original_records
    )

    result_path = imported.root / run_id / "result.json"
    tampered = json.loads(result_path.read_bytes())
    tampered["correction_history"]["correction_outcome_digest"] = "sha256:" + "9" * 64
    result_path.write_bytes(canonical_json_bytes(tampered))
    assert not imported.validate_bundle(run_id)["valid"]
    with pytest.raises(RunStoreError, match="integrity"):
        imported.get_run(run_id)
