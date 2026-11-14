from __future__ import annotations

import base64
import os
from datetime import datetime, timezone

import pytest

from bluefire.tenant_record_controller_contract import tenant_target_snapshot_ref
from bluefire.tenant_record_lab import baseline_defense_config, generate_tenant_record_fixture
from bluefire.tenant_record_observer import BoundedTenantAuditLog
from bluefire.tenant_record_service import TenantRecordApplication
from bluefire.tenant_record_sidecar_observer import (
    OBSERVATION_SCHEMA,
    READY_SCHEMA,
    OwnedTenantSidecarObservationReader,
    TenantSidecarObservationError,
    _binding,
    _checked_record,
)
from bluefire.util import canonical_json_bytes, content_hash

ATTEMPT = "engine-attempt-" + "a" * 32
REQUEST = "request-" + "b" * 24


def _observation(path: str = "/health"):  # type: ignore[no-untyped-def]
    fixture = generate_tenant_record_fixture(b"sidecar-observer-seed-000000000001")
    if path == "/exports?tenant={probe}":
        path = f"/exports?tenant={fixture.probe_tenant_id}"
    if path == "/records/{probe}":
        path = f"/records/{fixture.records_for(fixture.probe_tenant_id)[0].record_id}"
    config = baseline_defense_config(fixture)
    audit = BoundedTenantAuditLog()
    app = TenantRecordApplication(
        fixture=fixture,
        config=config,
        audit_log=audit,
        clock=lambda: datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc),
        request_id_factory=lambda: REQUEST,
    )
    headers = {"host": "tenant-record.test"}
    if path.startswith("/exports") or path.startswith("/records/"):
        headers["x-bluefire-lab-tenant"] = fixture.probe_tenant_id
    response = app.handle("GET", path, headers, source_identity="engine_worker")
    row = audit.row(REQUEST)
    snapshot = tenant_target_snapshot_ref(
        fixture_digest=fixture.digest,
        target_snapshot_id=config.target_snapshot_id,
        service_generation=config.service_generation,
    )
    binding = {
        "attempt_id": ATTEMPT,
        "container_id": "c" * 64,
        "image_digest": "sha256:" + "d" * 64,
        "network_id": "e" * 64,
        "network_name": "bluefire-engine-" + "a" * 32,
        "target_alias": "bf-target-" + "a" * 32,
        "target_address": "172.28.40.2",
        "target_snapshot_ref": snapshot,
        "target_snapshot_id": config.target_snapshot_id,
        "fixture_digest": fixture.digest,
        "service_generation": config.service_generation,
        "owner_journal_ref": content_hash("sidecar-owner"),
    }
    record = {
        "schema_version": OBSERVATION_SCHEMA,
        "attempt_id": ATTEMPT,
        "target_snapshot_ref": snapshot,
        "service_generation": config.service_generation,
        "request_target": path,
        "target_request_id": REQUEST,
        "source_identity": "engine_worker",
        "response_status": response.status,
        "response_headers": dict(response.headers),
        "response_body_b64": base64.urlsafe_b64encode(response.body).decode("ascii").rstrip("="),
        "audit_row": row.to_dict(),
    }
    return binding, record


def _log(binding, record):  # type: ignore[no-untyped-def]
    ready = {
        "schema_version": READY_SCHEMA,
        "attempt_id": ATTEMPT,
        "packet_digest": content_hash("packet"),
        "child_ready_digest": content_hash("child-ready"),
        "target_snapshot_ref": binding["target_snapshot_ref"],
        "service_generation": binding["service_generation"],
        "target_authority": binding["target_alias"] + ":8080",
    }
    return canonical_json_bytes(ready) + b"\n" + canonical_json_bytes(record) + b"\n"


def test_sidecar_record_joins_exact_target_audit_and_response() -> None:
    binding, record = _observation()
    observed = _checked_record(record, binding)
    assert observed.target_request_id == REQUEST
    assert observed.request_target == "/health"
    assert observed.audit_row.response_status == observed.response_status
    assert observed.admitted_target_url == "http://bf-target-" + "a" * 32 + ":8080/health"


@pytest.mark.parametrize(
    "field,value", [("request_target", "/openapi.json"), ("source_identity", "ordinary_user")]
)
def test_sidecar_record_refuses_relabelled_request(field: str, value: str) -> None:
    binding, record = _observation()
    record[field] = value
    with pytest.raises(TenantSidecarObservationError):
        _checked_record(record, binding)


def test_sidecar_record_refuses_changed_body_or_audit() -> None:
    binding, record = _observation()
    record["response_body_b64"] = base64.urlsafe_b64encode(b"changed").decode("ascii").rstrip("=")
    with pytest.raises(TenantSidecarObservationError):
        _checked_record(record, binding)


def test_sidecar_record_refuses_changed_snapshot_or_export_tenant() -> None:
    binding, record = _observation()
    binding["target_snapshot_id"] = "snapshot-changed"
    with pytest.raises(TenantSidecarObservationError, match="response differs"):
        _checked_record(record, binding)

    with pytest.raises(TenantSidecarObservationError, match="snapshot binding"):
        _binding(binding)


def test_sidecar_record_refuses_relabelled_successful_record_lookup() -> None:
    binding, record = _observation("/records/{probe}")
    assert record["response_status"] == 200
    record["request_target"] = "/records/record-aaaaaaaaaaaaaaaaaaaa"
    with pytest.raises(TenantSidecarObservationError, match="response differs"):
        _checked_record(record, binding)

    binding, record = _observation("/exports?tenant={probe}")
    assert record["response_status"] == 200
    record["request_target"] = "/exports?tenant=tenant-other"
    with pytest.raises(TenantSidecarObservationError, match="response differs"):
        _checked_record(record, binding)


@pytest.mark.skipif(os.name != "posix", reason="owner-private sidecar source is Linux-only")
def test_sidecar_observation_is_reopened_from_private_exact_bytes(tmp_path) -> None:  # type: ignore[no-untyped-def]
    binding, record = _observation()
    root = tmp_path / "sidecar-observations"
    root.mkdir(mode=0o700)
    line = _log(binding, record)
    reader = OwnedTenantSidecarObservationReader(
        root=root,
        source_binding=binding,
        read_owned_logs=lambda _limit: line,
        observed_identity=lambda: binding,
    )
    observed = reader.observe_request(REQUEST)
    reopened = reader.reopen_request(ATTEMPT, REQUEST)
    assert reopened.source_receipt_ref == observed.source_receipt_ref
    assert reopened.response_body == observed.response_body
    with pytest.raises(TenantSidecarObservationError):
        reader.reopen_request("engine-attempt-" + "f" * 32, REQUEST)


@pytest.mark.skipif(os.name != "posix", reason="owner-private sidecar source is Linux-only")
def test_sidecar_observation_refuses_duplicate_log_identity(tmp_path) -> None:  # type: ignore[no-untyped-def]
    binding, record = _observation()
    root = tmp_path / "sidecar-observations"
    root.mkdir(mode=0o700)
    line = _log(binding, record)
    reader = OwnedTenantSidecarObservationReader(
        root=root,
        source_binding=binding,
        read_owned_logs=lambda _limit: line + canonical_json_bytes(record) + b"\n",
        observed_identity=lambda: binding,
    )
    with pytest.raises(TenantSidecarObservationError, match="exact"):
        reader.observe_request(REQUEST)


@pytest.mark.skipif(os.name != "posix", reason="owner-private sidecar source is Linux-only")
def test_sidecar_observation_refuses_truncated_docker_log(tmp_path) -> None:  # type: ignore[no-untyped-def]
    binding, record = _observation()
    root = tmp_path / "sidecar-observations"
    root.mkdir(mode=0o700)
    raw = _log(binding, record)[:-3]
    reader = OwnedTenantSidecarObservationReader(
        root=root,
        source_binding=binding,
        read_owned_logs=lambda _limit: raw,
        observed_identity=lambda: binding,
    )
    with pytest.raises(TenantSidecarObservationError, match="incomplete"):
        reader.observe_request(REQUEST)


@pytest.mark.skipif(os.name != "posix", reason="owner-private sidecar source is Linux-only")
def test_sidecar_observation_refuses_replaced_private_directory(tmp_path) -> None:  # type: ignore[no-untyped-def]
    binding, record = _observation()
    root = tmp_path / "sidecar-observations"
    root.mkdir(mode=0o700)
    reader = OwnedTenantSidecarObservationReader(
        root=root,
        source_binding=binding,
        read_owned_logs=lambda _limit: _log(binding, record),
        observed_identity=lambda: binding,
    )
    root.rename(tmp_path / "old-sidecar-observations")
    root.mkdir(mode=0o700)
    with pytest.raises(TenantSidecarObservationError, match="root changed"):
        reader.observe_request(REQUEST)
