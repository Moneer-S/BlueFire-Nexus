from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from bluefire.controlled_scenario_observation_journal import ControllerScenarioObservationJournal
from bluefire.controlled_scenario_sidecar_target import (
    ScenarioSidecarTargetError,
    _captured_http,
    verify_sidecar_target_result,
)
from bluefire.controlled_scenario_target_contract import match_captured_http, pending_command
from bluefire.controlled_strix_scenario import ScenarioObservationRequest
from bluefire.strix_controlled_backend import (
    ControlledExecReceipt,
    ControlledExecRequest,
    ControlledSandboxHandle,
)
from bluefire.strix_controlled_worker_channel import ControlledWorkerBinding, ControllerSettledCall
from bluefire.tenant_record_experiment_fixture import prepare_tenant_record_experiment_case
from bluefire.tenant_record_lab import baseline_defense_config, generate_tenant_record_fixture
from bluefire.tenant_record_observer import BoundedTenantAuditLog, observe_tenant_response
from bluefire.tenant_record_service import TenantRecordApplication
from bluefire.tenant_record_sidecar_observer import (
    OBSERVATION_SCHEMA,
    READY_SCHEMA,
    OwnedTenantSidecarObservationReader,
)
from bluefire.util import canonical_json_bytes

ATTEMPT = "engine-attempt-" + "a" * 32
REQUEST_ID = "request-" + "b" * 24
REF = "sha256:" + "c" * 64


def test_captured_http_rejects_ambiguous_or_incomplete_response():
    with pytest.raises(ScenarioSidecarTargetError, match="ambiguous"):
        _captured_http(b"HTTP/1.1 200 OK\r\n\r\nbody\r\n\r\nextra")
    with pytest.raises(ScenarioSidecarTargetError, match="incomplete"):
        _captured_http(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{}")


def test_pending_shell_command_rejects_extra_shell_effect():
    url = "http://bf-target-" + "a" * 32 + ":8080/openapi.json"
    command = "curl --silent --show-error --include --max-time 5 $(touch /tmp/extra) " + url
    args = json.dumps(
        {"cmd": command, "yield_time_ms": 5000}, sort_keys=True, separators=(",", ":")
    )
    request = ScenarioObservationRequest(
        ATTEMPT,
        REF,
        "discover_target",
        "call_0001_1234567890abcdef",
        "exec_command",
        "sha256:" + hashlib.sha256(args.encode("ascii")).hexdigest(),
        args,
        url,
        REF,
        "sha256:" + hashlib.sha256(b"ok").hexdigest(),
        2,
        "ok",
    )
    with pytest.raises(ScenarioSidecarTargetError, match="command differs"):
        pending_command(request, ["bash", "-lc", command], "protected-tenant")


def test_target_response_rejects_extra_model_visible_header():
    headers = {
        "content-type": "application/json",
        "content-length": "2",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "x-bluefire-lab-request": REQUEST_ID,
    }
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        + b"".join(f"{name}: {value}\r\n".encode("ascii") for name, value in headers.items())
        + b"location: /other\r\n\r\n{}"
    )
    with pytest.raises(ScenarioSidecarTargetError, match="protected target event differ"):
        match_captured_http(raw, source_status=200, source_headers=headers, source_body=b"{}")


@pytest.mark.skipif(os.name != "posix", reason="protected sidecar reader is Linux-only")
def test_exact_captured_shell_joins_protected_sidecar_and_independent_evidence(tmp_path):
    fixture = generate_tenant_record_fixture(b"scenario-sidecar-source-seed-0000001")
    config = baseline_defense_config(fixture)
    case, _criterion, urls = prepare_tenant_record_experiment_case(
        fixture,
        target_config=config,
        attempt_id=ATTEMPT,
        attempt_role="baseline",
        objective_ref=REF,
        environment_ref=REF,
        scope_ref=REF,
    )
    target = TenantRecordApplication(
        fixture=fixture,
        config=config,
        audit_log=BoundedTenantAuditLog(),
        clock=lambda: datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc),
        request_id_factory=lambda: REQUEST_ID,
    )
    response = target.handle(
        "GET", "/openapi.json", {"host": "tenant-record.test"}, source_identity="engine_worker"
    )
    audit = target.audit_log.row(REQUEST_ID)
    binding = {
        "attempt_id": ATTEMPT,
        "container_id": "d" * 64,
        "image_digest": REF,
        "network_id": "e" * 64,
        "network_name": "bluefire-engine-" + "a" * 32,
        "target_alias": "bf-target-" + "a" * 32,
        "target_address": "172.28.40.2",
        "target_snapshot_ref": case.target_snapshot_ref,
        "target_snapshot_id": config.target_snapshot_id,
        "fixture_digest": fixture.digest,
        "service_generation": config.service_generation,
        "owner_journal_ref": REF,
    }
    record = {
        "schema_version": OBSERVATION_SCHEMA,
        "attempt_id": ATTEMPT,
        "target_snapshot_ref": case.target_snapshot_ref,
        "service_generation": config.service_generation,
        "request_target": "/openapi.json",
        "target_request_id": REQUEST_ID,
        "source_identity": "engine_worker",
        "response_status": response.status,
        "response_headers": dict(response.headers),
        "response_body_b64": base64.urlsafe_b64encode(response.body).decode("ascii").rstrip("="),
        "audit_row": audit.to_dict(),
    }
    ready = {
        "schema_version": READY_SCHEMA,
        "attempt_id": ATTEMPT,
        "packet_digest": REF,
        "child_ready_digest": REF,
        "target_snapshot_ref": case.target_snapshot_ref,
        "service_generation": config.service_generation,
        "target_authority": binding["target_alias"] + ":8080",
    }
    sidecar_root = tmp_path / "sidecar-source"
    sidecar_root.mkdir(mode=0o700)
    reader = OwnedTenantSidecarObservationReader(
        root=sidecar_root,
        source_binding=binding,
        read_owned_logs=lambda _limit: (
            canonical_json_bytes(ready) + b"\n" + canonical_json_bytes(record) + b"\n"
        ),
        observed_identity=lambda: binding,
    )
    journal_root = tmp_path / "scenario-source"
    journal_root.mkdir(mode=0o700)
    journal = ControllerScenarioObservationJournal(journal_root / "journal.sqlite")
    url = case.engine_brief()["discovery"]["target"]
    command = "curl --silent --show-error --include --max-time 5 " + url
    args_json = json.dumps(
        {"cmd": command, "yield_time_ms": 5000}, sort_keys=True, separators=(",", ":")
    )
    stdout = (
        b"HTTP/1.1 200 OK\r\n"
        + b"".join(
            f"{name}: {value}\r\n".encode("ascii") for name, value in response.headers.items()
        )
        + b"\r\n"
        + response.body
    )
    handle = ControlledSandboxHandle(ATTEMPT, "sandbox-" + "f" * 32, REF, object())
    operation_id = "operation-" + "0" * 32
    request = ControlledExecRequest(
        "bluefire.strix-controlled-exec-request.v1",
        REF,
        REF,
        operation_id,
        handle,
        ("bash", "-lc", command),
        5.0,
        "/workspace",
    )
    receipt = ControlledExecReceipt(
        "bluefire.strix-controlled-exec-receipt.v1",
        REF,
        REF,
        REF,
        0,
        "sha256:" + hashlib.sha256(stdout).hexdigest(),
        "sha256:" + hashlib.sha256(b"").hexdigest(),
        stdout,
        b"",
    )
    settled = ControllerSettledCall(
        ControlledWorkerBinding(ATTEMPT, REF, REF, REF, REF, REF, 10_000_000_000, "1" * 32),
        "exec_exact",
        "rpc-0001",
        request,
        receipt,
        b"frame",
        5,
    )
    captured = journal.capture_settled_exec(settled)
    assert captured is not None
    scenario_request = ScenarioObservationRequest(
        ATTEMPT,
        REF,
        "discover_target",
        "call_0001_1234567890abcdef",
        "exec_command",
        "sha256:" + hashlib.sha256(args_json.encode("ascii")).hexdigest(),
        args_json,
        url,
        urls.digest,
        "sha256:" + hashlib.sha256(stdout).hexdigest(),
        len(stdout),
        stdout.decode("utf-8"),
    )
    trusted_source = reader.observe_request(REQUEST_ID)
    initial_evidence = observe_tenant_response(
        fixture=fixture,
        config=config,
        audit_row=trusted_source.audit_row,
        response_status=trusted_source.response_status,
        response_headers=trusted_source.response_headers,
        response_body=trusted_source.response_body,
        attempt_id=ATTEMPT,
        run_id="run-20261113T120000Z-0123456789abcdef",
        step_id="discover_target",
        target_scope_ref=case.scope_ref,
    )
    with pytest.raises(ValueError, match="sidecar evidence source is invalid"):
        journal.retain_sidecar_evidence(
            request=scenario_request,
            operation_id=operation_id,
            sidecar_source_ref=trusted_source.source_receipt_ref,
            target_request_id=REQUEST_ID,
            evidence=replace(initial_evidence, content={"request_id": REQUEST_ID}),
            reader=reader,
            fixture=fixture,
            config=config,
            case=case,
            url_set=urls,
        )
    assert (
        journal.reopen_sidecar_attempt(
            ATTEMPT,
            reader=reader,
            fixture=fixture,
            config=config,
            case=case,
            url_set=urls,
        )
        == ()
    )
    verified = verify_sidecar_target_result(
        request=scenario_request,
        operation_id=operation_id,
        journal=journal,
        reader=reader,
        fixture=fixture,
        target_config=config,
        case=case,
        url_set=urls,
        run_id="run-20261113T120000Z-0123456789abcdef",
        step_id="discover_target",
    )
    assert verified.observed.target_request_id == REQUEST_ID
    assert verified.evidence.content["independent_observation"] is True
    assert verified.evidence.content["request_id"] == REQUEST_ID
    assert (
        verified.sidecar_source_ref == reader.reopen_request(ATTEMPT, REQUEST_ID).source_receipt_ref
    )
    reopened = journal.reopen_sidecar_evidence(
        scenario_request.digest,
        reader=reader,
        fixture=fixture,
        config=config,
        case=case,
        url_set=urls,
    )
    assert reopened.evidence.record_hash == verified.evidence.record_hash
    assert reopened.retention_ref == verified.evidence_retention_ref
    source_identity = journal.source_identity_ref
    reopened_journal = ControllerScenarioObservationJournal(journal_root / "journal.sqlite")
    assert reopened_journal.source_identity_ref == source_identity
    seal_ref = reopened_journal.seal_sidecar_attempt(
        ATTEMPT,
        (scenario_request.digest,),
        REF,
        reader=reader,
        fixture=fixture,
        config=config,
        case=case,
        url_set=urls,
    )
    sealed_ref, terminal_ref, complete = reopened_journal.reopen_sealed_sidecar_attempt(
        ATTEMPT,
        reader=reader,
        fixture=fixture,
        config=config,
        case=case,
        url_set=urls,
    )
    assert (sealed_ref, terminal_ref) == (seal_ref, REF)
    assert tuple(item.request_ref for item in complete) == (scenario_request.digest,)
    staged = reopened_journal.reopen_staged_independent_observations(
        ATTEMPT,
        mechanism_ref=REF,
        verified_terminal_ref=REF,
        reader=reader,
        fixture=fixture,
        config=config,
        case=case,
        url_set=urls,
    )
    assert len(staged) == 1
    assert staged[0].evidence.record_hash == verified.evidence.record_hash
    wrong_urls = replace(urls, urls=urls.urls[:-1])
    wrong_request = replace(scenario_request, authorized_url_set_ref=wrong_urls.digest)
    with pytest.raises(
        ScenarioSidecarTargetError, match="target source and pending attempt differ"
    ):
        verify_sidecar_target_result(
            request=wrong_request,
            operation_id=operation_id,
            journal=journal,
            reader=reader,
            fixture=fixture,
            target_config=config,
            case=case,
            url_set=wrong_urls,
            run_id="run-20261113T120000Z-0123456789abcdef",
            step_id="discover_target",
        )
