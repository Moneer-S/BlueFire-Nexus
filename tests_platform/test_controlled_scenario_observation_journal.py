"""Intermediate evidence must survive a model continuation and reject drift."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from dataclasses import replace

import pytest

import bluefire.controlled_scenario_observation_journal as observation_journal
from bluefire.controlled_scenario_observation_journal import (
    ControllerScenarioObservationJournal,
    ScenarioObservationJournalError,
    ScenarioObservationLinks,
)
from bluefire.controlled_strix_scenario import ScenarioObservationRequest
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.strix_controlled_backend import (
    ControlledExecReceipt,
    ControlledExecRequest,
    ControlledSandboxHandle,
)
from bluefire.strix_controlled_worker_channel import (
    ControlledWorkerBinding,
    ControllerSettledCall,
)
from bluefire.tenant_record_controller_contract import tenant_target_snapshot_ref
from bluefire.util import content_hash

ATTEMPT = "engine-attempt-" + "a" * 32
REF = "sha256:" + "1" * 64
RELAY_ID = "relay-request-" + "b" * 32
TARGET_ID = "request-" + "c" * 24


def _journal(tmp_path, monkeypatch) -> ControllerScenarioObservationJournal:
    root = tmp_path / "protected"
    root.mkdir(mode=0o700)
    # The local Windows sandbox cannot set the strict owner-only DACL. These
    # generated-data contract tests exercise journal semantics; Linux CI must
    # exercise the real filesystem privacy boundary.
    if observation_journal.os.name == "nt":
        monkeypatch.setattr(
            ControllerScenarioObservationJournal,
            "_verify_private_path",
            staticmethod(lambda _path, *, directory: None),
        )
        monkeypatch.setattr(
            observation_journal, "apply_owner_private_acl_path", lambda _path, *, directory: None
        )
    return ControllerScenarioObservationJournal(root / "observation.sqlite")


def _case(journal: ControllerScenarioObservationJournal):
    body = b'{"service":"tenant-record-lab"}\n'
    response_hash = "sha256:" + hashlib.sha256(body).hexdigest()
    target_url = "http://bf-target-" + "a" * 32 + ":8080/openapi.json"
    command = "curl --silent --show-error --include --max-time 5 " + target_url
    arguments_json = json.dumps({"cmd": command, "yield_time_ms": 5000}, sort_keys=True, separators=(",", ":"))
    request = ScenarioObservationRequest(
        attempt_id=ATTEMPT,
        scenario_ref=REF,
        phase_id="discover_target",
        call_id="call_0001_1234567890abcdef",
        tool_name="exec_command",
        arguments_digest="sha256:" + hashlib.sha256(arguments_json.encode("ascii")).hexdigest(),
        arguments_json=arguments_json,
        target_url=target_url,
        authorized_url_set_ref=REF,
        model_result_digest="sha256:" + hashlib.sha256(b"fixture text").hexdigest(),
        model_result_bytes=len(b"fixture text"),
        model_result="fixture text",
    )
    handle = ControlledSandboxHandle(ATTEMPT, "sandbox-" + "d" * 32, REF, object())
    tool_request = ControlledExecRequest(
        "bluefire.strix-controlled-exec-request.v1",
        REF,
        REF,
        "operation-" + "e" * 32,
        handle,
        ("bash", "-lc", command),
        5.0,
        "/workspace",
    )
    terminal = b"fixture text"
    tool_receipt = ControlledExecReceipt(
        "bluefire.strix-controlled-exec-receipt.v1",
        REF,
        REF,
        REF,
        0,
        "sha256:" + hashlib.sha256(terminal).hexdigest(),
        "sha256:" + hashlib.sha256(b"").hexdigest(),
        terminal,
        b"",
    )
    binding = ControlledWorkerBinding(
        ATTEMPT, REF, REF, REF, REF, REF, 10_000_000_000, "f" * 32
    )
    settled = ControllerSettledCall(
        binding, "exec_exact", "rpc-0001", tool_request, tool_receipt, b"response-frame", 5
    )
    captured = journal.capture_settled_exec(settled)
    assert captured is not None
    operation = {"attempt_id": ATTEMPT, "request_id": RELAY_ID, "route_id": "metadata"}
    audit = {"request_id": RELAY_ID, "status": "succeeded", "evidence_ref": REF}
    target_audit = {
        "request_id": TARGET_ID,
        "route": "metadata",
        "response_status": 200,
        "response_bytes": len(body),
        "response_sha256": response_hash,
        "target_snapshot_id": "snapshot-lab",
        "service_generation": "generation-lab",
    }
    headers = {
        "content-type": "application/json",
        "content-length": str(len(body)),
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
        "x-bluefire-lab-request": TARGET_ID,
    }
    header_hash = content_hash(headers)
    target_audit["response_headers_sha256"] = header_hash
    receipt = {
        "request_id": RELAY_ID,
        "audit_record_digest": content_hash(audit),
        "operation": "metadata",
        "response_status": 200,
        "response_digest": response_hash,
        "response_bytes": len(body),
    }
    docs = {
        "tool": captured.document,
        "relay_operation": operation,
        "relay_audit": audit,
        "relay_receipt": receipt,
        "target_audit": target_audit,
        "target_response": {
            "schema_version": "bluefire.scenario-target-response.v1",
            "status": 200,
            "headers": headers,
            "body_base64": base64.b64encode(body).decode("ascii"),
            "target_observation_ref": REF,
        },
    }
    links = ScenarioObservationLinks(
        attempt_id=ATTEMPT,
        claim_ref=REF,
        activation_ref=REF,
        tool_request_id=captured.request_id,
        tool_receipt_ref=REF,
        tool_capture_ref=captured.capture_ref,
        execution_admission_ref=REF,
        dispatch_ref=REF,
        attachment_ref=REF,
        terminal_ref=REF,
        relay_request_id=RELAY_ID,
        relay_operation_ref=content_hash(operation),
        relay_receipt_ref=content_hash(receipt),
        relay_audit_ref=content_hash(audit),
        admitted_target_url=request.target_url,
        authorized_url_set_ref=request.authorized_url_set_ref,
        target_request_id=TARGET_ID,
        target_audit_ref=content_hash(target_audit),
        target_response_ref=REF,
        target_snapshot_ref=tenant_target_snapshot_ref(
            fixture_digest=REF,
            target_snapshot_id="snapshot-lab",
            service_generation="generation-lab",
        ),
        service_generation="generation-lab",
    )
    evidence = EvidenceRecord.create(
        run_id="run-" + "e" * 32,
        step_id="discover_target",
        behavior_id="tenant_record_authorization_boundary",
        provenance=EvidenceProvenance.OBSERVED,
        producer="bluefire.tenant-record-observer",
        content={
            "attempt_id": ATTEMPT,
            "request_id": TARGET_ID,
            "audit_row_digest": links.target_audit_ref,
            "response_status": 200,
            "service_generation": links.service_generation,
            "response_sha256": response_hash,
            "response_headers_sha256": header_hash,
            "target_snapshot_id": "snapshot-lab",
        },
        target_scope_ref=REF,
        environment={"fixture_digest": REF},
    )
    return request, links, evidence, docs


def test_retained_observation_reopens_before_continuation(tmp_path, monkeypatch):
    journal = _journal(tmp_path, monkeypatch)
    path = journal.path
    request, links, evidence, docs = _case(journal)
    retained = journal.retain(
        request=request, links=links, evidence=evidence, source_documents=docs
    )
    assert retained.request_ref == request.digest
    assert retained.retention_ref != evidence.record_hash
    assert retained.evidence.record_hash == evidence.record_hash
    reopened = ControllerScenarioObservationJournal(path).reopen(request.digest)
    assert reopened == retained
    assert ControllerScenarioObservationJournal(path).reopen_attempt(ATTEMPT) == (retained,)
    seal = journal.seal_attempt(ATTEMPT, (request.digest,))
    assert journal.reopen_sealed_attempt(ATTEMPT) == (seal, (retained,))
    with pytest.raises(ScenarioObservationJournalError, match="sealed"):
        journal.retain(request=request, links=links, evidence=evidence, source_documents=docs)


def test_changed_or_reused_source_refused(tmp_path, monkeypatch):
    journal = _journal(tmp_path, monkeypatch)
    request, links, evidence, docs = _case(journal)
    journal.retain(request=request, links=links, evidence=evidence, source_documents=docs)
    with pytest.raises(ScenarioObservationJournalError, match="settled tool capture differs"):
        journal.retain(
            request=request,
            links=links,
            evidence=evidence,
            source_documents={**docs, "tool": {"call_id": "changed"}},
        )
    with pytest.raises(ScenarioObservationJournalError, match="source was reused"):
        journal.retain(
            request=replace(request, phase_id="alternate"),
            links=links,
            evidence=evidence,
            source_documents=docs,
        )


def test_target_response_mismatch_refused(tmp_path, monkeypatch):
    journal = _journal(tmp_path, monkeypatch)
    request, links, evidence, docs = _case(journal)
    altered = {**docs, "target_response": {**docs["target_response"], "body_base64": "YQ=="}}
    with pytest.raises(ScenarioObservationJournalError, match="source identities differ"):
        journal.retain(
            request=request, links=links, evidence=evidence, source_documents=altered
        )
    assert journal.reopen_attempt(ATTEMPT) == ()


def test_initial_source_mismatches_refused(tmp_path, monkeypatch):
    journal = _journal(tmp_path, monkeypatch)
    request, links, evidence, docs = _case(journal)
    with pytest.raises(ScenarioObservationJournalError, match="settled shell differs"):
        journal.retain(
            request=replace(request, target_url=request.target_url.replace("/openapi.json", "/health")),
            links=replace(links, admitted_target_url=request.target_url.replace("/openapi.json", "/health")),
            evidence=evidence,
            source_documents=docs,
        )
    with pytest.raises(ScenarioObservationJournalError, match="target response headers"):
        journal.retain(
            request=request,
            links=links,
            evidence=evidence,
            source_documents={**docs, "target_response": {**docs["target_response"], "headers": {}}},
        )
    with pytest.raises(ScenarioObservationJournalError, match="source identities differ"):
        journal.retain(
            request=request,
            links=replace(links, target_snapshot_ref=REF),
            evidence=evidence,
            source_documents=docs,
        )
    with pytest.raises(ScenarioObservationJournalError, match="model-visible"):
        journal.retain(
            request=replace(request, model_result="fabricated"),
            links=links,
            evidence=evidence,
            source_documents=docs,
        )
    forged = "unobserved success\n" + request.model_result
    with pytest.raises(ScenarioObservationJournalError, match="settled shell differs"):
        journal.retain(
            request=replace(
                request,
                model_result=forged,
                model_result_digest="sha256:" + hashlib.sha256(forged.encode()).hexdigest(),
                model_result_bytes=len(forged.encode()),
            ),
            links=links,
            evidence=evidence,
            source_documents=docs,
        )
    assert journal.reopen_attempt(ATTEMPT) == ()


def test_reopened_byte_tampering_refused(tmp_path, monkeypatch):
    journal = _journal(tmp_path, monkeypatch)
    path = journal.path
    request, links, evidence, docs = _case(journal)
    journal.retain(request=request, links=links, evidence=evidence, source_documents=docs)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER observations_no_update")
        connection.execute("UPDATE observations SET retention_ref=?", (REF,))
    with pytest.raises(ScenarioObservationJournalError, match="linkage changed"):
        journal.reopen(request.digest)


def test_seal_rejects_missing_provider_trace(tmp_path, monkeypatch):
    journal = _journal(tmp_path, monkeypatch)
    request, links, evidence, docs = _case(journal)
    journal.retain(request=request, links=links, evidence=evidence, source_documents=docs)
    with pytest.raises(ScenarioObservationJournalError, match="provider trace"):
        journal.seal_attempt(ATTEMPT, ())
    with pytest.raises(ScenarioObservationJournalError, match="not sealed"):
        journal.reopen_sealed_attempt(ATTEMPT)


def test_role_terminal_receipt_reopens_by_exact_owner(tmp_path, monkeypatch):
    journal = _journal(tmp_path, monkeypatch)
    document = {
        "schema_version": "bluefire.installed-strix-v2-source-collection-terminal.v1",
        "attempt_id": ATTEMPT,
        "owner_ref": REF,
        "state": "verified_absent",
        "evidence_ref": REF,
    }
    document["receipt_ref"] = content_hash(document)
    ref = journal.retain_role_terminal(document)
    assert ref == document["receipt_ref"]
    assert journal.reopen_role_terminal(ref) == document
    assert journal.reopen_latest_role_terminal(ATTEMPT, "source_collection", REF) == document
    assert journal.reopen_latest_role_terminal(ATTEMPT, "source_collection", "sha256:" + "2" * 64) is None
    changed = {**document, "state": "verified_settled"}
    changed["receipt_ref"] = content_hash({key: value for key, value in changed.items() if key != "receipt_ref"})
    with pytest.raises(ScenarioObservationJournalError, match="retry differs"):
        journal.retain_role_terminal(changed)
