from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from bluefire.engine_execution_proof import (
    EngineExecutionProofError,
    execution_proof_receipt,
    project_attempt_execution_proof,
)

ATTEMPT_ID = "engine-attempt-" + "1" * 32
RUN_ID = "run-20261105T120000Z-" + "2" * 16
REVISION = "3" * 40
DIGEST = "sha256:" + "4" * 64
MANIFEST = "sha256:" + "5" * 64
ENGINE_EVIDENCE = "engine-evidence-" + "6" * 24
INDEPENDENT_EVIDENCE = "evidence-" + "7" * 20
ARTIFACT_ID = "artifact-" + "8" * 32


def _proof() -> dict[str, Any]:
    proof: dict[str, Any] = {
        "schema_version": "bluefire.installed-engine-execution-proof.v1",
        "attempt_id": ATTEMPT_ID,
        "run_id": RUN_ID,
        "controller_receipt_ref": DIGEST,
        "runtime": {
            "engine_id": "strix",
            "engine_revision": REVISION,
            "engine_package_digest": DIGEST,
            "runtime_identity_ref": "sha256:" + "9" * 64,
            "image_identity_ref": "sha256:" + "a" * 64,
            "runtime_activation_ref": "sha256:" + "b" * 64,
            "runtime_closure_ref": "sha256:" + "c" * 64,
            "fixed_exec_receipt_ref": "sha256:" + "d" * 64,
            "startup_overlay_ref": "sha256:" + "e" * 64,
            "installed_service_started": True,
            "native_worker_started": True,
        },
        "tool_execution": {
            "executed": True,
            "events": [
                {
                    "event_id": "engine-tool-event-" + "f" * 24,
                    "tool_name": "http_request",
                    "state": "completed",
                    "receipt_ref": "sha256:" + "1" * 64,
                    "occurred_at": "2026-11-05T12:00:00Z",
                }
            ],
        },
        "target": {
            "response_observed": True,
            "response_receipt_ref": "sha256:" + "2" * 64,
            "independent_evidence_refs": [INDEPENDENT_EVIDENCE],
        },
        "model": {
            "kind": "test",
            "provider": "test.provider",
            "id": "test-model",
            "live_model_proof": False,
            "requests": 2,
            "input_tokens": 120,
            "output_tokens": 48,
            "cost_microusd": 0,
            "lease_revocation_receipt_ref": "sha256:" + "3" * 64,
            "bearer_redaction_attested": True,
        },
        "protocol_provider": {
            "kind": "test_caido_protocol",
            "identity_ref": "sha256:" + "4" * 64,
            "live_caido_proof": False,
        },
        "artifact_manifest_ref": MANIFEST,
        "artifacts": [
            {
                "artifact_id": ARTIFACT_ID,
                "attempt_id": ATTEMPT_ID,
                "name": "normalized-findings.json",
                "sha256": "sha256:" + "5" * 64,
                "bytes": 240,
                "media_type": "application/json",
                "access": "private",
            }
        ],
        "findings": [
            {
                "finding_id": "engine-finding-" + "6" * 24,
                "attempt_id": ATTEMPT_ID,
                "title": "Protected record disclosed",
                "severity": "high",
                "mechanism_digest": "sha256:" + "7" * 64,
                "status": "reproduced",
                "summary": "The retained controller record links the finding to the observed response.",
                "source_artifact_id": ARTIFACT_ID,
                "evidence_ids": [ENGINE_EVIDENCE],
            }
        ],
    }
    proof["controller_receipt_ref"] = execution_proof_receipt(proof)
    return proof


def _project(proof: dict[str, Any] | None, *, model_test_provider: bool = True) -> dict[str, Any]:
    run = (
        {"run_id": RUN_ID} if proof is None else {"run_id": RUN_ID, "engine_execution_proof": proof}
    )
    return project_attempt_execution_proof(
        run,
        attempt_id=ATTEMPT_ID,
        run_id=RUN_ID,
        engine_revision=REVISION,
        engine_package_digest=DIGEST,
        model_provider="test.provider",
        model_id="test-model",
        model_test_provider=model_test_provider,
        independent_evidence_refs=(INDEPENDENT_EVIDENCE,),
        engine_evidence_refs=(ENGINE_EVIDENCE,),
        artifact_manifest_ref=MANIFEST,
        artifact_byte_limit=1024,
        action_limit=4,
    )


def _rehash(proof: dict[str, Any]) -> dict[str, Any]:
    proof["controller_receipt_ref"] = execution_proof_receipt(proof)
    return proof


def test_projects_fixture_receipt_shape_without_upgrading_test_providers() -> None:
    result = _project(_proof())

    assert result["execution_proof"]["status"] == "target_observed"
    assert result["execution_proof"]["installed_service_started"] is True
    assert result["execution_proof"]["native_worker_started"] is True
    assert result["execution_proof"]["tool_execution_proven"] is True
    assert result["execution_proof"]["target_response_proven"] is True
    assert result["execution_proof"]["target_response_receipt_ref"] == "sha256:" + "2" * 64
    assert result["execution_proof"]["model"]["kind"] == "test"
    assert result["execution_proof"]["model"]["live_model_proof"] is False
    assert result["execution_proof"]["protocol_provider"]["kind"] == "test_caido_protocol"
    assert result["execution_proof"]["protocol_provider"]["live_caido_proof"] is False
    assert result["usage"]["tool_calls"] == 1
    assert result["tool_events"][0]["tool_name"] == "http_request"
    assert result["findings"][0]["evidence_ids"] == [ENGINE_EVIDENCE]
    assert result["artifacts"][0]["sha256"] == "sha256:" + "5" * 64


def test_missing_legacy_proof_stays_explicitly_unverified() -> None:
    result = _project(None)

    assert result["execution_proof"]["status"] == "unverified"
    assert result["execution_proof"]["controller_receipt_ref"] is None
    assert result["execution_proof"]["target_response_receipt_ref"] is None
    assert result["execution_proof"]["model"]["kind"] == "unverified"
    assert result["execution_proof"]["protocol_provider"]["kind"] == "unverified"
    assert result["tool_events"] is None
    assert result["findings"] is None
    assert result["artifacts"] is None
    assert result["usage"]["tool_calls"] is None


def test_test_provider_cannot_be_reported_as_verified_live_inference() -> None:
    proof = _proof()
    proof["model"]["kind"] = "live"
    proof["model"]["live_model_proof"] = True
    _rehash(proof)

    with pytest.raises(EngineExecutionProofError, match="model execution proof changed"):
        _project(proof)


def test_live_inference_requires_a_retained_model_request() -> None:
    proof = _proof()
    proof["model"]["kind"] = "live"
    proof["model"]["live_model_proof"] = True
    proof["model"]["requests"] = 0
    _rehash(proof)

    with pytest.raises(EngineExecutionProofError, match="no retained request"):
        _project(proof, model_test_provider=False)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda proof: proof["runtime"].update(installed_service_started=False),
        lambda proof: proof["tool_execution"]["events"][0].update(state="started"),
        lambda proof: proof["target"].update(independent_evidence_refs=[]),
        lambda proof: proof["model"].update(bearer_redaction_attested=False),
        lambda proof: proof["model"].update(lease_revocation_receipt_ref=None),
        lambda proof: proof["model"].update(live_model_proof=True),
        lambda proof: proof["protocol_provider"].update(live_caido_proof=True),
        lambda proof: proof["artifacts"][0].update(name="../report.json"),
        lambda proof: proof["findings"][0].update(evidence_ids=["engine-evidence-" + "8" * 24]),
    ],
)
def test_refuses_malformed_or_unbound_execution_claims(mutate: Any) -> None:
    proof = deepcopy(_proof())
    mutate(proof)
    _rehash(proof)

    with pytest.raises(EngineExecutionProofError):
        _project(proof)


def test_refuses_receipt_tampering_even_when_fields_still_parse() -> None:
    proof = _proof()
    proof["model"]["requests"] = 3

    with pytest.raises(EngineExecutionProofError, match="receipt"):
        _project(proof)
