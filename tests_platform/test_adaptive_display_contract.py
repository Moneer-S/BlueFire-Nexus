"""Keep the authored frontend fixture bound to the actual observation producer.

This is deterministic software evidence, not a host observation, executed gzip
operation, live-provider result, or experiment. Regenerate explicitly with:
python -m tests_platform.test_adaptive_display_contract --write-fixture
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from bluefire.adaptive_observations import project_runtime_observations
from bluefire.evidence import EvidenceProvenance, EvidenceRecord
from bluefire.file_permissions import PERMISSION_LIMITATION

FIXTURE_PATH = (
    Path(__file__).resolve().parents[1]
    / "frontend"
    / "tests"
    / "fixtures"
    / "adaptive-observation-contract.json"
)
AUTHORED_LABEL = (
    "Authored software fixture; no host observation, executed gzip operation, "
    "live-provider result, or experiment."
)


def build_adaptive_observation_contract() -> dict[str, Any]:
    """Build the shared contract with fixed inputs and the production projector."""
    record = EvidenceRecord.create(
        run_id="authored-adaptive-display-run",
        step_id="inspect",
        behavior_id="endpoint.discovery.system.v1",
        action_id="sandbox.discovery.list.v1",
        provenance=EvidenceProvenance.OBSERVED,
        producer="authored-display-contract",
        target_scope_ref="fixture-scope",
        timestamp="2026-09-20T00:00:00Z",
        limitations=(AUTHORED_LABEL,),
        content={
            "artifact_type": "collector_observation",
            "observation_kind": "filesystem",
            "observed_fields": {
                "permission_status": "available",
                "effective_access": "not_evaluated",
                "permission_mode_octal": "0660",
                "group_write_bit": True,
                "other_write_bit": False,
                "non_owner_write_bit": True,
            },
        },
    )
    source_step = {
        "step_id": record.step_id,
        "behavior_id": record.behavior_id,
        "action_id": record.action_id,
        "status": "failed",
        "evidence_ids": [record.evidence_id, "unresolved-authored-evidence"],
        "error": {"code": "atomic_gzip_timeout"},
    }
    projection = project_runtime_observations(
        steps=[source_step],
        records=[record],
        alternatives=[],
        artifacts={},
        platform="linux",
        remaining_steps=2,
        remaining_seconds=10.0,
        retries_remaining=1,
    )
    return {
        "authored_label": AUTHORED_LABEL,
        "run_id": record.run_id,
        "source_step": source_step,
        "evidence": [record.to_dict()],
        "projection": projection,
    }


def test_committed_display_fixture_matches_actual_producer() -> None:
    committed = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    generated = build_adaptive_observation_contract()
    assert committed == generated
    assert generated == build_adaptive_observation_contract()


def test_display_contract_retains_permissions_failure_gap_and_uncertainty() -> None:
    projection = build_adaptive_observation_contract()["projection"]
    attempt = projection["attempts"][0]
    facts = attempt["evidence"][0]["facts"]
    assert facts["artifact_type"] == "collector_observation"
    assert facts["observation_kind"] == "filesystem"
    assert facts["permission_status"] == "available"
    assert facts["permission_mode_octal"] == "0660"
    assert facts["group_write_bit"] is True
    assert facts["other_write_bit"] is False
    assert facts["non_owner_write_bit"] is True
    assert facts["effective_access"] == "not_evaluated"
    failure = attempt["failure"]
    assert failure["classification"] == "execution_timeout"
    assert failure["code"] == "atomic_gzip_timeout"
    assert failure["telemetry_gap"] is True
    assert failure["unrecognized_code_present"] is False
    assert failure["target_prevention"] == "not_established"
    assert attempt["missing_evidence_count"] == 1
    assert PERMISSION_LIMITATION in projection["unknowns"]
    assert "Target prevention is not established by a product refusal." in projection["unknowns"]


def test_display_contract_keeps_verified_evidence_and_source_step_references() -> None:
    fixture = build_adaptive_observation_contract()
    record = EvidenceRecord.from_mapping(fixture["evidence"][0])
    source_step = fixture["source_step"]
    attempt = fixture["projection"]["attempts"][0]
    projected = attempt["evidence"][0]
    assert fixture["authored_label"] == AUTHORED_LABEL
    assert fixture["run_id"] == record.run_id
    assert attempt["step_id"] == source_step["step_id"] == record.step_id
    assert attempt["behavior_id"] == source_step["behavior_id"] == record.behavior_id
    assert attempt["action_id"] == source_step["action_id"] == record.action_id
    assert projected["evidence_id"] == record.evidence_id
    assert projected["record_hash"] == record.record_hash
    assert projected["provenance"] == "observed"
    assert source_step["evidence_ids"] == [record.evidence_id, "unresolved-authored-evidence"]
    assert len(attempt["evidence"]) == 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Regenerate the authored display contract fixture."
    )
    parser.add_argument("--write-fixture", action="store_true", required=True)
    parser.parse_args()
    FIXTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE_PATH.write_text(
        json.dumps(build_adaptive_observation_contract(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
