from __future__ import annotations

import pytest

from bluefire.detections import (
    DetectionCandidate,
    DetectionError,
    DetectionPipeline,
    DetectionState,
)
from bluefire.evidence import EvidenceProvenance, EvidenceRecord


def _candidate() -> DetectionCandidate:
    return DetectionCandidate.hypothesis(
        behavior_id="collection.stage_fixture.v1",
        title="Sandbox fixture staged",
        target_language="sigma",
        logsource={"category": "file_event", "product": "generic"},
        selection={"artifact_type": "file_observation", "path|contains": "staged/"},
        provenance={"kind": "authored", "reference": "bluefire-catalog"},
        known_misses=("No filesystem collector is available.",),
    )


def test_detection_lifecycle_is_evidence_driven() -> None:
    pipeline = DetectionPipeline()
    candidate = pipeline.parse(_candidate())
    assert candidate.state is DetectionState.PARSED
    candidate = pipeline.exercise_fixtures(
        candidate,
        [
            {
                "fixture_id": "malicious-1",
                "artifact_type": "file_observation",
                "path": "staged/a.txt",
            }
        ],
    )
    assert candidate.state is DetectionState.FIXTURE_EXERCISED

    observed = EvidenceRecord.create(
        run_id="run-test",
        step_id="stage",
        behavior_id="collection.stage_fixture.v1",
        action_id="sandbox.collection.stage.v1",
        provenance=EvidenceProvenance.OBSERVED,
        producer="sandbox-observer.v1",
        runner_profile_id="profile.test",
        content={"artifact_type": "file_observation", "path": "staged/a.txt"},
        target_scope_ref="runner-profile:profile.test",
    )
    candidate = pipeline.exercise_observed(candidate, [observed])
    assert candidate.state is DetectionState.OBSERVED_EXERCISED
    assert candidate.observed_evidence_ids == (observed.evidence_id,)

    candidate = pipeline.evaluate_benign(
        candidate,
        [
            {
                "fixture_id": "benign-1",
                "artifact_type": "file_observation",
                "path": "documents/a.txt",
            }
        ],
        notes=("Benign fixture did not match.",),
    )
    assert candidate.state is DetectionState.BENIGN_EVALUATED
    assert candidate.benign_match_count == 0


def test_rendering_or_parsing_alone_cannot_skip_to_validated() -> None:
    with pytest.raises(DetectionError):
        _candidate().transition(DetectionState.BENIGN_EVALUATED)


def test_nonmatching_malicious_fixture_rejects_candidate() -> None:
    pipeline = DetectionPipeline()
    candidate = pipeline.exercise_fixtures(
        pipeline.parse(_candidate()),
        [{"fixture_id": "malicious-1", "artifact_type": "other", "path": "a.txt"}],
    )
    assert candidate.state is DetectionState.REJECTED
    assert candidate.rejection_reason
