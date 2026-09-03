from __future__ import annotations

import pytest

from bluefire.detections import (
    DetectionCandidate,
    DetectionError,
    DetectionPipeline,
    DetectionState,
    ExternalDetectionValidator,
)
from bluefire.evidence import EvidenceProvenance, EvidenceRecord


def _candidate() -> DetectionCandidate:
    return DetectionCandidate.hypothesis(
        behavior_id="collection.stage_fixture.v1",
        title="Sandbox fixture staged",
        target_language="internal",
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
    nonmatching = EvidenceRecord.create(
        run_id="run-test",
        step_id="stage-other",
        behavior_id="collection.stage_fixture.v1",
        action_id="sandbox.collection.stage.v1",
        provenance=EvidenceProvenance.OBSERVED,
        producer="sandbox-observer.v1",
        content={"artifact_type": "file_observation", "path": "documents/a.txt"},
        target_scope_ref="runner-profile:profile.test",
    )
    candidate = pipeline.exercise_observed(candidate, [observed, nonmatching])
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


def test_detection_candidate_rehydration_is_strict_and_identity_bound() -> None:
    document = _candidate().to_dict()
    assert DetectionCandidate.from_mapping(document).to_dict() == document

    tampered = {**document, "candidate_id": "detection-00000000000000000000"}
    with pytest.raises(DetectionError, match="identity"):
        DetectionCandidate.from_mapping(tampered)

    with pytest.raises(DetectionError, match="unknown fields"):
        DetectionCandidate.from_mapping({**document, "unreviewed": True})

    changed_definition = {**document, "title": "Tampered immutable title"}
    with pytest.raises(DetectionError, match="definition_digest"):
        DetectionCandidate.from_mapping(changed_definition)


def test_public_baseline_contract_is_exact_and_definition_bound() -> None:
    baseline = {
        "schema_version": "bluefire.public-baseline.v1",
        "research_source_id": "research.atomic-red-team.v1",
        "source_digest": "sha256:" + "a" * 64,
        "pin": "6132b92779873cb0d05bef07ba0a480d47eb1cc8",  # pragma: allowlist secret
        "version": "2026-08-24 snapshot",
        "license": "MIT",
        "license_review": "reviewed",
        "relationship": "comparative",
        "use": "comparison",
    }
    enriched_baseline = {
        **baseline,
        "schema_version": "bluefire.public-baseline.v2",
        "exact_ref": "6132b92779873cb0d05bef07ba0a480d47eb1cc8",
        "retrieved_at": "2026-08-25",
        "file_level_license_review": "Repository license reviewed at the pinned commit.",
        "trademark_considerations": "No marks are used in generated rule content.",
        "use_classification": "reference_only",
        "attribution": "Atomic Red Team metadata retained for comparison only.",
        "security_review": "Public tests are not fetched, copied, or executed.",
        "last_verified_at": "2026-08-25",
        "update_status": "current",
    }
    candidate = DetectionCandidate.hypothesis(
        behavior_id="collection.stage_fixture.v1",
        title="Source-linked baseline",
        target_language="internal",
        logsource={"category": "file_event"},
        selection={"path|contains": "staged/"},
        provenance={"source": "operator", "license": "MIT"},
        public_baselines=[baseline],
    )

    assert candidate.public_baselines == (baseline,)
    enriched = DetectionCandidate.hypothesis(
        behavior_id="collection.stage_fixture.v1",
        title="Source-linked enriched baseline",
        target_language="internal",
        logsource={"category": "file_event"},
        selection={"path|contains": "staged/"},
        provenance={"source": "operator", "license": "MIT"},
        public_baselines=[enriched_baseline],
    )
    assert enriched.public_baselines == (enriched_baseline,)
    with pytest.raises(DetectionError, match="exactly"):
        DetectionCandidate.hypothesis(
            behavior_id="collection.stage_fixture.v1",
            title="Invalid baseline",
            target_language="internal",
            logsource={"category": "file_event"},
            selection={"path|contains": "staged/"},
            provenance={"source": "operator", "license": "MIT"},
            public_baselines=[{**baseline, "notes": "arbitrary"}],
        )
    with pytest.raises(DetectionError, match="use_classification"):
        DetectionCandidate.hypothesis(
            behavior_id="collection.stage_fixture.v1",
            title="Invalid enriched baseline",
            target_language="internal",
            logsource={"category": "file_event"},
            selection={"path|contains": "staged/"},
            provenance={"source": "operator", "license": "MIT"},
            public_baselines=[{**enriched_baseline, "use_classification": "copied_unknown"}],
        )


def test_nonmatching_malicious_fixture_rejects_candidate() -> None:
    pipeline = DetectionPipeline()
    candidate = pipeline.exercise_fixtures(
        pipeline.parse(_candidate()),
        [{"fixture_id": "malicious-1", "artifact_type": "other", "path": "a.txt"}],
    )
    assert candidate.state is DetectionState.REJECTED
    assert candidate.rejection_reason


def test_external_languages_require_authoritative_validation() -> None:
    candidate = DetectionCandidate.hypothesis(
        behavior_id="endpoint.process.discovery.v1",
        title="Process discovery",
        target_language="sigma",
        logsource={"category": "process_creation"},
        selection={"Image|contains": "process-list"},
        provenance={"source": "BlueFire Nexus", "license": "MIT"},
    )
    with pytest.raises(DetectionError, match="authoritative parser"):
        DetectionPipeline().parse(candidate)


def test_pysigma_parses_a_real_rule_and_rejects_invalid_source() -> None:
    candidate = DetectionCandidate.hypothesis(
        behavior_id="endpoint.process.discovery.v1",
        title="Fixed process discovery",
        target_language="sigma",
        logsource={"category": "process_creation"},
        selection={"Image|endswith": "process-list.exe"},
        provenance={"source": "BlueFire Nexus", "license": "MIT"},
    )
    source = """
title: Fixed Process Discovery
id: 11111111-1111-4111-8111-111111111111
status: test
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: '\\process-list.exe'
  condition: selection
falsepositives:
  - Approved inventory tooling
level: low
"""
    validator = ExternalDetectionValidator()
    parsed = validator.parse_sigma(candidate, source)

    assert parsed.state is DetectionState.PARSED
    assert parsed.parser_backend["name"] == "pySigma"
    assert parsed.validation["rule_count"] == 1
    rejected = validator.parse_sigma(candidate, "title: incomplete")
    assert rejected.state is DetectionState.REJECTED


def test_yara_is_compiled_and_exercised_against_bounded_fixtures() -> None:
    candidate = DetectionCandidate.hypothesis(
        behavior_id="sandbox.fixture.create.v1",
        title="BlueFire deterministic fixture",
        target_language="yara",
        logsource={"category": "file"},
        selection={"content|contains": "bluefire_fixture_marker"},
        provenance={"source": "BlueFire Nexus", "license": "MIT"},
    )
    source = """
rule bluefire_deterministic_fixture {
  strings:
    $marker = "bluefire_fixture_marker" ascii
  condition:
    $marker
}
"""
    validator = ExternalDetectionValidator()
    parsed = validator.compile_yara(candidate, source)
    exercised = validator.exercise_yara_fixtures(
        parsed,
        [
            {"fixture_id": "malicious-1", "data": "bluefire_fixture_marker"},
            {"fixture_id": "malicious-variant", "data": "prefix bluefire_fixture_marker suffix"},
        ],
    )

    assert parsed.state is DetectionState.PARSED
    assert parsed.validation["compiled"] is True
    assert exercised.state is DetectionState.FIXTURE_EXERCISED
    assert exercised.match_count == 2


def test_spl_structural_check_does_not_claim_backend_validation() -> None:
    candidate = DetectionCandidate.hypothesis(
        behavior_id="sandbox.collection.stage.v1",
        title="Staging search",
        target_language="spl",
        logsource={"category": "file"},
        selection={"path|contains": "staged/"},
        provenance={"source": "BlueFire Nexus", "license": "MIT"},
    )
    checked = ExternalDetectionValidator().check_spl(
        candidate, 'index=lab path="staged/*" | stats count by host'
    )

    assert checked.state is DetectionState.HYPOTHESIS
    assert checked.validation["syntax_checked"] is True
    assert checked.validation["authoritative_backend_validated"] is False


def test_detection_field_drift_and_public_baseline_delta_are_explicit() -> None:
    validator = ExternalDetectionValidator()
    drift = validator.field_drift(
        ["process.executable", "process.command_line"],
        ["process.executable", "user.name"],
    )
    comparison = validator.compare_public_baseline(
        ["fixture-a", "fixture-variant"], ["fixture-a", "fixture-baseline"]
    )

    assert drift["predicted_only"] == ("process.command_line",)
    assert drift["observed_only"] == ("user.name",)
    assert comparison["candidate_only"] == ["fixture-variant"]
    assert comparison["baseline_only"] == ["fixture-baseline"]
