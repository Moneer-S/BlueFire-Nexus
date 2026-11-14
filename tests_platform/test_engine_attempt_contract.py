from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

from bluefire.engine_attempt_contract import (
    _CONTROLLER_EVIDENCE_AUTHORITY,
    AttemptCompleteness,
    AttemptRole,
    AttemptState,
    EngineAttemptBinding,
    EngineAttemptContractError,
    EngineAttemptRecord,
    EngineEvidenceItem,
    EvidenceCategory,
)
from bluefire.util import content_hash


def digest(character: str) -> str:
    return "sha256:" + character * 64


def binding_document(**overrides):
    value = {
        "schema_version": "bluefire.engine-attempt-binding.v1",
        "experiment_id": "experiment-" + "1" * 32,
        "attempt_id": "engine-attempt-" + "2" * 32,
        "run_id": "run-20261104T120000Z-" + "3" * 16,
        "role": "baseline",
        "objective_ref": digest("4"),
        "environment_ref": digest("5"),
        "target_snapshot_ref": digest("6"),
        "scope_ref": digest("7"),
        "scope_version": "owned-lab.v1",
        "engine_id": "strix",
        "engine_version": "1.7.0",
        "engine_revision": "8" * 40,
        "engine_package_digest": digest("9"),
        "policy_overlay_digest": digest("a"),
        "model_provider": "test-provider",
        "model_id": "controlled-model",
        "model_data_destination": "owned local test gateway",
        "model_authorization_ref": digest("b"),
        "wall_clock_seconds": 600,
        "action_limit": 24,
        "cost_limit_microunits": 0,
        "artifact_byte_limit": 16 * 1024 * 1024,
        "created_at": "2026-11-04T12:00:00Z",
        "parent_attempt_id": None,
    }
    value.update(overrides)
    return value


def test_binding_keeps_engine_model_scope_and_attempt_identities_immutable() -> None:
    binding = EngineAttemptBinding.from_mapping(binding_document())

    assert binding.role is AttemptRole.BASELINE
    assert binding.experiment_id != binding.attempt_id != binding.run_id
    assert binding.engine_revision == "8" * 40
    assert binding.target_snapshot_ref == digest("6")
    assert binding.to_dict() == binding_document()
    assert binding.binding_digest.startswith("sha256:")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("attempt_id", "engine-attempt-other", "attempt ID"),
        ("run_id", "run-other", "run ID"),
        ("target_snapshot_ref", digest("f")[:-1], "target snapshot"),
        ("engine_revision", "main", "engine identity"),
        ("wall_clock_seconds", 0, "wall-clock"),
        ("artifact_byte_limit", 65 * 1024 * 1024, "artifact byte"),
    ],
)
def test_binding_rejects_invalid_identity_or_budget(field, value, message) -> None:
    with pytest.raises(EngineAttemptContractError, match=message):
        EngineAttemptBinding.from_mapping(binding_document(**{field: value}))


def test_binding_direct_replace_and_serialization_cannot_bypass_validation() -> None:
    binding = EngineAttemptBinding.from_mapping(binding_document())
    direct = binding_document(action_limit=0, role=AttemptRole.BASELINE)

    with pytest.raises(EngineAttemptContractError, match="action limit"):
        EngineAttemptBinding(**direct)  # type: ignore[arg-type]
    with pytest.raises(EngineAttemptContractError, match="action limit"):
        replace(binding, action_limit=0)

    object.__setattr__(binding, "attempt_id", "engine-attempt-invalid")
    with pytest.raises(EngineAttemptContractError, match="attempt ID"):
        binding.to_dict()


def test_attempt_lifecycle_requires_distinct_upstream_session_and_real_timestamps() -> None:
    binding = EngineAttemptBinding.from_mapping(binding_document())
    queued = EngineAttemptRecord.create(binding)
    preflight = queued.transition(AttemptState.PREFLIGHT)
    running = preflight.transition(
        AttemptState.RUNNING,
        upstream_session_id="upstream-run-123",
        timestamp="2026-11-04T12:00:01Z",
    )
    completed = running.transition(
        AttemptState.COMPLETED,
        timestamp="2026-11-04T12:02:00Z",
        exit_code=0,
        completeness=AttemptCompleteness.UNKNOWN,
        exit_reason="upstream reported completion; coverage was unavailable",
        limitations=("Completion is not an independent security outcome.",),
    )

    assert completed.state is AttemptState.COMPLETED
    assert completed.upstream_session_id == "upstream-run-123"
    assert completed.completeness is AttemptCompleteness.UNKNOWN
    assert completed.to_dict()["binding_digest"] == binding.binding_digest
    assert EngineAttemptRecord.from_mapping(completed.to_dict()) == completed


def test_exit_code_never_infers_completion_or_security() -> None:
    running = (
        EngineAttemptRecord.create(EngineAttemptBinding.from_mapping(binding_document()))
        .transition(AttemptState.PREFLIGHT)
        .transition(
            AttemptState.RUNNING,
            upstream_session_id="upstream-run-456",
            timestamp="2026-11-04T12:00:01Z",
        )
    )

    partial = running.transition(
        AttemptState.PARTIAL,
        timestamp="2026-11-04T12:01:00Z",
        exit_code=0,
        completeness=AttemptCompleteness.PARTIAL,
        exit_reason="wall-clock stop",
    )
    findings = running.transition(
        AttemptState.COMPLETED,
        timestamp="2026-11-04T12:01:00Z",
        exit_code=2,
        completeness=AttemptCompleteness.COMPLETE,
        exit_reason="findings returned",
    )

    assert partial.state is AttemptState.PARTIAL
    assert findings.state is AttemptState.COMPLETED


def test_attempt_rejects_skipped_transition_or_session_change() -> None:
    queued = EngineAttemptRecord.create(EngineAttemptBinding.from_mapping(binding_document()))
    with pytest.raises(EngineAttemptContractError, match="transition"):
        queued.transition(
            AttemptState.COMPLETED,
            timestamp="2026-11-04T12:00:01Z",
            exit_code=0,
        )
    running = queued.transition(AttemptState.PREFLIGHT).transition(
        AttemptState.RUNNING,
        upstream_session_id="upstream-run-1",
        timestamp="2026-11-04T12:00:01Z",
    )
    with pytest.raises(EngineAttemptContractError, match="identity changed"):
        running.transition(
            AttemptState.STOPPING,
            upstream_session_id="upstream-run-2",
        )
    with pytest.raises(EngineAttemptContractError, match="completeness"):
        running.transition(
            AttemptState.COMPLETED,
            timestamp="2026-11-04T12:02:00Z",
            completeness="complete",  # type: ignore[arg-type]
        )

    tampered = queued.to_dict()
    tampered["upstream_session_id"] = "impossible-session"
    with pytest.raises(EngineAttemptContractError, match="inconsistent"):
        EngineAttemptRecord.from_mapping(tampered)

    terminal = running.transition(
        AttemptState.FAILED,
        timestamp="2026-11-04T12:02:00Z",
        exit_reason="controlled failure",
    ).to_dict()
    terminal["upstream_session_id"] = None
    with pytest.raises(EngineAttemptContractError, match="inconsistent"):
        EngineAttemptRecord.from_mapping(terminal)

    fabricated_completion = queued.to_dict()
    fabricated_completion.update(
        {
            "state": "completed",
            "ended_at": "2026-11-04T12:02:00Z",
            "exit_code": 0,
        }
    )
    with pytest.raises(EngineAttemptContractError, match="inconsistent"):
        EngineAttemptRecord.from_mapping(fabricated_completion)


@pytest.mark.parametrize(
    ("state", "outcome"),
    [
        (AttemptState.FAILED, {"exit_code": 1}),
        (
            AttemptState.CANCELLED,
            {"completeness": AttemptCompleteness.PARTIAL},
        ),
    ],
)
def test_prestart_terminal_record_cannot_claim_process_outcome(
    state: AttemptState, outcome: dict[str, object]
) -> None:
    queued = EngineAttemptRecord.create(EngineAttemptBinding.from_mapping(binding_document()))

    with pytest.raises(EngineAttemptContractError, match="started upstream session"):
        queued.transition(
            state,
            timestamp="2026-11-04T12:00:01Z",
            exit_reason="preflight failed before an engine session existed",
            **outcome,  # type: ignore[arg-type]
        )

    fabricated = queued.to_dict()
    fabricated.update(
        {
            "state": state.value,
            "ended_at": "2026-11-04T12:00:01Z",
            "exit_reason": "preflight failed before an engine session existed",
            **{
                name: value.value if isinstance(value, AttemptCompleteness) else value
                for name, value in outcome.items()
            },
        }
    )
    with pytest.raises(EngineAttemptContractError, match="inconsistent"):
        EngineAttemptRecord.from_mapping(fabricated)


def test_attempt_direct_replace_and_serialization_cannot_bypass_lifecycle() -> None:
    binding = EngineAttemptBinding.from_mapping(binding_document())
    queued = EngineAttemptRecord.create(binding)

    with pytest.raises(EngineAttemptContractError, match="inconsistent"):
        EngineAttemptRecord(
            schema_version="bluefire.engine-attempt.v1",
            binding=binding,
            binding_digest=binding.binding_digest,
            state=AttemptState.COMPLETED,
            upstream_session_id=None,
            started_at=None,
            ended_at=None,
            exit_code=0,
            completeness=AttemptCompleteness.COMPLETE,
            exit_reason="forged",
            limitations=(),
        )
    with pytest.raises(EngineAttemptContractError, match="inconsistent"):
        replace(
            queued,
            state=AttemptState.COMPLETED,
            exit_code=0,
            completeness=AttemptCompleteness.COMPLETE,
        )

    object.__setattr__(queued, "state", AttemptState.COMPLETED)
    object.__setattr__(queued, "exit_code", 0)
    object.__setattr__(queued, "completeness", AttemptCompleteness.COMPLETE)
    with pytest.raises(EngineAttemptContractError, match="inconsistent"):
        queued.to_dict()

    forged_binding = EngineAttemptBinding.from_mapping(binding_document())
    object.__setattr__(forged_binding, "attempt_id", "engine-attempt-invalid")
    with pytest.raises(EngineAttemptContractError, match="attempt ID"):
        EngineAttemptRecord.create(forged_binding)


def test_evidence_categories_do_not_conflate_engine_and_independent_results() -> None:
    common = {
        "attempt_id": "engine-attempt-" + "2" * 32,
        "run_id": "run-20261104T120000Z-" + "3" * 16,
        "observed_at": "2026-11-04T12:02:00Z",
        "content": {"mechanism": "object read", "outcome": "observed"},
    }
    assertion = EngineEvidenceItem.create(
        **common,
        category=EvidenceCategory.ENGINE_ASSERTION,
        producer="strix",
        source_artifact_digest=digest("c"),
        limitations=("This is an upstream assertion.",),
    )
    observed = EngineEvidenceItem.create(
        **common,
        category=EvidenceCategory.INDEPENDENT_TARGET_EFFECT,
        producer="bluefire.target-observer",
        parent_evidence_ids=(assertion.evidence_id,),
        _controller_authority=_CONTROLLER_EVIDENCE_AUTHORITY,
    )

    assert assertion.category is EvidenceCategory.ENGINE_ASSERTION
    assert observed.category is EvidenceCategory.INDEPENDENT_TARGET_EFFECT
    assert observed.parent_evidence_ids == (assertion.evidence_id,)
    assert observed.evidence_id != assertion.evidence_id
    assert (
        EngineEvidenceItem.from_mapping(
            observed.to_dict(), _controller_authority=_CONTROLLER_EVIDENCE_AUTHORITY
        )
        == observed
    )

    with pytest.raises(EngineAttemptContractError, match="controller authority"):
        EngineEvidenceItem.from_mapping(observed.to_dict())

    tampered = observed.to_dict()
    tampered["content"] = {"mechanism": "invented", "outcome": "observed"}
    with pytest.raises(EngineAttemptContractError, match="content or identity"):
        EngineEvidenceItem.from_mapping(
            tampered, _controller_authority=_CONTROLLER_EVIDENCE_AUTHORITY
        )


def test_engine_binding_roles_exclude_controller_reproducer_and_legitimate_control() -> None:
    roles = {
        EngineAttemptBinding.from_mapping(binding_document(role=role)).role
        for role in (
            "baseline",
            "adaptive_search",
        )
    }
    assert roles == set(AttemptRole)

    for controller_role in ("retained_reproducer", "legitimate_use"):
        with pytest.raises(EngineAttemptContractError, match="role"):
            EngineAttemptBinding.from_mapping(binding_document(role=controller_role))


def test_independent_evidence_requires_controller_authority_and_content_is_bounded() -> None:
    common = {
        "attempt_id": "engine-attempt-" + "2" * 32,
        "run_id": "run-20261104T120000Z-" + "3" * 16,
        "category": EvidenceCategory.INDEPENDENT_SECURITY_OUTCOME,
        "producer": "bluefire.target-observer",
        "observed_at": "2026-11-04T12:02:00Z",
    }
    with pytest.raises(EngineAttemptContractError, match="controller authority"):
        EngineEvidenceItem.create(**common, content={"outcome": "blocked"})

    with pytest.raises(EngineAttemptContractError, match="byte bound"):
        EngineEvidenceItem.create(
            **common,
            content={f"detail-{index}": "x" * 4096 for index in range(16)},
            _controller_authority=_CONTROLLER_EVIDENCE_AUTHORITY,
        )

    deeply_nested: object = "leaf"
    for _index in range(14):
        deeply_nested = {"next": deeply_nested}
    with pytest.raises(EngineAttemptContractError, match="complex"):
        EngineEvidenceItem.create(
            **common,
            content={"root": deeply_nested},
            _controller_authority=_CONTROLLER_EVIDENCE_AUTHORITY,
        )


def test_direct_evidence_constructor_cannot_bypass_controller_authority() -> None:
    with pytest.raises(TypeError):
        EngineEvidenceItem(  # type: ignore[call-arg]
            schema_version="bluefire.engine-evidence.v1",
            evidence_id="engine-evidence-" + "1" * 24,
            attempt_id="engine-attempt-" + "2" * 32,
            run_id="run-20261104T120000Z-" + "3" * 16,
            category=EvidenceCategory.INDEPENDENT_SECURITY_OUTCOME,
            producer="untrusted-engine",
            observed_at="2026-11-04T12:02:00Z",
            content={"outcome": "invented"},
            content_digest=digest("d"),
            source_artifact_digest=None,
            parent_evidence_ids=(),
            limitations=(),
        )


def test_evidence_serialization_rejects_mutation_after_admission_or_rehydration() -> None:
    common = {
        "attempt_id": "engine-attempt-" + "2" * 32,
        "run_id": "run-20261104T120000Z-" + "3" * 16,
        "category": EvidenceCategory.ENGINE_ASSERTION,
        "producer": "strix",
        "observed_at": "2026-11-04T12:02:00Z",
        "source_artifact_digest": digest("c"),
    }
    top_level = EngineEvidenceItem.create(
        **common,
        content={"outcome": "reported"},
    )
    cast(dict[str, Any], top_level.content)["outcome"] = "changed"
    with pytest.raises(EngineAttemptContractError, match="changed after admission"):
        top_level.to_dict()

    original = EngineEvidenceItem.create(
        **common,
        content={"details": {"outcome": "reported"}},
    )
    rehydrated = EngineEvidenceItem.from_mapping(original.to_dict())
    details = cast(dict[str, Any], rehydrated.content)["details"]
    cast(dict[str, Any], details)["outcome"] = "changed"
    with pytest.raises(EngineAttemptContractError, match="changed after admission"):
        rehydrated.to_dict()


def test_private_evidence_admission_still_fails_canonical_serialization_when_invalid() -> None:
    content = {"outcome": "reported"}
    content_digest = content_hash(content)
    identity = {
        "attempt_id": "invalid-attempt",
        "run_id": "run-20261104T120000Z-" + "3" * 16,
        "category": EvidenceCategory.ENGINE_ASSERTION.value,
        "producer": "strix",
        "observed_at": "2026-11-04T12:02:00Z",
        "content_digest": content_digest,
        "source_artifact_digest": digest("c"),
        "parent_evidence_ids": (),
        "limitations": (),
    }
    forged = EngineEvidenceItem._admit(
        evidence_id="engine-evidence-" + content_hash(identity).removeprefix("sha256:")[:24],
        attempt_id="invalid-attempt",
        run_id="run-20261104T120000Z-" + "3" * 16,
        category=EvidenceCategory.ENGINE_ASSERTION,
        producer="strix",
        observed_at="2026-11-04T12:02:00Z",
        content=content,
        content_digest=content_digest,
        source_artifact_digest=digest("c"),
        parent_evidence_ids=(),
        limitations=(),
        controller_attestation=None,
    )

    with pytest.raises(EngineAttemptContractError, match="identity"):
        forged.to_dict()
