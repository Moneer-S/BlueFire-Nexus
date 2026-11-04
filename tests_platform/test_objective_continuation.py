from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace

import pytest

from bluefire.contracts import StepOutcome
from bluefire.evidence import EvidenceProvenance
from bluefire.objective_continuation import (
    FACTS_SCHEMA,
    HISTORY_SCHEMA,
    MAX_DOCUMENT_BYTES,
    PROPOSAL_SCHEMA,
    ActualAttempt,
    ActualOperation,
    ConditionBinding,
    ContinuationProposal,
    CurrentFact,
    CurrentFacts,
    FactRequirement,
    FactState,
    ImportedResult,
    ObjectiveContinuationError,
    ObjectiveHistory,
    PrerequisiteAction,
    PrerequisiteKind,
    ProposedOperation,
    ReconsideredDecision,
    RepeatBasis,
    RepeatJustification,
    ResourceBinding,
    ResultReference,
    assess_continuation,
)
from bluefire.tenant_record_lab import (
    baseline_defense_config,
    generate_tenant_record_fixture,
    hardened_defense_config,
)
from bluefire.util import canonical_json_bytes, content_hash


def digest(value: str) -> str:
    return content_hash(value)


@pytest.fixture
def case():
    """Recorded mechanics only: no application, engine, process or model runs."""
    fixture = generate_tenant_record_fixture(b"objective-continuation-fixture-01")
    baseline = baseline_defense_config(fixture)
    conditions = (
        ConditionBinding("fixture_generation", digest(fixture.resource_generation)),
        ConditionBinding("service_generation", digest(baseline.service_generation)),
    )
    objective, environment = digest("tenant-read-objective"), digest("owned-tenant-lab")
    results = []

    def result(attempt: str, branch: str, step: str, method: str, output: str):
        row = ResultReference(
            attempt,
            branch,
            "run-" + attempt,
            digest("plan-" + attempt),
            step,
            method,
            output,
            objective,
            environment,
            fixture.digest,
            fixture.fixture_id,
            digest(fixture.resource_generation),
            "finding.tenant-record.v1",
            EvidenceProvenance.OBSERVED,
            digest("evidence-" + output),
            digest("content-" + output),
        )
        results.append(row)
        return row

    locator = result("attempt-a", "export-branch", "discover", "tenant.discover.v1", "locator")
    export = result("attempt-a", "export-branch", "export", "tenant.bounded-export.v1", "refusal")
    metadata = result(
        "attempt-b", "metadata-branch", "inspect", "tenant.metadata.v1", "record-route"
    )

    def operation(identity, method, ordinal, outputs=(), outcome=StepOutcome.SUCCESS):
        return ActualOperation(
            identity,
            identity,
            method,
            ordinal,
            "Bounded export is the viable route" if ordinal == 0 else "Inspect this bounded route",
            digest("parameters"),
            (),
            conditions,
            (ResourceBinding(fixture.fixture_id, digest(fixture.resource_generation)),),
            outcome,
            False,
            digest("record-" + identity),
            outputs,
        )

    choose = operation("choose", "tenant.choose-route.v1", 0)
    discover = operation("discover", "tenant.discover.v1", 1, (locator,))
    blocked = operation("export", "tenant.bounded-export.v1", 2, (export,), StepOutcome.BLOCKED)
    inspect = operation("inspect", "tenant.metadata.v1", 3, (metadata,), StepOutcome.PARTIAL)
    history = ObjectiveHistory(
        HISTORY_SCHEMA,
        objective,
        environment,
        (
            ActualAttempt(
                "attempt-a",
                "export-branch",
                "run-attempt-a",
                digest("plan-attempt-a"),
                digest("attempt-record-a"),
                (choose, discover, blocked),
            ),
            ActualAttempt(
                "attempt-b",
                "metadata-branch",
                "run-attempt-b",
                digest("plan-attempt-b"),
                digest("attempt-record-b"),
                (inspect,),
            ),
        ),
    )
    current = CurrentFacts(
        FACTS_SCHEMA,
        objective,
        environment,
        fixture.digest,
        1000,
        digest("assessment"),
        conditions,
        (
            CurrentFact(
                "locator-current",
                locator.digest,
                "fixture_identity",
                locator.digest,
                FactState.ESTABLISHED,
                800,
                None,
                conditions,
                "Fixture identity independently observed",
            ),
            CurrentFact(
                "export-access",
                export.digest,
                "access",
                export.digest,
                FactState.ESTABLISHED,
                850,
                2000,
                conditions,
                "Bounded export refusal independently observed",
            ),
        ),
    )
    imported = ImportedResult(
        locator,
        locator.semantic_type,
        (FactRequirement("locator-current", "fixture_identity", ("fixture_generation",), None),),
    )
    proposal = ContinuationProposal(
        PROPOSAL_SCHEMA,
        objective,
        environment,
        fixture.digest,
        "attempt-b",
        "attempt-c",
        "record-branch",
        digest("new-record-lookup-plan"),
        ReconsideredDecision(
            "attempt-a",
            "choose",
            choose.assumption,
            "Use discovered record locator on the independent lookup route",
            (export.digest, metadata.digest),
        ),
        (),
        (
            ProposedOperation(
                "lookup-new",
                "tenant.record-lookup.v1",
                digest("lookup-parameters"),
                (imported,),
                conditions,
                (),
                None,
            ),
        ),
    )
    return history, current, proposal, fixture, baseline


def assess(history, current, proposal, *, now=1000):
    return assess_continuation(
        proposal,
        history,
        current,
        expected_history_digest=history.digest,
        expected_current_facts_digest=current.digest,
        now_ms=now,
    )


def with_import(proposal, imported):
    return replace(proposal, operations=(replace(proposal.operations[0], imports=(imported,)),))


def access_import(history):
    result = history.attempts[0].operations[-1].results[0]
    return ImportedResult(
        result,
        result.semantic_type,
        (
            FactRequirement(
                "export-access", "access", ("fixture_generation", "service_generation"), 500
            ),
        ),
    )


def test_nonlocal_tenant_bounded_export_backtracks_without_repeating_effects(case):
    history, current, proposal, _, _ = case
    before = canonical_json_bytes(history.to_dict())
    assessment = assess(history, current, proposal)
    assert assessment.inputs_current
    assert proposal.frontier_attempt_id == "attempt-b"
    assert proposal.reconsideration.attempt_id == "attempt-a"
    assert proposal.operations[0].imports[0].source.branch_id == "export-branch"
    assert proposal.operations[0].method_id == "tenant.record-lookup.v1"
    assert canonical_json_bytes(history.to_dict()) == before
    assert assessment.proposal_digest == proposal.digest
    assert not hasattr(assessment, "authorization")


def test_signed_session_change_invalidates_only_required_service_facts(case):
    history, current, proposal, fixture, baseline = case
    hardened = hardened_defense_config(
        fixture,
        signing_key=b"continuation-test-signing-key-00001",
        key_id="key-continuation",
        application_nonce="apply-continuation-0001",
        prior=baseline,
    )
    assert hardened.fixture_digest == baseline.fixture_digest
    changed_conditions = (
        current.conditions[0],
        ConditionBinding("service_generation", digest(hardened.service_generation)),
    )
    changed = replace(current, conditions=changed_conditions)
    proposal = replace(
        proposal, operations=(replace(proposal.operations[0], conditions=changed_conditions),)
    )
    assert assess(history, changed, proposal).inputs_current
    both = replace(
        proposal.operations[0], imports=proposal.operations[0].imports + (access_import(history),)
    )
    assessment = assess(history, changed, replace(proposal, operations=(both,)))
    assert assessment.unmet_fact_ids == ("export-access",)
    assert history.attempts[0].operations[-1].results[0].digest == current.facts[1].subject_ref
    assert current.facts[0] == changed.facts[0]


@pytest.mark.parametrize("state", [FactState.STALE, FactState.UNCERTAIN])
def test_stale_or_uncertain_fact_cannot_supply_current_prerequisite(case, state):
    history, current, proposal, _, _ = case
    changed = replace(current, facts=(replace(current.facts[0], state=state), current.facts[1]))
    assert assess(history, changed, proposal).unmet_fact_ids == ("locator-current",)


def test_selective_age_expiry_and_exact_boundaries(case):
    history, current, proposal, _, _ = case
    proposal = with_import(proposal, access_import(history))
    assert assess(history, current, proposal, now=1350).inputs_current
    assert assess(history, current, proposal, now=1351).unmet_fact_ids == ("export-access",)
    imported = replace(
        proposal.operations[0].imports[0],
        requirements=(FactRequirement("export-access", "access", (), None),),
    )
    proposal = with_import(proposal, imported)
    assert assess(history, current, proposal, now=1999).inputs_current
    assert assess(history, current, proposal, now=2000).unmet_fact_ids == ("export-access",)


@pytest.mark.parametrize(
    "kind", [PrerequisiteKind.OBSERVE, PrerequisiteKind.RESTORE, PrerequisiteKind.RECREATE]
)
def test_explicit_prerequisite_never_establishes_state_or_synthesizes_output(case, kind):
    history, current, proposal, _, _ = case
    source = proposal.operations[0].imports[0].source
    current = replace(
        current, facts=(replace(current.facts[0], state=FactState.STALE), current.facts[1])
    )
    requested = (
        source.resource_generation_ref
        if kind is PrerequisiteKind.RESTORE
        else digest("recreated-generation")
        if kind is PrerequisiteKind.RECREATE
        else None
    )
    action = PrerequisiteAction(
        "refresh-locator",
        "attempt-prerequisite",
        kind,
        "tenant.reviewed-prerequisite.v1",
        source.digest,
        source.resource_id,
        source.resource_generation_ref,
        requested,
        ("locator-current",),
        "Explicit prerequisite must be separately reviewed and observed",
        digest("prerequisite-parameters"),
        current.conditions,
        None,
    )
    operation = replace(proposal.operations[0], prerequisite_action_ids=(action.action_id,))
    proposal = replace(proposal, prerequisites=(action,), operations=(operation,))
    result = assess(history, current, proposal)
    assert result.unmet_fact_ids == ("locator-current",)
    assert result.pending_prerequisite_action_ids == ("refresh-locator",)
    assert not result.inputs_current
    assert len(history.attempts) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("attempt_id", "another-attempt"),
        ("branch_id", "another-branch"),
        ("run_id", "another-run"),
        ("plan_digest", digest("other-plan")),
        ("producer_step_id", "another-step"),
        ("producer_method_id", "another-method"),
        ("output_name", "optional-missing-output"),
        ("objective_ref", digest("another-objective")),
        ("environment_ref", digest("another-environment")),
        ("fixture_ref", digest("another-fixture")),
        ("resource_id", "another-resource"),
        ("resource_generation_ref", digest("another-generation")),
        ("semantic_type", "finding.other.v1"),
        ("provenance", EvidenceProvenance.EXECUTED),
        ("evidence_ref", digest("another-evidence")),
        ("content_digest", digest("another-content")),
    ],
)
def test_import_requires_every_exact_original_binding(case, field, value):
    history, current, proposal, _, _ = case
    imported = proposal.operations[0].imports[0]
    candidate = with_import(
        proposal, replace(imported, source=replace(imported.source, **{field: value}))
    )
    with pytest.raises(ObjectiveContinuationError, match="exact actual emitted"):
        assess(history, current, candidate)


def test_semantic_type_current_fact_subject_and_trust_roots_are_checked(case):
    history, current, proposal, _, _ = case
    with pytest.raises(ObjectiveContinuationError, match="semantic type"):
        assess(
            history,
            current,
            with_import(
                proposal,
                replace(
                    proposal.operations[0].imports[0], expected_semantic_type="artifact.other.v1"
                ),
            ),
        )
    bad = replace(
        current,
        facts=(
            replace(
                current.facts[0],
                subject_ref=current.facts[1].subject_ref,
                observation_result_ref=current.facts[1].subject_ref,
            ),
            current.facts[1],
        ),
    )
    with pytest.raises(ObjectiveContinuationError, match="exact dependency"):
        assess(history, bad, proposal)
    with pytest.raises(ObjectiveContinuationError, match="trusted binding"):
        assess_continuation(
            proposal,
            history,
            current,
            expected_history_digest=digest("model-claimed-history"),
            expected_current_facts_digest=current.digest,
            now_ms=1000,
        )
    with pytest.raises(ObjectiveContinuationError, match="trusted binding"):
        assess_continuation(
            proposal,
            history,
            current,
            expected_history_digest=history.digest,
            expected_current_facts_digest=digest("model-claimed-facts"),
            now_ms=1000,
        )


def test_attempt_frontier_and_reconsideration_are_bound_to_actual_history(case):
    history, current, proposal, _, _ = case
    for candidate in (
        replace(proposal, new_attempt_id="attempt-a"),
        replace(proposal, frontier_attempt_id="attempt-a"),
    ):
        with pytest.raises(ObjectiveContinuationError):
            assess(history, current, candidate)
    for reconsideration in (
        replace(proposal.reconsideration, original_assumption="Invented past assumption"),
        replace(proposal.reconsideration, attempt_id="attempt-b"),
        replace(
            proposal.reconsideration,
            operation_id="inspect",
            attempt_id="attempt-b",
            original_assumption=history.attempts[1].operations[0].assumption,
            learned_result_refs=(history.attempts[0].operations[1].results[0].digest,),
        ),
    ):
        with pytest.raises(ObjectiveContinuationError):
            assess(history, current, replace(proposal, reconsideration=reconsideration))


def repeat_proposal(history, proposal, basis, **kwargs):
    baseline = history.attempts[0].operations[-1]
    repeat = RepeatJustification(
        baseline.digest,
        basis,
        "Repeat for an explicit bounded purpose",
        kwargs.get("evidence", ()),
        kwargs.get("purpose"),
    )
    operation = ProposedOperation(
        "export-repeat-new",
        baseline.method_id,
        kwargs.get("parameters_digest", baseline.parameters_digest),
        (),
        kwargs.get("conditions", baseline.conditions),
        (),
        repeat,
    )
    return replace(proposal, operations=(operation,))


@pytest.mark.parametrize("basis", [RepeatBasis.CHANGED_INPUTS, RepeatBasis.CHANGED_PREREQUISITES])
def test_unchanged_wasteful_repetition_is_rejected(case, basis):
    history, current, proposal, _, _ = case
    with pytest.raises(ObjectiveContinuationError, match="have not changed"):
        assess(history, current, repeat_proposal(history, proposal, basis))


def test_repeats_permit_changed_inputs_prerequisites_new_evidence_or_fresh_test(case):
    history, current, proposal, _, _ = case
    changed_inputs = repeat_proposal(
        history,
        proposal,
        RepeatBasis.CHANGED_INPUTS,
        parameters_digest=digest("bounded-new-selector"),
    )
    assert assess(history, current, changed_inputs).inputs_current
    changed_conditions = (
        current.conditions[0],
        ConditionBinding("service_generation", digest("fresh-service")),
    )
    changed = replace(current, conditions=changed_conditions)
    changed_prerequisite = repeat_proposal(
        history, proposal, RepeatBasis.CHANGED_PREREQUISITES, conditions=changed_conditions
    )
    assert assess(history, changed, changed_prerequisite).inputs_current
    later = history.attempts[1].operations[0].results[0].digest
    assert assess(
        history,
        current,
        repeat_proposal(history, proposal, RepeatBasis.NEW_EVIDENCE, evidence=(later,)),
    ).inputs_current
    assert assess(
        history,
        current,
        repeat_proposal(
            history,
            proposal,
            RepeatBasis.FRESH_TEST,
            purpose="Measure whether the bounded refusal is stable on a fresh independent request",
        ),
    ).inputs_current


def test_repeat_cannot_drop_conditions_or_cite_older_information(case):
    history, current, proposal, _, _ = case
    old = history.attempts[0].operations[1].results[0].digest
    with pytest.raises(ObjectiveContinuationError, match="meaningful later evidence"):
        assess(
            history,
            current,
            repeat_proposal(history, proposal, RepeatBasis.NEW_EVIDENCE, evidence=(old,)),
        )
    with pytest.raises(ObjectiveContinuationError, match="condition dimensions"):
        assess(
            history,
            current,
            repeat_proposal(
                history,
                proposal,
                RepeatBasis.CHANGED_PREREQUISITES,
                conditions=(current.conditions[0],),
            ),
        )


def test_unknown_effects_block_until_independent_current_reconciliation(case):
    history, current, proposal, _, _ = case
    original = history.attempts[0]
    uncertain = replace(original.operations[-1], effects_uncertain=True)
    history = replace(
        history,
        attempts=(
            replace(original, operations=original.operations[:-1] + (uncertain,)),
            history.attempts[1],
        ),
    )
    result = assess(history, current, proposal)
    assert result.unreconciled_operation_refs == (uncertain.digest,)
    assert not result.inputs_current
    observation = history.attempts[1].operations[0].results[0].digest
    fact = CurrentFact(
        "effect-reconciliation",
        uncertain.digest,
        "effects_reconciled",
        observation,
        FactState.ESTABLISHED,
        950,
        None,
        current.conditions,
        "Independent observation reconciled uncertain effects",
    )
    reconciled = replace(current, facts=current.facts + (fact,))
    assert assess(history, reconciled, proposal).inputs_current


def test_duplicate_proposed_work_cannot_repeat_one_historical_justification(case):
    history, current, proposal, _, _ = case
    proposal = repeat_proposal(
        history, proposal, RepeatBasis.FRESH_TEST, purpose="Independent bounded repeat test"
    )
    first = proposal.operations[0]
    duplicate = replace(first, operation_id="another-repeat-id")
    with pytest.raises(ObjectiveContinuationError, match="duplicate proposed work"):
        assess(history, current, replace(proposal, operations=(first, duplicate)))


def test_conflicting_current_assessments_cannot_be_cherry_picked(case):
    _, current, _, _, _ = case
    conflict = replace(current.facts[0], fact_id="locator-conflicting", state=FactState.STALE)
    with pytest.raises(ObjectiveContinuationError, match="ambiguous current"):
        replace(current, facts=current.facts + (conflict,))


def test_observation_cannot_predate_result_or_reconcile_its_own_operation(case):
    history, current, proposal, _, _ = case
    older = history.attempts[0].operations[1].results[0].digest
    wrong = replace(current.facts[1], observation_result_ref=older)
    with pytest.raises(ObjectiveContinuationError, match="predates its subject"):
        assess(history, replace(current, facts=(current.facts[0], wrong)), proposal)
    actual = history.attempts[0].operations[-1]
    self_observation = CurrentFact(
        "self-reconciliation",
        actual.digest,
        "effects_reconciled",
        actual.results[0].digest,
        FactState.ESTABLISHED,
        900,
        None,
        current.conditions,
        "Same-operation output cannot reconcile later uncertainty",
    )
    with pytest.raises(ObjectiveContinuationError, match="must follow"):
        assess(history, replace(current, facts=current.facts + (self_observation,)), proposal)


def test_pending_prerequisites_bind_resource_generation_and_exact_consumer(case):
    history, current, proposal, _, _ = case
    source = proposal.operations[0].imports[0].source
    action = PrerequisiteAction(
        "observe-locator",
        "attempt-prerequisite",
        PrerequisiteKind.OBSERVE,
        "tenant.observe.v1",
        source.digest,
        source.resource_id,
        source.resource_generation_ref,
        None,
        ("locator-current",),
        "Review a specific pending observation",
        digest("observation-parameters"),
        current.conditions,
        None,
    )
    operation = replace(proposal.operations[0], prerequisite_action_ids=(action.action_id,))
    valid = replace(proposal, prerequisites=(action,), operations=(operation,))
    assert not assess(history, current, valid).inputs_current
    duplicate_effect = replace(
        action, method_id=operation.method_id, parameters_digest=operation.parameters_digest
    )
    with pytest.raises(ObjectiveContinuationError, match="across operations and prerequisites"):
        assess(history, current, replace(valid, prerequisites=(duplicate_effect,)))
    duplicate = replace(
        action, action_id="duplicate-observation", attempt_id="attempt-other-prerequisite"
    )
    duplicate_operation = replace(
        operation, prerequisite_action_ids=(action.action_id, duplicate.action_id)
    )
    with pytest.raises(ObjectiveContinuationError, match="duplicate prerequisite work"):
        assess(
            history,
            current,
            replace(valid, prerequisites=(action, duplicate), operations=(duplicate_operation,)),
        )
    prior_method = replace(action, method_id="tenant.discover.v1")
    with pytest.raises(ObjectiveContinuationError, match="latest actual condition baseline"):
        assess(history, current, replace(valid, prerequisites=(prior_method,)))
    for changes in (
        {"resource_id": "unrelated-resource"},
        {"source_generation_ref": digest("unrelated-generation")},
    ):
        with pytest.raises(ObjectiveContinuationError, match="resource or source generation"):
            assess(history, current, replace(valid, prerequisites=(replace(action, **changes),)))
    unrelated_consumer = replace(
        operation, operation_id="unrelated-operation", method_id="tenant.other.v1", imports=()
    )
    with pytest.raises(ObjectiveContinuationError, match="consuming operation"):
        assess(history, current, replace(valid, operations=(operation, unrelated_consumer)))
    with pytest.raises(ObjectiveContinuationError, match="actual operation identity"):
        old_action = replace(action, action_id="discover")
        assess(
            history,
            current,
            replace(
                proposal,
                prerequisites=(old_action,),
                operations=(replace(operation, prerequisite_action_ids=(old_action.action_id,)),),
            ),
        )


def test_assessment_serialization_is_closed_and_versioned(case):
    history, current, proposal, _, _ = case
    assessment = assess(history, current, proposal)
    for changes in (
        {"schema_version": "unknown"},
        {"proposal_digest": "not-a-digest"},
        {"unmet_fact_ids": ("fact", "fact")},
        {"unreconciled_operation_refs": ("not-a-digest",)},
    ):
        with pytest.raises(ObjectiveContinuationError):
            replace(assessment, **changes)


def test_frozen_records_round_trip_and_detach_wire_values(case):
    history, current, proposal, _, _ = case
    for row in (history, current, proposal, assess(history, current, proposal)):
        assert type(row).from_mapping(row.to_dict()) == row
        assert type(row).from_json(canonical_json_bytes(row.to_dict())) == row
        with pytest.raises(FrozenInstanceError):
            row.schema_version = "modified"
    wire = proposal.to_dict()
    wire["operations"][0]["imports"][0]["source"]["output_name"] = "tampered"
    assert proposal.operations[0].imports[0].source.output_name == "locator"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda row: row.update(schema_version="bluefire.objective-continuation.v99"),
        lambda row: row.update(unreviewed_authority=True),
        lambda row: row.update(prerequisites=None),
        lambda row: row["reconsideration"].update(learned_result_refs=[]),
        lambda row: row["operations"][0].update(repeat={}),
        lambda row: row["operations"][0]["imports"][0]["requirements"][0].update(max_age_ms=True),
    ],
)
def test_strict_closed_serialization_rejects_malformed_proposals(case, mutation):
    _, _, proposal, _, _ = case
    row = proposal.to_dict()
    mutation(row)
    with pytest.raises(ObjectiveContinuationError):
        ContinuationProposal.from_mapping(row)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema_version":"one","schema_version":"two"}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b"\xff",
        b"[" * 2000 + b"]" * 2000,
        b" " * (MAX_DOCUMENT_BYTES + 1),
    ],
    ids=["duplicate", "nan", "infinity", "encoding", "depth", "size"],
)
def test_strict_json_rejects_duplicate_keys_nonfinite_encoding_depth_and_size(payload):
    with pytest.raises(ObjectiveContinuationError):
        ContinuationProposal.from_json(payload)


def test_construction_rejects_mutable_arrays_coerced_scalars_and_forged_history(case):
    history, current, proposal, _, _ = case
    with pytest.raises(ObjectiveContinuationError):
        replace(history, attempts=list(history.attempts))
    with pytest.raises(ObjectiveContinuationError):
        replace(current, assessed_at_ms=True)
    with pytest.raises(ObjectiveContinuationError):
        replace(current.facts[0], state="established")
    with pytest.raises(ObjectiveContinuationError):
        replace(history, attempts=(history.attempts[0], history.attempts[0]))
    with pytest.raises(ObjectiveContinuationError):
        replace(history.attempts[0].operations[0], outcome="reserved")
    with pytest.raises(ObjectiveContinuationError):
        replace(proposal, branch_id="bad\nbranch")
    assert json.loads(canonical_json_bytes(proposal.to_dict())) == proposal.to_dict()
