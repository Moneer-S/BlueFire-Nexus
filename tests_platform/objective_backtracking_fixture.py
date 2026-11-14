"""Deterministic contract fixture for a nonlocal objective continuation.

These are illustrative saved records, not a model, native run, or independent
verification of their claimed observations. The fixture keeps recorded effects,
controller assessed current facts, and unexecuted proposals separate.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from bluefire.contracts import StepOutcome
from bluefire.evidence import EvidenceProvenance
from bluefire.objective_continuation import (
    FACTS_SCHEMA,
    HISTORY_SCHEMA,
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
    ObjectiveHistory,
    PrerequisiteAction,
    PrerequisiteKind,
    ProposedOperation,
    ReconsideredDecision,
    ResourceBinding,
    ResultReference,
)
from bluefire.util import content_hash


@dataclass(frozen=True)
class BacktrackingFixture:
    history: ObjectiveHistory
    current: CurrentFacts
    proposal: ContinuationProposal
    refreshed_history: ObjectiveHistory
    refreshed_current: CurrentFacts
    refreshed_proposal: ContinuationProposal
    completed_history: ObjectiveHistory


def build_backtracking_fixture() -> BacktrackingFixture:
    """Build failed route, selective refresh, and recorded alternative effect."""
    h = content_hash
    objective, environment, fixture = h("receiver-objective"), h("owned-lab"), h("fixture-v1")
    fixture_generation = ConditionBinding("fixture_generation", h("fixture-generation-v1"))
    defense_generation = ConditionBinding("defense_generation", h("defense-generation-v1"))
    conditions = (fixture_generation, defense_generation)
    bundle_resource = ResourceBinding("retained-bundle", h("retained-bundle-generation"))
    session_resource = ResourceBinding("receiver-session", h("receiver-session-generation"))
    finding_resource = ResourceBinding("diagnostic-record", h("diagnostic-generation"))

    def result(
        attempt: str,
        branch: str,
        step: str,
        method: str,
        output: str,
        resource: ResourceBinding,
        semantic_type: str,
        provenance: EvidenceProvenance = EvidenceProvenance.OBSERVED,
    ) -> ResultReference:
        return ResultReference(
            attempt_id=attempt,
            branch_id=branch,
            run_id="run-" + attempt,
            plan_digest=h("plan-" + attempt),
            producer_step_id=step,
            producer_method_id=method,
            output_name=output,
            objective_ref=objective,
            environment_ref=environment,
            fixture_ref=fixture,
            resource_id=resource.resource_id,
            resource_generation_ref=resource.generation_ref,
            semantic_type=semantic_type,
            provenance=provenance,
            evidence_ref=h("evidence-" + attempt + "-" + output),
            content_digest=h("content-" + attempt + "-" + output),
        )

    def operation(
        step: str,
        method: str,
        ordinal: int,
        assumption: str,
        inputs: tuple[str, ...] = (),
        outputs: tuple[ResultReference, ...] = (),
        outcome: StepOutcome = StepOutcome.SUCCESS,
    ) -> ActualOperation:
        resources = tuple(
            sorted(
                {
                    ResourceBinding(item.resource_id, item.resource_generation_ref)
                    for item in outputs
                },
                key=lambda item: item.resource_id,
            )
        )
        return ActualOperation(
            operation_id=step,
            step_id=step,
            method_id=method,
            ordinal=ordinal,
            assumption=assumption,
            parameters_digest=h("parameters-" + step),
            input_result_refs=inputs,
            conditions=conditions,
            resources=resources,
            outcome=outcome,
            effects_uncertain=False,
            record_ref=h("record-" + step),
            results=outputs,
        )

    bundle = result(
        "attempt-direct",
        "branch-direct",
        "generate",
        "fixture.generate.v1",
        "bundle",
        bundle_resource,
        "artifact.retained-jsonl.v1",
    )
    session = result(
        "attempt-direct",
        "branch-direct",
        "bind-session",
        "receiver.bind.v1",
        "session",
        session_resource,
        "binding.receiver-session.v1",
    )
    refusal = result(
        "attempt-direct",
        "branch-direct",
        "submit-direct",
        "receiver.direct.v1",
        "refusal",
        session_resource,
        "finding.receiver-refusal.v1",
    )
    alternative = result(
        "attempt-diagnose",
        "branch-diagnose",
        "inspect-refusal",
        "receiver.inspect.v1",
        "alternative-route",
        finding_resource,
        "finding.alternative-route.v1",
    )
    choice = operation(
        "choose-direct",
        "receiver.choose-route.v1",
        0,
        "The direct receiver route accepts generated records without transformation.",
    )
    direct = ActualAttempt(
        "attempt-direct",
        "branch-direct",
        "run-attempt-direct",
        h("plan-attempt-direct"),
        h("attempt-record-direct"),
        (
            choice,
            operation(
                "generate",
                "fixture.generate.v1",
                1,
                "Generate bounded records once.",
                outputs=(bundle,),
            ),
            operation(
                "bind-session",
                "receiver.bind.v1",
                2,
                "Bind the receiver session.",
                outputs=(session,),
            ),
            operation(
                "submit-direct",
                "receiver.direct.v1",
                3,
                "Submit the generated records directly.",
                inputs=(bundle.digest, session.digest),
                outputs=(refusal,),
                outcome=StepOutcome.BLOCKED,
            ),
        ),
    )
    diagnose = ActualAttempt(
        "attempt-diagnose",
        "branch-diagnose",
        "run-attempt-diagnose",
        h("plan-attempt-diagnose"),
        h("attempt-record-diagnose"),
        (
            operation(
                "inspect-refusal",
                "receiver.inspect.v1",
                4,
                "Inspect the direct-route refusal for another reviewed route.",
                inputs=(refusal.digest,),
                outputs=(alternative,),
                outcome=StepOutcome.PARTIAL,
            ),
        ),
    )
    history = ObjectiveHistory(HISTORY_SCHEMA, objective, environment, (direct, diagnose))

    bundle_fact = CurrentFact(
        "bundle-current",
        bundle.digest,
        "retained_bytes_verified",
        bundle.digest,
        FactState.ESTABLISHED,
        800,
        None,
        conditions,
        "Controller verified the exact retained immutable payload.",
    )
    alternative_fact = CurrentFact(
        "alternative-current",
        alternative.digest,
        "route_contract_verified",
        alternative.digest,
        FactState.ESTABLISHED,
        850,
        None,
        conditions,
        "Controller verified the exact reviewed alternate route finding.",
    )
    session_fact = CurrentFact(
        "session-current",
        session.digest,
        "receiver_session_current",
        session.digest,
        FactState.STALE,
        850,
        950,
        conditions,
        "The earlier session observation expired before the continuation.",
    )
    current = CurrentFacts(
        FACTS_SCHEMA,
        objective,
        environment,
        fixture,
        1000,
        h("assessment-before-refresh"),
        conditions,
        (bundle_fact, alternative_fact, session_fact),
    )
    imports = (
        ImportedResult(
            bundle,
            bundle.semantic_type,
            (
                FactRequirement(
                    "bundle-current", "retained_bytes_verified", ("fixture_generation",), None
                ),
            ),
        ),
        ImportedResult(
            alternative,
            alternative.semantic_type,
            (
                FactRequirement(
                    "alternative-current", "route_contract_verified", ("fixture_generation",), None
                ),
            ),
        ),
        ImportedResult(
            session,
            session.semantic_type,
            (
                FactRequirement(
                    "session-current", "receiver_session_current", ("defense_generation",), 200
                ),
            ),
        ),
    )
    reconsideration = ReconsideredDecision(
        "attempt-direct",
        "choose-direct",
        choice.assumption,
        "Use the post-refusal alternate route with the retained bundle and a fresh receiver session.",
        (refusal.digest, alternative.digest),
    )
    refresh_action = PrerequisiteAction(
        "observe-session",
        "attempt-refresh",
        PrerequisiteKind.OBSERVE,
        "receiver.observe-session.v1",
        session.digest,
        session_resource.resource_id,
        session_resource.generation_ref,
        None,
        ("session-current",),
        "Recheck only the expired mutable receiver session.",
        h("parameters-observe-session"),
        conditions,
        None,
    )
    proposed_operation = ProposedOperation(
        "submit-alternate",
        "receiver.transform-and-submit.v1",
        h("parameters-submit-alternate"),
        imports,
        conditions,
        (refresh_action.action_id,),
        None,
    )
    proposal = ContinuationProposal(
        PROPOSAL_SCHEMA,
        objective,
        environment,
        fixture,
        "attempt-diagnose",
        "attempt-alternate-draft",
        "branch-alternate",
        h("plan-alternate-draft"),
        reconsideration,
        (refresh_action,),
        (proposed_operation,),
    )

    session_check = result(
        "attempt-refresh",
        "branch-refresh",
        "observe-session",
        "receiver.observe-session.v1",
        "session-check",
        session_resource,
        "observation.receiver-session.v1",
    )
    refresh = ActualAttempt(
        "attempt-refresh",
        "branch-refresh",
        "run-attempt-refresh",
        h("plan-attempt-refresh"),
        h("attempt-record-refresh"),
        (
            operation(
                "observe-session",
                "receiver.observe-session.v1",
                5,
                "Reobserve the receiver session before the alternate submission.",
                inputs=(session.digest,),
                outputs=(session_check,),
            ),
        ),
    )
    refreshed_history = replace(history, attempts=history.attempts + (refresh,))
    refreshed_current = replace(
        current,
        assessed_at_ms=1120,
        assessment_record_ref=h("assessment-after-refresh"),
        facts=current.facts[:2]
        + (
            replace(
                session_fact,
                state=FactState.ESTABLISHED,
                observation_result_ref=session_check.digest,
                observed_at_ms=1100,
                valid_until_ms=1400,
                reason="Independent session observation under the current defense generation.",
            ),
        ),
    )
    refreshed_proposal = replace(
        proposal,
        frontier_attempt_id="attempt-refresh",
        new_attempt_id="attempt-alternate",
        proposed_plan_digest=h("plan-attempt-alternate"),
        prerequisites=(),
        operations=(replace(proposed_operation, prerequisite_action_ids=()),),
    )
    delivery = result(
        "attempt-alternate",
        "branch-alternate",
        "submit-alternate",
        "receiver.transform-and-submit.v1",
        "delivery-report",
        session_resource,
        "report.receiver-delivery.v1",
        EvidenceProvenance.EXECUTED,
    )
    executed = ActualAttempt(
        "attempt-alternate",
        "branch-alternate",
        "run-attempt-alternate",
        refreshed_proposal.proposed_plan_digest,
        h("attempt-record-alternate"),
        (
            operation(
                "submit-alternate",
                "receiver.transform-and-submit.v1",
                6,
                "Execute the reviewed alternate route with the rechecked session.",
                inputs=tuple(item.source.digest for item in imports),
                outputs=(delivery,),
            ),
        ),
    )
    completed_history = replace(
        refreshed_history, attempts=refreshed_history.attempts + (executed,)
    )
    return BacktrackingFixture(
        history,
        current,
        proposal,
        refreshed_history,
        refreshed_current,
        refreshed_proposal,
        completed_history,
    )
