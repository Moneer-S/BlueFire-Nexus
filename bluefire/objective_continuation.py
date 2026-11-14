"""Versioned, inert objective-continuation records and dependency assessment.

History is an immutable projection of actual records, not a proposed graph or a
reservation. Current facts are a separate controller assessment. Proposals may
reconsider an earlier decision and explicitly import actual results from any
recorded branch; they cannot manufacture outputs or establish present custody.

The caller must resolve original records and supply trusted expected digests.
Hashes here establish consistency only. An assessment grants no capability,
approval, resource reservation, dispatch, restoration, or execution authority.
It deliberately does not participate in legacy exact-plan retry semantics.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, fields
from enum import Enum
from types import UnionType
from typing import Any, Mapping, TypeVar, Union, cast, get_args, get_origin, get_type_hints

from .contracts import StepOutcome
from .evidence import EvidenceProvenance
from .util import canonical_json_bytes, content_hash

HISTORY_SCHEMA = "bluefire.objective-history.v1"
FACTS_SCHEMA = "bluefire.objective-current-facts.v1"
PROPOSAL_SCHEMA = "bluefire.objective-continuation-proposal.v1"
ASSESSMENT_SCHEMA = "bluefire.objective-continuation-assessment.v1"
MAX_DOCUMENT_BYTES = 256 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,159}")
_MAX_TIME = (1 << 63) - 1
R = TypeVar("R", bound="_Record")


class ObjectiveContinuationError(ValueError):
    """A continuation record is malformed or contradicts its bound history."""


class FactState(str, Enum):
    ESTABLISHED = "established"
    UNCERTAIN = "uncertain"
    STALE = "stale"


class PrerequisiteKind(str, Enum):
    OBSERVE = "observe"
    RESTORE = "restore"
    RECREATE = "recreate"
    RECONCILE = "reconcile"


class RepeatBasis(str, Enum):
    CHANGED_INPUTS = "changed_inputs"
    CHANGED_PREREQUISITES = "changed_prerequisites"
    NEW_EVIDENCE = "new_evidence"
    FRESH_TEST = "fresh_test"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ObjectiveContinuationError(message)


def _identifier(value: str) -> None:
    _require(_ID.fullmatch(value) is not None, "invalid bounded identity")


def _digest(value: str) -> None:
    _require(_DIGEST.fullmatch(value) is not None, "invalid sha256 binding")


def _time(value: int) -> None:
    _require(0 <= value <= _MAX_TIME, "time or ordinal is outside its bound")


def _unique(values: tuple[str, ...], label: str) -> None:
    _require(len(set(values)) == len(values), f"duplicate {label}")


def _bound_wire(value: Any) -> None:
    """Bound direct mappings before allocating their decoded record tree."""
    remaining = MAX_DOCUMENT_BYTES

    def visit(item: Any, depth: int) -> None:
        nonlocal remaining
        _require(depth <= 20, "record nesting exceeds its bound")
        if isinstance(item, Mapping):
            _require(len(item) <= 128, "record object exceeds its bound")
            remaining -= 2 + max(0, len(item) - 1)
            for key, child in item.items():
                _require(type(key) is str and len(key) <= 128, "record key is invalid")
                remaining -= len(canonical_json_bytes(key)) + 1
                visit(child, depth + 1)
        elif type(item) is list:
            _require(len(item) <= 128, "record array exceeds its bound")
            remaining -= 2 + max(0, len(item) - 1)
            for child in item:
                visit(child, depth + 1)
        else:
            _require(
                type(item) in (str, int, bool, type(None)), "record contains a noncanonical scalar"
            )
            if type(item) is str:
                _require(len(item) <= 2000, "record text exceeds its bound")
            if type(item) is int:
                _require(-_MAX_TIME <= item <= _MAX_TIME, "record integer exceeds its bound")
            remaining -= len(canonical_json_bytes(item))
        _require(remaining >= 0, "document byte bound")

    visit(value, 0)


def _decode(value: Any, annotation: Any, *, wire: bool) -> Any:
    """Decode only this closed dataclass vocabulary, with no coercions."""
    origin, args = get_origin(annotation), get_args(annotation)
    if origin in (Union, UnionType):
        if value is None and type(None) in args:
            return None
        choices = tuple(item for item in args if item is not type(None))
        _require(len(choices) == 1, "unsupported record union")
        return _decode(value, choices[0], wire=wire)
    if origin is tuple:
        _require(type(value) is (list if wire else tuple), "record array is not canonical")
        _require(len(value) <= 128, "record array exceeds its bound")
        return tuple(_decode(item, args[0], wire=wire) for item in value)
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        if not wire:
            _require(type(value) is annotation, "record enum is not canonical")
            return value
        _require(type(value) is str, "record enum must be a string")
        try:
            return annotation(value)
        except ValueError as exc:
            raise ObjectiveContinuationError("unknown record enum") from exc
    if isinstance(annotation, type) and issubclass(annotation, _Record):
        if wire:
            return annotation.from_mapping(value)
        _require(type(value) is annotation, "nested record is not canonical")
        return value
    _require(annotation in (str, int, bool), "unsupported record field")
    _require(type(value) is annotation, "record scalar is not canonical")
    if annotation is str:
        _require(
            bool(value)
            and value == value.strip()
            and len(value) <= 2000
            and all(ord(character) >= 32 and ord(character) != 127 for character in value),
            "record text is invalid",
        )
    return value


class _Record:
    """One strict wire representation and immutable in-memory representation."""

    def __post_init__(self) -> None:
        for name, annotation in get_type_hints(type(self)).items():
            _decode(getattr(self, name), annotation, wire=False)
        self._validate()

    def _validate(self) -> None:
        pass

    @classmethod
    def from_mapping(cls: type[R], value: Any) -> R:
        _bound_wire(value)
        names = {field.name for field in fields(cast(Any, cls))}
        _require(isinstance(value, Mapping) and set(value) == names, "record fields differ")
        annotations = get_type_hints(cls)
        return cls(**{key: _decode(value[key], annotations[key], wire=True) for key in names})

    @classmethod
    def from_json(cls: type[R], value: bytes) -> R:
        _require(type(value) is bytes and len(value) <= MAX_DOCUMENT_BYTES, "JSON byte bound")

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, item in items:
                _require(key not in result, "duplicate JSON key")
                result[key] = item
            return result

        def constant(_value: str) -> None:
            raise ObjectiveContinuationError("nonfinite JSON value")

        try:
            row = json.loads(
                value.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant
            )
            return cls.from_mapping(row)
        except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
            if isinstance(exc, ObjectiveContinuationError):
                raise
            raise ObjectiveContinuationError("invalid strict JSON record") from exc

    def to_dict(self) -> dict[str, Any]:
        def encode(value: Any) -> Any:
            if isinstance(value, _Record):
                return value.to_dict()
            if isinstance(value, Enum):
                return value.value
            if isinstance(value, tuple):
                return [encode(item) for item in value]
            return value

        return {field.name: encode(getattr(self, field.name)) for field in fields(cast(Any, self))}

    @property
    def digest(self) -> str:
        return content_hash(self.to_dict())

    def _size(self) -> None:
        _require(
            len(canonical_json_bytes(self.to_dict())) <= MAX_DOCUMENT_BYTES, "document byte bound"
        )


@dataclass(frozen=True, slots=True)
class ConditionBinding(_Record):
    """An independently resolved relevant context dimension, not free-form state."""

    key: str
    value_ref: str

    def _validate(self) -> None:
        _identifier(self.key)
        _digest(self.value_ref)


@dataclass(frozen=True, slots=True)
class ResourceBinding(_Record):
    resource_id: str
    generation_ref: str

    def _validate(self) -> None:
        _identifier(self.resource_id)
        _digest(self.generation_ref)


def _conditions(values: tuple[ConditionBinding, ...]) -> dict[str, str]:
    _unique(tuple(item.key for item in values), "condition keys")
    return {item.key: item.value_ref for item in values}


@dataclass(frozen=True, slots=True)
class ResultReference(_Record):
    """Exact original producer and observed content identity; never an alias."""

    attempt_id: str
    branch_id: str
    run_id: str
    plan_digest: str
    producer_step_id: str
    producer_method_id: str
    output_name: str
    objective_ref: str
    environment_ref: str
    fixture_ref: str
    resource_id: str
    resource_generation_ref: str
    semantic_type: str
    provenance: EvidenceProvenance
    evidence_ref: str
    content_digest: str

    def _validate(self) -> None:
        for value in (
            self.attempt_id,
            self.branch_id,
            self.run_id,
            self.producer_step_id,
            self.producer_method_id,
            self.output_name,
            self.resource_id,
            self.semantic_type,
        ):
            _identifier(value)
        for value in (
            self.plan_digest,
            self.objective_ref,
            self.environment_ref,
            self.fixture_ref,
            self.resource_generation_ref,
            self.evidence_ref,
            self.content_digest,
        ):
            _digest(value)


@dataclass(frozen=True, slots=True)
class ActualOperation(_Record):
    """One actually attempted operation; a reservation cannot populate this row."""

    operation_id: str
    step_id: str
    method_id: str
    ordinal: int
    assumption: str
    parameters_digest: str
    input_result_refs: tuple[str, ...]
    conditions: tuple[ConditionBinding, ...]
    resources: tuple[ResourceBinding, ...]
    outcome: StepOutcome
    effects_uncertain: bool
    record_ref: str
    results: tuple[ResultReference, ...]

    def _validate(self) -> None:
        for value in (self.operation_id, self.step_id, self.method_id):
            _identifier(value)
        _time(self.ordinal)
        _digest(self.parameters_digest)
        _digest(self.record_ref)
        _conditions(self.conditions)
        _unique(tuple(item.resource_id for item in self.resources), "actual resource identities")
        _unique(self.input_result_refs, "actual input bindings")
        for value in self.input_result_refs:
            _digest(value)
        _unique(tuple(item.output_name for item in self.results), "actual outputs")
        for result in self.results:
            _require(
                (result.producer_step_id, result.producer_method_id)
                == (self.step_id, self.method_id),
                "result differs from its actual producer",
            )
            _require(
                ResourceBinding(result.resource_id, result.resource_generation_ref)
                in self.resources,
                "result resource is not bound by its actual operation",
            )


@dataclass(frozen=True, slots=True)
class ActualAttempt(_Record):
    attempt_id: str
    branch_id: str
    run_id: str
    plan_digest: str
    record_ref: str
    operations: tuple[ActualOperation, ...]

    def _validate(self) -> None:
        for value in (self.attempt_id, self.branch_id, self.run_id):
            _identifier(value)
        _digest(self.plan_digest)
        _digest(self.record_ref)
        _require(bool(self.operations), "actual attempt has no attempted operations")
        for operation in self.operations:
            for result in operation.results:
                _require(
                    (result.attempt_id, result.branch_id, result.run_id, result.plan_digest)
                    == (self.attempt_id, self.branch_id, self.run_id, self.plan_digest),
                    "result differs from its actual attempt",
                )


@dataclass(frozen=True, slots=True)
class ObjectiveHistory(_Record):
    schema_version: str
    objective_ref: str
    environment_ref: str
    attempts: tuple[ActualAttempt, ...]

    def _validate(self) -> None:
        _require(self.schema_version == HISTORY_SCHEMA, "unsupported history version")
        _digest(self.objective_ref)
        _digest(self.environment_ref)
        _require(bool(self.attempts), "history requires an actual frontier")
        _unique(tuple(item.attempt_id for item in self.attempts), "attempt identities")
        _unique(tuple(item.run_id for item in self.attempts), "run identities")
        seen_results: set[str] = set()
        operation_ids: list[str] = []
        previous = -1
        for attempt in self.attempts:
            for operation in attempt.operations:
                _require(operation.ordinal > previous, "actual operation chronology is invalid")
                previous = operation.ordinal
                operation_ids.append(operation.operation_id)
                _require(
                    set(operation.input_result_refs) <= seen_results,
                    "actual input is unavailable or forward-referenced",
                )
                for result in operation.results:
                    _require(
                        (result.objective_ref, result.environment_ref)
                        == (self.objective_ref, self.environment_ref),
                        "actual result belongs to another objective or environment",
                    )
                    _require(result.digest not in seen_results, "duplicate actual result")
                    seen_results.add(result.digest)
        _unique(tuple(operation_ids), "operation identities")
        self._size()


@dataclass(frozen=True, slots=True)
class CurrentFact(_Record):
    """Controller assessment about an exact result or uncertain operation."""

    fact_id: str
    subject_ref: str
    predicate: str
    observation_result_ref: str
    state: FactState
    observed_at_ms: int
    valid_until_ms: int | None
    conditions: tuple[ConditionBinding, ...]
    reason: str

    def _validate(self) -> None:
        _identifier(self.fact_id)
        _identifier(self.predicate)
        _digest(self.subject_ref)
        _digest(self.observation_result_ref)
        _time(self.observed_at_ms)
        if self.valid_until_ms is not None:
            _time(self.valid_until_ms)
            _require(self.valid_until_ms > self.observed_at_ms, "fact expiry predates observation")
        _conditions(self.conditions)


@dataclass(frozen=True, slots=True)
class CurrentFacts(_Record):
    """Trusted assessment: caller verifies observation meaning and event time.

    Source existence and OBSERVED provenance alone cannot prove a predicate,
    custody, present access or reconciliation. The controller must verify that
    the original observation supports the exact subject and predicate before
    binding this projection's digest outside the candidate document.
    """

    schema_version: str
    objective_ref: str
    environment_ref: str
    fixture_ref: str
    assessed_at_ms: int
    assessment_record_ref: str
    conditions: tuple[ConditionBinding, ...]
    facts: tuple[CurrentFact, ...]

    def _validate(self) -> None:
        _require(self.schema_version == FACTS_SCHEMA, "unsupported current-facts version")
        for value in (
            self.objective_ref,
            self.environment_ref,
            self.fixture_ref,
            self.assessment_record_ref,
        ):
            _digest(value)
        _time(self.assessed_at_ms)
        _conditions(self.conditions)
        _unique(tuple(item.fact_id for item in self.facts), "current fact identities")
        _require(
            len({(item.subject_ref, item.predicate) for item in self.facts}) == len(self.facts),
            "ambiguous current subject and predicate assessments",
        )
        for fact in self.facts:
            _require(
                fact.observed_at_ms <= self.assessed_at_ms, "fact observation follows assessment"
            )
        self._size()


@dataclass(frozen=True, slots=True)
class FactRequirement(_Record):
    fact_id: str
    predicate: str
    context_keys: tuple[str, ...]
    max_age_ms: int | None

    def _validate(self) -> None:
        _identifier(self.fact_id)
        _identifier(self.predicate)
        _unique(self.context_keys, "freshness dimensions")
        for value in self.context_keys:
            _identifier(value)
        if self.max_age_ms is not None:
            _time(self.max_age_ms)


@dataclass(frozen=True, slots=True)
class ImportedResult(_Record):
    source: ResultReference
    expected_semantic_type: str
    requirements: tuple[FactRequirement, ...]

    def _validate(self) -> None:
        _identifier(self.expected_semantic_type)
        _require(
            bool(self.requirements), "executable import requires current prerequisite assessment"
        )
        _unique(tuple(item.fact_id for item in self.requirements), "import requirements")


@dataclass(frozen=True, slots=True)
class ReconsideredDecision(_Record):
    attempt_id: str
    operation_id: str
    original_assumption: str
    revised_assumption: str
    learned_result_refs: tuple[str, ...]

    def _validate(self) -> None:
        _identifier(self.attempt_id)
        _identifier(self.operation_id)
        _require(
            self.original_assumption != self.revised_assumption,
            "reconsideration does not change the assumption",
        )
        _require(bool(self.learned_result_refs), "reconsideration requires later information")
        _unique(self.learned_result_refs, "reconsideration evidence")
        for value in self.learned_result_refs:
            _digest(value)


@dataclass(frozen=True, slots=True)
class RepeatJustification(_Record):
    prior_operation_ref: str
    basis: RepeatBasis
    explanation: str
    evidence_result_refs: tuple[str, ...]
    fresh_test_purpose: str | None

    def _validate(self) -> None:
        _digest(self.prior_operation_ref)
        _unique(self.evidence_result_refs, "repeat evidence")
        for value in self.evidence_result_refs:
            _digest(value)
        _require(
            (self.basis is RepeatBasis.FRESH_TEST) == (self.fresh_test_purpose is not None),
            "fresh-test purpose must be explicit and specific to a fresh test",
        )
        _require(
            (self.basis is RepeatBasis.NEW_EVIDENCE) == bool(self.evidence_result_refs),
            "new-evidence repetition requires explicit evidence references",
        )


@dataclass(frozen=True, slots=True)
class PrerequisiteAction(_Record):
    action_id: str
    attempt_id: str
    kind: PrerequisiteKind
    method_id: str
    subject_ref: str
    resource_id: str
    source_generation_ref: str
    requested_generation_ref: str | None
    addresses_fact_ids: tuple[str, ...]
    rationale: str
    parameters_digest: str
    conditions: tuple[ConditionBinding, ...]
    repeat: RepeatJustification | None

    def _validate(self) -> None:
        for value in (self.action_id, self.attempt_id, self.method_id, self.resource_id):
            _identifier(value)
        _digest(self.subject_ref)
        _digest(self.source_generation_ref)
        _digest(self.parameters_digest)
        _conditions(self.conditions)
        if self.requested_generation_ref is not None:
            _digest(self.requested_generation_ref)
        _require(
            (self.kind in (PrerequisiteKind.RESTORE, PrerequisiteKind.RECREATE))
            == (self.requested_generation_ref is not None),
            "restoration or recreation requires an explicit requested generation",
        )
        if self.kind is PrerequisiteKind.RESTORE:
            _require(
                self.requested_generation_ref == self.source_generation_ref,
                "restoration must name the original generation",
            )
        if self.kind is PrerequisiteKind.RECREATE:
            _require(
                self.requested_generation_ref != self.source_generation_ref,
                "recreation requires a new generation",
            )
        _unique(self.addresses_fact_ids, "prerequisite fact identities")
        _require(bool(self.addresses_fact_ids), "prerequisite action must name its pending facts")
        for value in self.addresses_fact_ids:
            _identifier(value)


@dataclass(frozen=True, slots=True)
class ProposedOperation(_Record):
    operation_id: str
    method_id: str
    parameters_digest: str
    imports: tuple[ImportedResult, ...]
    conditions: tuple[ConditionBinding, ...]
    prerequisite_action_ids: tuple[str, ...]
    repeat: RepeatJustification | None

    def _validate(self) -> None:
        _identifier(self.operation_id)
        _identifier(self.method_id)
        _digest(self.parameters_digest)
        _conditions(self.conditions)
        _unique(tuple(item.source.digest for item in self.imports), "import sources")
        _unique(self.prerequisite_action_ids, "operation prerequisites")
        for value in self.prerequisite_action_ids:
            _identifier(value)


@dataclass(frozen=True, slots=True)
class ContinuationProposal(_Record):
    schema_version: str
    objective_ref: str
    environment_ref: str
    fixture_ref: str
    frontier_attempt_id: str
    new_attempt_id: str
    branch_id: str
    proposed_plan_digest: str
    reconsideration: ReconsideredDecision
    prerequisites: tuple[PrerequisiteAction, ...]
    operations: tuple[ProposedOperation, ...]

    def _validate(self) -> None:
        _require(self.schema_version == PROPOSAL_SCHEMA, "unsupported continuation version")
        for value in (
            self.objective_ref,
            self.environment_ref,
            self.fixture_ref,
            self.proposed_plan_digest,
        ):
            _digest(value)
        for value in (self.frontier_attempt_id, self.new_attempt_id, self.branch_id):
            _identifier(value)
        _require(bool(self.operations), "continuation requires proposed operations")
        _unique(
            tuple(item.operation_id for item in self.operations), "proposed operation identities"
        )
        _unique(
            tuple(item.action_id for item in self.prerequisites), "prerequisite action identities"
        )
        _unique(
            tuple(item.operation_id for item in self.operations)
            + tuple(item.action_id for item in self.prerequisites),
            "proposed work identities",
        )
        _unique(
            tuple(item.attempt_id for item in self.prerequisites) + (self.new_attempt_id,),
            "new effect attempt identities",
        )
        self._size()


@dataclass(frozen=True, slots=True)
class ContinuationAssessment(_Record):
    """Dependency results only. Even a clear result is not permission to execute."""

    schema_version: str
    proposal_digest: str
    history_digest: str
    current_facts_digest: str
    unmet_fact_ids: tuple[str, ...]
    pending_prerequisite_action_ids: tuple[str, ...]
    unreconciled_operation_refs: tuple[str, ...]

    def _validate(self) -> None:
        _require(
            self.schema_version == ASSESSMENT_SCHEMA, "unsupported continuation assessment version"
        )
        for value in (self.proposal_digest, self.history_digest, self.current_facts_digest):
            _digest(value)
        _unique(self.unmet_fact_ids, "unmet facts")
        _unique(self.pending_prerequisite_action_ids, "pending prerequisites")
        _unique(self.unreconciled_operation_refs, "unreconciled operations")
        for value in self.unmet_fact_ids + self.pending_prerequisite_action_ids:
            _identifier(value)
        for value in self.unreconciled_operation_refs:
            _digest(value)
        self._size()

    @property
    def inputs_current(self) -> bool:
        return not (
            self.unmet_fact_ids
            or self.pending_prerequisite_action_ids
            or self.unreconciled_operation_refs
        )


def _fact_current(
    fact: CurrentFact | None,
    requirement: FactRequirement,
    subject_ref: str,
    current: CurrentFacts,
    now_ms: int,
) -> bool:
    if fact is None:
        return False
    _require(
        (fact.subject_ref, fact.predicate) == (subject_ref, requirement.predicate),
        "fact does not address its exact dependency",
    )
    if fact.state is not FactState.ESTABLISHED:
        return False
    if fact.valid_until_ms is not None and now_ms >= fact.valid_until_ms:
        return False
    if requirement.max_age_ms is not None and now_ms - fact.observed_at_ms > requirement.max_age_ms:
        return False
    observed, present = _conditions(fact.conditions), _conditions(current.conditions)
    return all(
        key in observed and key in present and observed[key] == present[key]
        for key in requirement.context_keys
    )


def _check_repeat(
    method_id: str,
    parameters_digest: str,
    inputs: tuple[str, ...],
    conditions: dict[str, str],
    repeat: RepeatJustification | None,
    actual: Mapping[str, ActualOperation],
    results: Mapping[str, tuple[ResultReference, int]],
) -> None:
    prior = [item for item in actual.values() if item.method_id == method_id]
    if not prior:
        _require(repeat is None, "repeat justification has no actual prior method")
        return
    baseline = max(prior, key=lambda item: item.ordinal)
    _require(
        repeat is not None and repeat.prior_operation_ref == baseline.digest,
        "repeated method requires the latest actual condition baseline",
    )
    assert repeat is not None
    old_conditions = _conditions(baseline.conditions)
    # The independently reviewed method projection fixes relevant dimensions.
    # Model-selected additions cannot by themselves justify another attempt.
    _require(
        set(conditions) == set(old_conditions),
        "repeat drops or invents relevant condition dimensions",
    )
    if repeat.basis is RepeatBasis.CHANGED_INPUTS:
        _require(
            (parameters_digest, sorted(inputs))
            != (baseline.parameters_digest, sorted(baseline.input_result_refs)),
            "repeat inputs have not changed",
        )
    elif repeat.basis is RepeatBasis.CHANGED_PREREQUISITES:
        _require(conditions != old_conditions, "repeat prerequisites have not changed")
    elif repeat.basis is RepeatBasis.NEW_EVIDENCE:
        _require(
            all(
                ref in results and results[ref][1] > baseline.ordinal
                for ref in repeat.evidence_result_refs
            ),
            "repeat lacks meaningful later evidence",
        )


def assess_continuation(
    proposal: ContinuationProposal,
    history: ObjectiveHistory,
    current: CurrentFacts,
    *,
    expected_history_digest: str,
    expected_current_facts_digest: str,
    now_ms: int,
) -> ContinuationAssessment:
    """Validate inert bindings against independently trusted immutable projections.

    A missing/stale/uncertain prerequisite is reported, never fabricated. Declared
    observe/restore/recreate/reconcile actions remain pending until new actual
    records and a fresh trusted current assessment are supplied in a newly issued
    continuation proposal pinned to the new actual frontier. An old proposal is
    never resumed automatically after prerequisite effects. Capability,
    semantic-port, effect, approval and spending checks remain the compiler and
    dispatcher's responsibility; model-declared requirements cannot replace them.
    """
    _require(type(now_ms) is int, "assessment time is not canonical")
    _time(now_ms)
    _digest(expected_history_digest)
    _digest(expected_current_facts_digest)
    _require(history.digest == expected_history_digest, "history differs from trusted binding")
    _require(
        current.digest == expected_current_facts_digest, "current facts differ from trusted binding"
    )
    _require(current.assessed_at_ms <= now_ms, "assessment is in the future")
    _require(
        (proposal.objective_ref, proposal.environment_ref)
        == (history.objective_ref, history.environment_ref)
        == (current.objective_ref, current.environment_ref),
        "continuation changes objective or environment",
    )
    _require(proposal.fixture_ref == current.fixture_ref, "continuation changes current fixture")
    _require(
        proposal.frontier_attempt_id == history.attempts[-1].attempt_id,
        "continuation frontier is not latest actual attempt",
    )
    attempts = {item.attempt_id: item for item in history.attempts}
    operations = {
        operation.operation_id: (attempt, operation)
        for attempt in history.attempts
        for operation in attempt.operations
    }
    operation_refs = {operation.digest: operation for _, operation in operations.values()}
    results = {
        result.digest: (result, operation.ordinal)
        for _, operation in operations.values()
        for result in operation.results
    }
    new_ids = (proposal.new_attempt_id,) + tuple(item.attempt_id for item in proposal.prerequisites)
    _require(not set(new_ids) & set(attempts), "new effects reuse a historical attempt identity")
    work_ids = {item.operation_id for item in proposal.operations} | {
        item.action_id for item in proposal.prerequisites
    }
    _require(not work_ids & set(operations), "proposal reuses an actual operation identity")
    reconsidered = proposal.reconsideration
    original = operations.get(reconsidered.operation_id)
    _require(
        original is not None and original[0].attempt_id == reconsidered.attempt_id,
        "reconsidered decision does not exist",
    )
    assert original is not None
    _require(
        original[1].assumption == reconsidered.original_assumption,
        "reconsidered assumption differs from actual history",
    )
    _require(
        all(
            ref in results and results[ref][1] > original[1].ordinal
            for ref in reconsidered.learned_result_refs
        ),
        "reconsideration lacks information learned after the decision",
    )
    facts = {item.fact_id: item for item in current.facts}
    for fact in current.facts:
        _require(
            fact.subject_ref in results or fact.subject_ref in operation_refs,
            "current fact addresses unknown history",
        )
        observed = results.get(fact.observation_result_ref)
        _require(
            observed is not None and observed[0].provenance is EvidenceProvenance.OBSERVED,
            "current fact lacks exact independent observation",
        )
        assert observed is not None
        subject_ordinal = (
            results[fact.subject_ref][1]
            if fact.subject_ref in results
            else operation_refs[fact.subject_ref].ordinal
        )
        _require(observed[1] >= subject_ordinal, "current observation predates its subject")
        if fact.predicate == "effects_reconciled":
            _require(
                fact.subject_ref in operation_refs and observed[1] > subject_ordinal,
                "effect reconciliation must follow its actual operation",
            )
    prerequisites = {item.action_id: item for item in proposal.prerequisites}
    present_conditions = _conditions(current.conditions)
    unmet: set[str] = set()
    required_fact_subjects: dict[str, str] = {}
    proposed_signatures: set[str] = set()
    for operation in proposal.operations:
        _require(
            set(operation.prerequisite_action_ids) <= set(prerequisites),
            "operation prerequisite is unavailable",
        )
        conditions = _conditions(operation.conditions)
        signature = content_hash(
            {
                "method": operation.method_id,
                "parameters": operation.parameters_digest,
                "inputs": sorted(item.source.digest for item in operation.imports),
                "conditions": conditions,
            }
        )
        _require(
            signature not in proposed_signatures,
            "duplicate proposed work under unchanged conditions",
        )
        proposed_signatures.add(signature)
        _require(
            all(present_conditions.get(key) == value for key, value in conditions.items()),
            "proposed operation conditions are not current",
        )
        for imported in operation.imports:
            source = imported.source
            _require(
                source.digest in results and results[source.digest][0] == source,
                "import is not an exact actual emitted result",
            )
            _require(
                source.semantic_type == imported.expected_semantic_type,
                "import semantic type differs",
            )
            _require(source.fixture_ref == current.fixture_ref, "import belongs to another fixture")
            for requirement in imported.requirements:
                prior_subject = required_fact_subjects.setdefault(
                    requirement.fact_id, source.digest
                )
                _require(
                    prior_subject == source.digest,
                    "one current fact cannot address different imported results",
                )
                if not _fact_current(
                    facts.get(requirement.fact_id), requirement, source.digest, current, now_ms
                ):
                    unmet.add(requirement.fact_id)
        operation_facts = {
            item.fact_id: imported.source.digest
            for imported in operation.imports
            for item in imported.requirements
        }
        for action_id in operation.prerequisite_action_ids:
            action = prerequisites[action_id]
            if action.kind is not PrerequisiteKind.RECONCILE:
                _require(
                    all(
                        operation_facts.get(fact_id) == action.subject_ref
                        for fact_id in action.addresses_fact_ids
                    ),
                    "prerequisite does not belong to its consuming operation",
                )
        _check_repeat(
            operation.method_id,
            operation.parameters_digest,
            tuple(item.source.digest for item in operation.imports),
            conditions,
            operation.repeat,
            operation_refs,
            results,
        )
    prerequisite_signatures: set[str] = set()
    for prerequisite in proposal.prerequisites:
        signature = content_hash(
            {
                "method": prerequisite.method_id,
                "kind": prerequisite.kind.value,
                "subject": prerequisite.subject_ref,
                "resource": prerequisite.resource_id,
                "source_generation": prerequisite.source_generation_ref,
                "requested_generation": prerequisite.requested_generation_ref,
            }
        )
        _require(
            signature not in prerequisite_signatures,
            "duplicate prerequisite work under unchanged conditions",
        )
        prerequisite_signatures.add(signature)
        prerequisite_conditions = _conditions(prerequisite.conditions)
        _require(
            all(
                present_conditions.get(key) == value
                for key, value in prerequisite_conditions.items()
            ),
            "prerequisite conditions are not current",
        )
        inputs = (prerequisite.subject_ref,) if prerequisite.subject_ref in results else ()
        work_signature = content_hash(
            {
                "method": prerequisite.method_id,
                "parameters": prerequisite.parameters_digest,
                "inputs": sorted(inputs),
                "conditions": prerequisite_conditions,
            }
        )
        _require(
            work_signature not in proposed_signatures,
            "duplicate proposed work across operations and prerequisites",
        )
        proposed_signatures.add(work_signature)
        _check_repeat(
            prerequisite.method_id,
            prerequisite.parameters_digest,
            inputs,
            prerequisite_conditions,
            prerequisite.repeat,
            operation_refs,
            results,
        )
        _require(
            prerequisite.subject_ref in results or prerequisite.subject_ref in operation_refs,
            "prerequisite addresses unknown history",
        )
        bound_resources: tuple[ResourceBinding, ...]
        if prerequisite.subject_ref in results:
            bound_result = results[prerequisite.subject_ref][0]
            bound_resources = (
                ResourceBinding(bound_result.resource_id, bound_result.resource_generation_ref),
            )
        else:
            bound_resources = operation_refs[prerequisite.subject_ref].resources
            _require(
                prerequisite.kind is PrerequisiteKind.RECONCILE,
                "only reconciliation can address an actual operation",
            )
        _require(
            ResourceBinding(prerequisite.resource_id, prerequisite.source_generation_ref)
            in bound_resources,
            "prerequisite resource or source generation differs from its actual subject",
        )
        for fact_id in prerequisite.addresses_fact_ids:
            expected_subject = required_fact_subjects.get(fact_id)
            if expected_subject is None and fact_id in facts:
                expected_subject = facts[fact_id].subject_ref
            _require(
                expected_subject == prerequisite.subject_ref,
                "prerequisite action does not address its fact dependency",
            )
    used_prerequisites = {
        ref for item in proposal.operations for ref in item.prerequisite_action_ids
    }
    _require(
        used_prerequisites == set(prerequisites), "unreferenced prerequisite actions are ambiguous"
    )
    unreconciled: set[str] = set()
    for ref, actual_operation in operation_refs.items():
        if actual_operation.effects_uncertain:
            reconciliations = [
                fact
                for fact in current.facts
                if fact.subject_ref == ref and fact.predicate == "effects_reconciled"
            ]
            _require(len(reconciliations) <= 1, "ambiguous effect reconciliation")
            if not reconciliations or not _fact_current(
                reconciliations[0],
                FactRequirement(
                    reconciliations[0].fact_id,
                    "effects_reconciled",
                    tuple(present_conditions),
                    None,
                ),
                ref,
                current,
                now_ms,
            ):
                unreconciled.add(ref)
    return ContinuationAssessment(
        ASSESSMENT_SCHEMA,
        proposal.digest,
        history.digest,
        current.digest,
        tuple(sorted(unmet)),
        tuple(sorted(prerequisites)),
        tuple(sorted(unreconciled)),
    )
