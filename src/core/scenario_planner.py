"""Capability-graph-aware scenario planner (offline / template provider).

Given a partial chain (the typed artifacts produced so far) the planner
recommends which modules can plausibly run next, ranked by how well
their consumed-types match what the chain has already emitted. It uses
the same capability IO contracts ``ChainContext`` indexes against, so
the planner's view is consistent with the runtime's view.

This module is deliberately **deterministic** and **offline** —
``offer_next_steps`` returns the same ranked list for the same input
chain, no LLM call is made, no remote provider is contacted. It is
the foundation for the priority 5 AI-assisted orchestration surface;
remote-provider integration is a follow-up that wraps this same
public API and validates LLM output against the same shape before
using it.

Public surface:

- :func:`offer_next_steps(chain_state) -> list[NextStepSuggestion]`
  ranks every registered module by chain-fit. The rank is defender-
  readable: "perfect fit" (every required input has an upstream
  emission) > "partial fit" (some optional inputs unsatisfied)
  > "chain entry" (consumes nothing — for empty-chain starters).
- :func:`explain_chain(chain_state) -> ChainExplanation` summarises
  the chain in plain text: which artifact types are present, which
  consumer warnings have fired, which producers are dangling
  (emit a type no consumer has used).
- :func:`suggest_scenario_variants(scenario_steps, count=3) -> list[list[dict]]`
  generates ``count`` mutated variants of an existing scenario by
  swapping one or more steps' technique/channel/method via the
  capability mutation catalog (PR #155). Each variant is a fresh
  list of step dicts the operator can persist as YAML; the planner
  never writes the variant to disk and never triggers execution.
"""

from __future__ import annotations

import copy
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .modules import build_runtime_modules
from .modules.contracts import ARTIFACT_TYPES, CapabilityIOContract, is_meaningful_contract
from .mutations import propose_mutations, apply_mutation


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NextStepSuggestion:
    """A single ranked recommendation for the next chain step.

    ``module`` is the registered name. ``score`` is a real number used
    only for sorting (higher = better fit); a defender doesn't read it
    directly. ``rank`` is the operator-readable tier:

    - ``"perfect_fit"``  - every required consumer slot is satisfied
      AND at least one optional slot is satisfied too.
    - ``"good_fit"``     - every required consumer slot is satisfied,
      no optional slots match (or no optional slots exist).
    - ``"partial_fit"``  - some required consumer slot is missing but
      the module has SOME upstream input it can use.
    - ``"chain_entry"``  - the module declares no required consumer
      (it's a chain entry tactic: initial_access /
      resource_development / reconnaissance / discovery).

    ``required_satisfied`` / ``optional_satisfied`` /
    ``required_missing`` make the rank reasoning machine-readable.

    ``rationale`` is a one-line defender-readable summary the report
    layer can surface as the recommendation's tooltip.
    """

    module: str
    rank: str
    score: float
    required_satisfied: Tuple[str, ...]
    optional_satisfied: Tuple[str, ...]
    required_missing: Tuple[str, ...]
    produces: Tuple[str, ...]
    rationale: str


@dataclass(frozen=True, slots=True)
class ChainExplanation:
    """Plain-text summary of a chain's coherence.

    ``produced_types`` lists every canonical artifact type the chain
    has emitted so far. ``unused_emissions`` lists types produced but
    never consumed downstream (a "dangling producer" the report can
    flag as a coverage gap). ``unsatisfied_warnings`` reflects every
    chain warning the runtime recorded for a missing required input.
    ``narrative`` is one paragraph defender-readable text.
    """

    produced_types: Tuple[str, ...]
    unused_emissions: Tuple[str, ...]
    unsatisfied_warnings: Tuple[Dict[str, str], ...]
    narrative: str


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChainState:
    """Shape the planner walks: the set of types produced so far +
    optional warnings list.

    Built from a :class:`ChainContext` snapshot via :func:`from_snapshot`,
    or constructed directly by callers that already track typed state
    elsewhere.
    """

    produced_types: frozenset
    warnings: Tuple[Dict[str, str], ...] = ()


def from_snapshot(snapshot: Mapping[str, Any]) -> ChainState:
    """Build a :class:`ChainState` from a chain-context snapshot dict.

    The snapshot is the same one the runtime puts under
    ``context["chain"]`` — see :class:`src.core.modules.ChainContext`.
    Tolerant of partial / empty snapshots so the planner can answer
    "what should I run first?" against an empty chain.
    """

    by_type = (snapshot.get("artifacts_by_type") if snapshot else None) or {}
    warnings_raw = (snapshot.get("warnings") if snapshot else None) or []
    warnings: List[Dict[str, str]] = []
    for warning in warnings_raw:
        if isinstance(warning, Mapping):
            warnings.append({str(k): str(v) for k, v in warning.items()})
    return ChainState(
        produced_types=frozenset(t for t in by_type.keys() if t in ARTIFACT_TYPES),
        warnings=tuple(warnings),
    )


# ---------------------------------------------------------------------------
# offer_next_steps
# ---------------------------------------------------------------------------


def offer_next_steps(
    chain_state: ChainState | Mapping[str, Any],
    *,
    registry: Optional[Mapping[str, Any]] = None,
    limit: int = 10,
) -> List[NextStepSuggestion]:
    """Return ranked next-step suggestions for a partial chain.

    Walks the live module registry (or the provided ``registry`` for
    testing) and rates every module against the chain's produced
    types. Modules whose required consumed slots are all satisfied
    rank highest; modules that consume nothing (chain entries) sit
    below partial-fit modules but above non-fit. Returns at most
    ``limit`` results.
    """

    state = (
        chain_state
        if isinstance(chain_state, ChainState)
        else from_snapshot(chain_state if isinstance(chain_state, Mapping) else {})
    )
    modules = registry if registry is not None else build_runtime_modules()
    suggestions: List[NextStepSuggestion] = []
    for name, module in modules.items():
        contract: CapabilityIOContract = getattr(module, "io_contract", CapabilityIOContract())
        if not is_meaningful_contract(contract):
            continue
        suggestion = _rate_module(name, contract, state)
        if suggestion is not None:
            suggestions.append(suggestion)
    # Sort by RANK TIER first, then by score within tier. Without the
    # explicit tier ordering, a chain_entry module that emits many new
    # types could outrank a partial_fit module via score inflation
    # (Codex P1 on PR #156): a discovery step producing 5 new typed
    # rows would beat exfiltration's partial_fit score of 2.0 + bonus
    # bonuses, breaking the "extension over restart" invariant.
    suggestions.sort(key=lambda s: (-_RANK_PRIORITY[s.rank], -s.score, s.module))
    return suggestions[:limit]


# Tier priority. Higher = preferred. Used to sort `offer_next_steps`
# results so a `partial_fit` module always outranks a `chain_entry`
# regardless of score inflation; within a tier, higher score wins.
_RANK_PRIORITY: Dict[str, int] = {
    "perfect_fit": 4,
    "good_fit": 3,
    "partial_fit": 2,
    "chain_entry": 1,
}


def _rate_module(
    name: str,
    contract: CapabilityIOContract,
    state: ChainState,
) -> Optional[NextStepSuggestion]:
    """Score a single module against the chain state.

    Returns ``None`` when the module has no produces / consumes
    declaration AND no chain-entry posture (i.e. opted out via
    ``not_applicable``).
    """

    if contract.not_applicable:
        return None
    required = set(contract.required_consumed_types())
    all_consumed = set(contract.consumed_types())
    optional = all_consumed - required
    produced = set(contract.produced_types())

    required_satisfied = required & state.produced_types
    optional_satisfied = optional & state.produced_types
    required_missing = required - state.produced_types

    # Rank tier + score. Score lets us sort within a tier:
    # bigger satisfied set, smaller missing set, more produced
    # types (extends the chain) wins.
    score = 0.0
    if not required:
        # Chain entry: still rank, but lower than any partial-fit so
        # we prefer extending an existing chain over restarting at
        # the entry.
        rank = "chain_entry"
        score += 1.0  # baseline score so it sorts above zero
    elif not required_missing:
        if optional_satisfied:
            rank = "perfect_fit"
            score += 5.0
        else:
            rank = "good_fit"
            score += 3.0
    elif required_satisfied or optional_satisfied:
        rank = "partial_fit"
        score += 2.0
    else:
        # No alignment whatsoever; skip.
        return None

    # Reward extending the chain with a brand-new emission type.
    new_produced = produced - state.produced_types
    score += 0.25 * len(new_produced)
    score += 0.5 * len(required_satisfied)
    score += 0.25 * len(optional_satisfied)
    score -= 0.5 * len(required_missing)

    rationale = _rationale_for(
        name,
        rank,
        required_satisfied,
        optional_satisfied,
        required_missing,
        produced,
    )
    return NextStepSuggestion(
        module=name,
        rank=rank,
        score=round(score, 4),
        required_satisfied=tuple(sorted(required_satisfied)),
        optional_satisfied=tuple(sorted(optional_satisfied)),
        required_missing=tuple(sorted(required_missing)),
        produces=tuple(sorted(produced)),
        rationale=rationale,
    )


def _rationale_for(
    name: str,
    rank: str,
    required_satisfied: set,
    optional_satisfied: set,
    required_missing: set,
    produced: set,
) -> str:
    if rank == "chain_entry":
        return (
            f"{name}: chain entry (no required upstream); produces "
            f"{', '.join(sorted(produced)) or 'nothing chain-relevant'}."
        )
    if rank == "perfect_fit":
        return (
            f"{name}: required slots satisfied "
            f"({', '.join(sorted(required_satisfied))}); also matches "
            f"optional slots ({', '.join(sorted(optional_satisfied))})."
        )
    if rank == "good_fit":
        return (
            f"{name}: required slots satisfied "
            f"({', '.join(sorted(required_satisfied)) or 'none required'})."
        )
    if rank == "partial_fit":
        return (
            f"{name}: partially satisfied (need "
            f"{', '.join(sorted(required_missing))}; "
            f"upstream provides {', '.join(sorted(required_satisfied | optional_satisfied)) or 'none'})."
        )
    return f"{name}: {rank}"


# ---------------------------------------------------------------------------
# explain_chain
# ---------------------------------------------------------------------------


def explain_chain(
    chain_state: ChainState | Mapping[str, Any],
    *,
    registry: Optional[Mapping[str, Any]] = None,
) -> ChainExplanation:
    """Summarise the chain's coherence in defender-readable text.

    Returns a :class:`ChainExplanation` listing produced types,
    dangling producers (types emitted upstream that no consumer in
    the registry would pick up), and unsatisfied warnings the
    runtime recorded.
    """

    state = (
        chain_state
        if isinstance(chain_state, ChainState)
        else from_snapshot(chain_state if isinstance(chain_state, Mapping) else {})
    )
    modules = registry if registry is not None else build_runtime_modules()
    consumed_anywhere: set = set()
    for module in modules.values():
        contract = getattr(module, "io_contract", None)
        if not is_meaningful_contract(contract):
            continue
        consumed_anywhere.update(contract.consumed_types())
    unused_emissions = tuple(sorted(state.produced_types - consumed_anywhere))
    produced_types = tuple(sorted(state.produced_types))

    if not produced_types:
        narrative = (
            "Empty chain - run a chain-entry tactic (initial_access / "
            "resource_development / reconnaissance / discovery) to seed "
            "the typed propagation graph."
        )
    else:
        bits: List[str] = []
        bits.append(
            f"Chain has emitted {len(produced_types)} typed artifact(s): "
            f"{', '.join(produced_types)}."
        )
        if state.warnings:
            warning_modules = sorted({w.get("module", "?") for w in state.warnings})
            bits.append(
                f"Chain warnings recorded for "
                f"{len(state.warnings)} consumer step(s): {', '.join(warning_modules)}."
            )
        if unused_emissions:
            bits.append(
                f"Dangling producer types (no registered consumer): "
                f"{', '.join(unused_emissions)}."
            )
        narrative = " ".join(bits)

    return ChainExplanation(
        produced_types=produced_types,
        unused_emissions=unused_emissions,
        unsatisfied_warnings=state.warnings,
        narrative=narrative,
    )


# ---------------------------------------------------------------------------
# suggest_scenario_variants
# ---------------------------------------------------------------------------


def suggest_scenario_variants(
    scenario_steps: Sequence[Mapping[str, Any]],
    *,
    count: int = 3,
    seed: Optional[int] = None,
) -> List[List[Dict[str, Any]]]:
    """Generate ``count`` mutated variants of a scenario.

    Each variant is a fresh list of step dicts with one or more steps
    swapped via the capability mutation catalog. The same seed produces
    the same variants byte-for-byte, so a defender can reproduce a
    variant set on demand.

    Variants are deduplicated by ``(step_index, param_key, to_value)``
    tuple: a caller asking for ``count=3`` distinct variants gets 3
    different mutations. When the catalog has fewer distinct mutations
    available than ``count``, the function emits as many unique
    variants as it can and stops -- callers asking for more variants
    than the catalog can provide receive the available subset rather
    than synthetic duplicates. (Without dedup, two variants could
    independently roll the same step+mutation pair and a defender
    asking for "three different variants" would actually run the same
    chain twice.)

    The planner never writes variants to disk and never triggers
    execution; the operator persists / runs the variant they want via
    the existing scenario pipeline.
    """

    if count <= 0 or not scenario_steps:
        return []

    rng = random.Random(seed) if seed is not None else random.Random()
    # Pre-compute whether ANY step has a catalog mutation available at
    # all. If not, fall back to the legacy behaviour of returning
    # ``count`` unmutated copies so downstream callers (CLI / planner
    # UI) still receive a stable count of variants. When at least one
    # step does have catalog mutations, we use the dedup-aware path
    # below: each variant is a UNIQUE (step, param_key, to_value)
    # mutation, and the loop stops early once the catalog is exhausted
    # rather than re-emitting duplicate variants.
    has_any_mutation = any(
        propose_mutations(step) for step in scenario_steps
    )
    variants: List[List[Dict[str, Any]]] = []

    if not has_any_mutation:
        for _ in range(count):
            variant: List[Dict[str, Any]] = [
                copy.deepcopy(dict(step)) for step in scenario_steps
            ]
            variants.append(variant)
        return variants

    seen_mutation_keys: set[Tuple[int, str, Any]] = set()
    # Cap the retry attempts so a catalog with fewer distinct mutations
    # than ``count`` can't loop forever.
    max_attempts = count * 4
    attempts = 0
    while len(variants) < count and attempts < max_attempts:
        attempts += 1
        # Deep-copy each step into the variant so unmutated steps
        # don't share nested ``params`` dicts with the input scenario
        # or with other variants.
        variant = [
            copy.deepcopy(dict(step)) for step in scenario_steps
        ]
        # Pick one step at random and apply one random mutation to it.
        # If the random pick has no available mutations, scan the rest
        # of the chain for a step that does.
        order = list(range(len(variant)))
        rng.shuffle(order)
        applied_key: Optional[Tuple[int, str, Any]] = None
        for idx in order:
            step = variant[idx]
            proposals = propose_mutations(step)
            if not proposals:
                continue
            # Filter out mutations we've already applied at this step.
            available = [
                m
                for m in proposals
                if (idx, m.param_key, m.to_value) not in seen_mutation_keys
            ]
            if not available:
                continue
            mutation = rng.choice(available)
            variant[idx] = apply_mutation(step, mutation)
            applied_key = (idx, mutation.param_key, mutation.to_value)
            break
        if applied_key is None:
            # No step in the chain has any unused mutation. Stop --
            # adding an unmutated copy would be a synthetic duplicate
            # of the original scenario, not a real variant.
            break
        seen_mutation_keys.add(applied_key)
        variants.append(variant)
    return variants


__all__ = [
    "ChainExplanation",
    "ChainState",
    "NextStepSuggestion",
    "explain_chain",
    "from_snapshot",
    "offer_next_steps",
    "suggest_scenario_variants",
]
