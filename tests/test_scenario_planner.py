"""Capability-graph-aware scenario planner.

The planner walks the live module registry against a chain state and
returns ranked suggestions for the next step. It is the foundation
for the priority 5 AI-assisted orchestration surface; remote-provider
integration is a follow-up that wraps this same public API and
validates LLM output against the same shape before using it.

Pinned invariants:

- ``offer_next_steps`` ranks chain-fit modules above chain-entry
  modules (so a partial chain prefers extending over restarting).
- ``perfect_fit`` only fires when every required consumer slot is
  satisfied AND at least one optional slot is satisfied too.
- ``good_fit`` fires when every required slot is satisfied, even if
  no optional slots match.
- ``partial_fit`` fires when SOME but not all required slots are
  satisfied.
- ``chain_entry`` fires for modules with no required consumer slots.
- A module that doesn't align at all is dropped from the result.
- ``explain_chain`` summarises the chain's coherence in plain text,
  flags dangling producers, and surfaces the runtime warnings.
- ``suggest_scenario_variants`` produces deterministic variants when
  given a seed; each variant carries a ``mutation_history`` row so
  the report can render the swap trail.
- The planner never executes a module, never writes scenario YAML,
  never makes a network call.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

import pytest

from src.core.modules import build_runtime_modules
from src.core.modules.chain import ChainContext
from src.core.scenario_planner import (
    ChainExplanation,
    ChainState,
    NextStepSuggestion,
    explain_chain,
    from_snapshot,
    offer_next_steps,
    suggest_scenario_variants,
)


# ---------------------------------------------------------------------------
# from_snapshot
# ---------------------------------------------------------------------------


def test_from_snapshot_handles_empty_input() -> None:
    state = from_snapshot({})
    assert state.produced_types == frozenset()
    assert state.warnings == ()


def test_from_snapshot_filters_unknown_artifact_types() -> None:
    """Unknown labels in the snapshot must not poison the produced set
    (the planner uses the canonical vocabulary)."""

    snapshot = {
        "artifacts_by_type": {
            "host": [{"value": "10.0.0.1"}],
            "definitely-not-a-real-type": [{"value": "x"}],
        },
        "warnings": [],
    }
    state = from_snapshot(snapshot)
    assert "host" in state.produced_types
    assert "definitely-not-a-real-type" not in state.produced_types


def test_from_snapshot_collects_warnings_as_strings() -> None:
    snapshot = {
        "artifacts_by_type": {},
        "warnings": [
            {"step_id": "s1", "module": "exfiltration", "missing_type": "host"},
        ],
    }
    state = from_snapshot(snapshot)
    assert len(state.warnings) == 1
    assert state.warnings[0]["module"] == "exfiltration"


# ---------------------------------------------------------------------------
# offer_next_steps - empty chain
# ---------------------------------------------------------------------------


def test_offer_next_steps_empty_chain_recommends_chain_entries_only() -> None:
    """An empty chain has no consumed-type matches, so only modules
    that consume nothing (chain entries) should appear in the
    recommendations."""

    state = from_snapshot({})
    suggestions = offer_next_steps(state, limit=20)
    assert suggestions, "empty chain should still recommend chain entries"
    assert all(s.rank == "chain_entry" for s in suggestions), (
        "empty chain produced non-chain_entry recommendations: "
        f"{[(s.module, s.rank) for s in suggestions]}"
    )


def test_offer_next_steps_empty_chain_includes_initial_access() -> None:
    state = from_snapshot({})
    suggestions = offer_next_steps(state, limit=30)
    modules = {s.module for s in suggestions}
    assert "initial_access" in modules
    assert "discovery" in modules


# ---------------------------------------------------------------------------
# offer_next_steps - chain with typed produces
# ---------------------------------------------------------------------------


def test_offer_next_steps_promotes_modules_that_consume_chain_emissions() -> None:
    """When discovery has emitted a host, credential_access (which
    consumes host) should outrank an empty-chain entry like
    initial_access."""

    registry = build_runtime_modules()
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=registry["discovery"].io_contract,
        artifacts={
            "discovery_type": "host_discovery",
            "targets": ["10.0.0.5"],
            "discovered": [],
        },
    )
    state = from_snapshot(chain.snapshot())
    suggestions = offer_next_steps(state, registry=registry, limit=10)

    # The chain has produced ``host``. credential_access has a required
    # ``host`` slot - it should be ranked good_fit (no optional slots
    # match either) above chain entries.
    cred = next((s for s in suggestions if s.module == "credential_access"), None)
    assert cred is not None
    assert cred.rank in {"good_fit", "perfect_fit"}
    assert "host" in cred.required_satisfied


def test_offer_next_steps_perfect_fit_requires_optional_match_too() -> None:
    """perfect_fit only fires when at least one OPTIONAL slot is also
    satisfied (in addition to every required slot)."""

    registry = build_runtime_modules()
    # Lateral movement requires host (target) and optionally consumes
    # source/host + credential. After discovery + creds the chain has
    # both ``host`` and ``credential`` - that should give lateral
    # movement a perfect_fit.
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=registry["discovery"].io_contract,
        artifacts={
            "discovery_type": "host_discovery",
            "targets": ["10.0.0.5"],
            "discovered": [],
        },
    )
    chain.record_step(
        step_id="cred-1",
        module="credential_access",
        contract=registry["credential_access"].io_contract,
        artifacts={"technique": "lsass_dump", "target": "10.0.0.5", "credential": {"hash": "abc"}},
    )
    state = from_snapshot(chain.snapshot())
    suggestions = offer_next_steps(state, registry=registry, limit=20)
    lat = next((s for s in suggestions if s.module == "lateral_movement"), None)
    assert lat is not None
    # lateral_movement requires host (only) and has optional source
    # (host) + credential + token. credential satisfied -> perfect_fit.
    assert lat.rank == "perfect_fit", (
        f"expected perfect_fit for lateral_movement, got {lat.rank}; "
        f"satisfied={lat.required_satisfied}, optional={lat.optional_satisfied}"
    )


def test_offer_next_steps_partial_fit_when_required_missing(
    tmp_path,
) -> None:
    """A consumer with required slots not yet produced upstream should
    rank partial_fit (or be excluded entirely if zero alignment)."""

    registry = build_runtime_modules()
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=registry["discovery"].io_contract,
        artifacts={"discovery_type": "files", "targets": ["/etc/passwd"], "discovered": []},
    )
    state = from_snapshot(chain.snapshot())
    suggestions = offer_next_steps(state, registry=registry, limit=20)
    # exfiltration requires HOST. Files-discovery emits FILE, not HOST.
    # exfiltration also has optional staged_file / collected_data /
    # c2_endpoint - none of which match either. So exfiltration drops
    # out of the recommendations entirely.
    exfil = next((s for s in suggestions if s.module == "exfiltration"), None)
    assert exfil is None, (
        f"exfiltration should drop out for files-only chain; got rank={exfil.rank if exfil else None}"
    )
    # anti_detection / defense_evasion accept FILE as an optional
    # input -> partial_fit (their required HOST is missing).
    evasion = next((s for s in suggestions if s.module == "defense_evasion"), None)
    assert evasion is not None
    assert evasion.rank == "partial_fit"
    assert "file" in evasion.optional_satisfied


def test_offer_next_steps_excludes_diagnostic_optouts() -> None:
    """legacy_capability_summary opted out via not_applicable; it
    must not appear in any recommendation list."""

    suggestions = offer_next_steps(from_snapshot({}), limit=50)
    assert not any(s.module == "legacy_capability_summary" for s in suggestions)


def test_offer_next_steps_respects_limit() -> None:
    suggestions = offer_next_steps(from_snapshot({}), limit=3)
    assert len(suggestions) <= 3


def test_offer_next_steps_rationale_mentions_module() -> None:
    suggestions = offer_next_steps(from_snapshot({}), limit=10)
    for s in suggestions:
        assert s.module in s.rationale, (
            f"rationale should mention module name: {s.rationale!r}"
        )


# ---------------------------------------------------------------------------
# explain_chain
# ---------------------------------------------------------------------------


def test_explain_chain_empty_returns_empty_chain_message() -> None:
    explanation = explain_chain(from_snapshot({}))
    assert isinstance(explanation, ChainExplanation)
    assert explanation.produced_types == ()
    assert explanation.unused_emissions == ()
    assert "Empty chain" in explanation.narrative


def test_explain_chain_lists_produced_types() -> None:
    state = ChainState(produced_types=frozenset({"host", "credential"}))
    explanation = explain_chain(state)
    assert explanation.produced_types == ("credential", "host")
    assert "host" in explanation.narrative
    assert "credential" in explanation.narrative


def test_explain_chain_flags_dangling_emissions() -> None:
    """A type produced upstream that no registered module consumes
    should appear in ``unused_emissions``."""

    # detection_context is produced by intelligence / reconnaissance /
    # impact / etc. but no registry module consumes it - it's a
    # report-layer terminator type. So a chain emitting only
    # detection_context should flag it as a dangling producer.
    state = ChainState(produced_types=frozenset({"detection_context"}))
    explanation = explain_chain(state)
    assert "detection_context" in explanation.unused_emissions
    assert "Dangling producer" in explanation.narrative


def test_explain_chain_surfaces_runtime_warnings() -> None:
    state = ChainState(
        produced_types=frozenset({"host"}),
        warnings=(
            {"step_id": "exfil-1", "module": "exfiltration", "missing_type": "host"},
        ),
    )
    explanation = explain_chain(state)
    assert "exfiltration" in explanation.narrative
    assert explanation.unsatisfied_warnings == state.warnings


# ---------------------------------------------------------------------------
# suggest_scenario_variants
# ---------------------------------------------------------------------------


def test_suggest_scenario_variants_zero_count_returns_empty() -> None:
    assert (
        suggest_scenario_variants(
            [{"module": "command_control", "params": {"channel": "http"}}],
            count=0,
        )
        == []
    )


def test_suggest_scenario_variants_empty_steps_returns_empty() -> None:
    assert suggest_scenario_variants([], count=5) == []


def test_suggest_scenario_variants_is_deterministic_with_seed() -> None:
    steps = [
        {"step_id": "s1", "module": "command_control", "params": {"channel": "http"}},
        {"step_id": "s2", "module": "exfiltration", "params": {"method": "via_c2"}},
    ]
    a = suggest_scenario_variants(steps, count=3, seed=42)
    b = suggest_scenario_variants(steps, count=3, seed=42)
    assert a == b


def test_suggest_scenario_variants_records_mutation_history() -> None:
    """Each variant should carry a ``mutation_history`` entry on the
    swapped step, so the report can show the swap trail."""

    steps = [
        {"step_id": "s1", "module": "command_control", "params": {"channel": "http"}},
        {"step_id": "s2", "module": "exfiltration", "params": {"method": "via_c2"}},
    ]
    variants = suggest_scenario_variants(steps, count=3, seed=42)
    assert len(variants) == 3
    for var in variants:
        any_history = False
        for step in var:
            history = step.get("params", {}).get("mutation_history")
            if history:
                any_history = True
                # Each entry has the four canonical fields.
                entry = history[-1]
                assert entry.get("param_key")
                assert entry.get("from_value") is not None
                assert entry.get("to_value")
                assert entry.get("rationale")
                break
        assert any_history, "variant has no mutation_history entry"


def test_suggest_scenario_variants_does_not_mutate_input() -> None:
    """The original step dicts must remain untouched after generating
    variants."""

    steps = [
        {"step_id": "s1", "module": "command_control", "params": {"channel": "http"}},
    ]
    suggest_scenario_variants(steps, count=2, seed=0)
    assert steps[0]["params"] == {"channel": "http"}
    assert "mutation_history" not in steps[0]["params"]


def test_suggest_scenario_variants_handles_steps_with_no_catalog_slot() -> None:
    """A scenario whose every step has no catalog slot should still
    return ``count`` variants - just unmutated copies."""

    steps = [{"step_id": "s1", "module": "definitely-not-real", "params": {}}]
    variants = suggest_scenario_variants(steps, count=2, seed=0)
    assert len(variants) == 2
    # No mutation_history because no mutation was applied.
    for var in variants:
        for step in var:
            assert "mutation_history" not in step.get("params", {})


def test_suggest_scenario_variants_emits_distinct_mutations() -> None:
    """Each variant the function emits must apply a UNIQUE
    ``(step_index, param_key, to_value)`` mutation. Without dedup,
    two random rolls could pick the same swap and produce
    byte-identical variants -- callers asking for ``count=3``
    different variants would silently get duplicate runs."""

    steps = [
        {"step_id": "s1", "module": "command_control", "params": {"channel": "http"}},
    ]
    variants = suggest_scenario_variants(steps, count=5, seed=0)
    # Project each variant onto its applied mutation key for equality.
    keys = []
    for var in variants:
        history = var[0]["params"].get("mutation_history", [])
        assert history, "every variant must record exactly one mutation"
        # The single mutation entry: (step_idx=0, param_key, to_value).
        entry = history[0]
        keys.append((entry["param_key"], entry["to_value"]))
    # All keys distinct.
    assert len(set(keys)) == len(keys), (
        f"variants are not deduplicated; saw duplicate mutation keys: "
        f"{keys}"
    )


def test_suggest_scenario_variants_stops_when_catalog_exhausted() -> None:
    """When the catalog has fewer distinct mutations than ``count``,
    the function emits as many unique variants as it can and stops --
    rather than re-emitting duplicates to fill the count.

    ``command_control.channel`` catalog has 11 entries; against a
    starting value of ``http`` there are 10 distinct alternatives.
    Asking for 50 variants should return at most 10."""

    steps = [
        {"step_id": "s1", "module": "command_control", "params": {"channel": "http"}},
    ]
    variants = suggest_scenario_variants(steps, count=50, seed=0)
    # Should be at most the catalog size minus the current value.
    assert len(variants) <= 10
    assert len(variants) >= 1
    # All the variants must still be distinct.
    keys = []
    for var in variants:
        history = var[0]["params"].get("mutation_history", [])
        assert history
        keys.append((history[0]["param_key"], history[0]["to_value"]))
    assert len(set(keys)) == len(keys)


# ---------------------------------------------------------------------------
# Codex follow-up fixes
# ---------------------------------------------------------------------------


def test_offer_next_steps_partial_fit_outranks_chain_entry() -> None:
    """Codex P1 on PR #156: rank tier must dominate score. A
    chain_entry module that emits many new typed rows could not
    outrank a partial_fit module via score inflation. The
    "extension over restart" invariant requires explicit tier-first
    sorting."""

    registry = build_runtime_modules()
    chain = ChainContext()
    chain.record_step(
        step_id="rd-1",
        module="resource_development",
        contract=registry["resource_development"].io_contract,
        artifacts={"resource_type": "domain", "kind": "domain"},
    )
    state = from_snapshot(chain.snapshot())
    suggestions = offer_next_steps(state, registry=registry, limit=20)
    rank_order = [s.rank for s in suggestions]
    if "chain_entry" in rank_order and "partial_fit" in rank_order:
        first_partial = rank_order.index("partial_fit")
        first_entry = rank_order.index("chain_entry")
        assert first_partial < first_entry, (
            "partial_fit must outrank chain_entry; got order: "
            f"{[(s.module, s.rank, s.score) for s in suggestions]}"
        )
    if "chain_entry" in rank_order and "good_fit" in rank_order:
        first_good = rank_order.index("good_fit")
        first_entry = rank_order.index("chain_entry")
        assert first_good < first_entry


def test_offer_next_steps_perfect_fit_outranks_good_fit() -> None:
    """Tier ordering: perfect_fit first, then good_fit, then
    partial_fit, then chain_entry. Pin the ordering invariant."""

    registry = build_runtime_modules()
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=registry["discovery"].io_contract,
        artifacts={
            "discovery_type": "host_discovery",
            "targets": ["10.0.0.5"],
            "discovered": [],
        },
    )
    chain.record_step(
        step_id="cred-1",
        module="credential_access",
        contract=registry["credential_access"].io_contract,
        artifacts={"technique": "lsass_dump", "target": "10.0.0.5", "credential": "x"},
    )
    state = from_snapshot(chain.snapshot())
    suggestions = offer_next_steps(state, registry=registry, limit=20)
    seen_ranks: List[str] = []
    for s in suggestions:
        if s.rank not in seen_ranks:
            seen_ranks.append(s.rank)
    expected_partial_order = ["perfect_fit", "good_fit", "partial_fit", "chain_entry"]
    expected_subseq = [r for r in expected_partial_order if r in seen_ranks]
    assert seen_ranks == expected_subseq, (
        f"rank tier ordering broken: {seen_ranks}"
    )


def test_suggest_scenario_variants_does_deep_copy_nested_params() -> None:
    """Codex P2 on PR #156: a shallow ``dict(step)`` left nested
    ``params`` dicts shared across variants and the input scenario.
    Mutating one variant's params would leak into the input and
    sibling variants. Pin that nested params dicts are independent
    after variant generation."""

    steps = [
        {
            "step_id": "s1",
            "module": "command_control",
            "params": {"channel": "http", "extras": {"flag": True}},
        },
        {
            "step_id": "s2",
            "module": "exfiltration",
            "params": {"method": "via_c2", "extras": {"flag": True}},
        },
    ]
    variants = suggest_scenario_variants(steps, count=3, seed=7)
    variants[0][0]["params"]["extras"]["flag"] = False
    assert steps[0]["params"]["extras"]["flag"] is True, (
        "input scenario step's nested params got mutated through variant"
    )
    for other_variant in variants[1:]:
        assert other_variant[0]["params"]["extras"]["flag"] is True, (
            "sibling variant's nested params got mutated through another variant"
        )


# ---------------------------------------------------------------------------
# Integration: planner reads ChainContext snapshot end-to-end
# ---------------------------------------------------------------------------


def test_planner_consumes_chaincontext_snapshot_directly() -> None:
    """The planner accepts either a ChainState or a snapshot dict; the
    snapshot path is the same shape ``ChainContext.snapshot()``
    returns, so the runtime can hand the snapshot straight into the
    planner without reshaping."""

    registry = build_runtime_modules()
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=registry["discovery"].io_contract,
        artifacts={"discovery_type": "host_discovery", "targets": ["lab-host"], "discovered": []},
    )
    snapshot = chain.snapshot()
    suggestions = offer_next_steps(snapshot, registry=registry, limit=10)
    assert suggestions
    explanation = explain_chain(snapshot, registry=registry)
    assert "host" in explanation.produced_types


# ---------------------------------------------------------------------------
# Module-reuse penalty (diversity bonus)
# ---------------------------------------------------------------------------


def test_from_snapshot_collects_modules_used_from_artifact_rows() -> None:
    """``modules_used`` is derived by walking ``artifacts_by_step``
    and collecting each artifact row's ``module`` field. Pin the
    derivation so a future change to the snapshot shape doesn't
    silently empty the set."""

    registry = build_runtime_modules()
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=registry["discovery"].io_contract,
        artifacts={
            "discovery_type": "host_discovery",
            "targets": ["10.0.0.5"],
            "discovered": [],
        },
    )
    state = from_snapshot(chain.snapshot())
    assert "discovery" in state.modules_used


def test_from_snapshot_modules_used_empty_for_legacy_snapshot() -> None:
    """A snapshot that omits ``artifacts_by_step`` entirely (or has
    rows without a ``module`` field) yields an empty ``modules_used``
    set. The planner then falls back to the legacy "no diversity
    bonus" behaviour."""

    state = from_snapshot({"artifacts_by_type": {"host": []}})
    assert state.modules_used == frozenset()


def test_offer_next_steps_applies_reuse_penalty_to_modules_in_chain() -> None:
    """A candidate module that already appears in the chain receives
    a small score reduction. Two modules with otherwise-identical
    chain-fit should sort with the not-yet-used module first.

    Concrete scenario: a chain that has run discovery + recorded
    only host artifacts. Both ``discovery`` (already in chain) and
    ``credential_access`` (not in chain) are candidates that
    consume / interact with the produced ``host`` type. The penalty
    pushes ``credential_access`` ahead of ``discovery`` where the
    score difference was previously a tie."""

    registry = build_runtime_modules()
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=registry["discovery"].io_contract,
        artifacts={
            "discovery_type": "host_discovery",
            "targets": ["10.0.0.5"],
            "discovered": [],
        },
    )
    state = from_snapshot(chain.snapshot())
    suggestions = offer_next_steps(state, registry=registry, limit=20)
    by_module = {s.module: s for s in suggestions}
    assert "discovery" in by_module
    assert "credential_access" in by_module
    cred_idx = next(
        i for i, s in enumerate(suggestions) if s.module == "credential_access"
    )
    disc_idx = next(
        i for i, s in enumerate(suggestions) if s.module == "discovery"
    )
    assert cred_idx < disc_idx, (
        "credential_access should outrank discovery -- the re-use "
        f"penalty pushes already-used modules down the list. Got: "
        f"{[(s.module, s.score) for s in suggestions[:5]]}"
    )


def test_offer_next_steps_reuse_penalty_does_not_remove_candidates() -> None:
    """The re-use penalty is a small score reduction, not a hard
    filter. A module already in the chain still appears in the
    recommendations -- the operator may legitimately re-run it with
    a different technique (e.g. discovery host_discovery then
    discovery user_info)."""

    registry = build_runtime_modules()
    chain = ChainContext()
    chain.record_step(
        step_id="disc-1",
        module="discovery",
        contract=registry["discovery"].io_contract,
        artifacts={
            "discovery_type": "host_discovery",
            "targets": ["10.0.0.5"],
            "discovered": [],
        },
    )
    state = from_snapshot(chain.snapshot())
    suggestions = offer_next_steps(state, registry=registry, limit=30)
    modules = {s.module for s in suggestions}
    assert "discovery" in modules
