"""AI-assisted technique mutation helpers (lab-only, gated)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping


@dataclass
class MutationResult:
    original: Dict[str, Any]
    mutated: Dict[str, Any]
    rationale: str


def mutate_step_params(
    params: Mapping[str, Any],
    *,
    allowed: bool,
    strategy: str = "low_noise",
) -> MutationResult:
    """Mutate step parameters for evasion research under explicit lab-only opt-in."""
    original = dict(params)
    mutated = dict(params)

    if not allowed:
        return MutationResult(
            original=original,
            mutated=original,
            rationale="Mutation disabled (requires explicit lab-only opt-in).",
        )

    if strategy == "low_noise":
        # Reduce obvious signal by tweaking known noisy keys.
        if "command" in mutated and isinstance(mutated["command"], str):
            mutated["command"] = mutated["command"].replace("echo ", "printf ")
        mutated["sleep_jitter_seconds"] = int(mutated.get("sleep_jitter_seconds", 1)) + 1
        rationale = "Applied low-noise mutation to command and timing fields."
    elif strategy == "protocol_shift":
        if "protocol" in mutated:
            current = str(mutated["protocol"]).lower()
            mapping = {"http": "dns", "dns": "https", "https": "http"}
            mutated["protocol"] = mapping.get(current, "dns")
        mutated["retry_interval"] = int(mutated.get("retry_interval", 15)) + 5
        rationale = "Shifted protocol and retry cadence for variant generation."
    else:
        mutated["variant_label"] = strategy
        rationale = "Applied generic mutation marker."

    mutated["mutation_applied"] = True
    return MutationResult(original=original, mutated=mutated, rationale=rationale)


def mutate_steps(
    steps: Iterable[Mapping[str, Any]],
    *,
    allowed: bool,
    strategy: str = "low_noise",
) -> list[MutationResult]:
    """Mutate a sequence of step param mappings."""
    return [
        mutate_step_params(step, allowed=allowed, strategy=strategy)
        for step in steps
    ]


def mutate_technique(
    module_name: str,
    base_params: Mapping[str, Any],
    *,
    strategy: str = "evasion-lite",
    run_id: str = "unknown",
) -> Dict[str, Any]:
    """
    Generate a safe, lab-scoped mutation payload for technique research.

    Mutation logic is deterministic by design for repeatable experiments.
    """
    base = dict(base_params)
    mutation = dict(base)

    # Lab-only guardrails: force explicit acknowledgment and no real network touch.
    mutation["i_understand_this_is_a_lab"] = True
    mutation["network_touch"] = False
    mutation["dry_run_only"] = True

    if strategy == "evasion-lite":
        mutation["jitter_ms"] = int(mutation.get("jitter_ms", 250)) + 150
        if "command" in mutation and isinstance(mutation["command"], str):
            mutation["command"] = mutation["command"].replace("echo ", "printf ")
        rationale = "Applied low-noise command and jitter mutation."
    elif strategy == "protocol-shift":
        if "protocol" in mutation:
            protocol = str(mutation["protocol"]).lower()
            mapping = {"http": "dns", "dns": "https", "https": "http"}
            mutation["protocol"] = mapping.get(protocol, "dns")
        mutation["retry_interval"] = int(mutation.get("retry_interval", 10)) + 5
        rationale = "Shifted protocol and retry cadence."
    else:
        mutation["variant_label"] = strategy
        rationale = "Applied generic strategy label."

    mutation["mutation_applied"] = True
    return {
        "module": module_name,
        "run_id": run_id,
        "strategy": strategy,
        "base_params": base,
        "mutated_params": mutation,
        "rationale": rationale,
    }
