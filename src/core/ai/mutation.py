"""AI-assisted technique mutation helpers (lab-only, gated)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping


@dataclass
class MutationResult:
    original: Dict[str, Any]
    mutated: Dict[str, Any]
    rationale: str


def _apply_strategy_mutation(
    payload: Dict[str, Any],
    *,
    strategy: str,
    low_noise_jitter_key: str,
    low_noise_default: int,
    low_noise_increment: int,
    protocol_retry_default: int,
    protocol_retry_increment: int,
) -> str:
    """Apply shared mutation strategy behavior and return rationale."""
    if strategy in {"low_noise", "evasion-lite"}:
        if "command" in payload and isinstance(payload["command"], str):
            payload["command"] = payload["command"].replace("echo ", "printf ")
        payload[low_noise_jitter_key] = (
            int(payload.get(low_noise_jitter_key, low_noise_default)) + low_noise_increment
        )
        return "Applied low-noise command and timing mutation."
    if strategy in {"protocol_shift", "protocol-shift"}:
        if "protocol" in payload:
            protocol = str(payload["protocol"]).lower()
            mapping = {"http": "dns", "dns": "https", "https": "http"}
            payload["protocol"] = mapping.get(protocol, "dns")
        payload["retry_interval"] = (
            int(payload.get("retry_interval", protocol_retry_default)) + protocol_retry_increment
        )
        return "Shifted protocol and retry cadence."
    payload["variant_label"] = strategy
    return "Applied generic mutation marker."


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

    rationale = _apply_strategy_mutation(
        mutated,
        strategy=strategy,
        low_noise_jitter_key="sleep_jitter_seconds",
        low_noise_default=1,
        low_noise_increment=1,
        protocol_retry_default=15,
        protocol_retry_increment=5,
    )

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

    rationale = _apply_strategy_mutation(
        mutation,
        strategy=strategy,
        low_noise_jitter_key="jitter_ms",
        low_noise_default=250,
        low_noise_increment=150,
        protocol_retry_default=10,
        protocol_retry_increment=5,
    )

    mutation["mutation_applied"] = True
    return {
        "module": module_name,
        "run_id": run_id,
        "strategy": strategy,
        "base_params": base,
        "mutated_params": mutation,
        "rationale": rationale,
    }
