"""Base abstractions for pluggable BlueFire modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Mapping, Optional, Tuple

from ..models import ModuleResult
from .contracts import CapabilityIOContract


class BaseModule(ABC):
    """Common interface all orchestrated modules must implement.

    ``io_contract`` is a class-level attribute. Each concrete module
    declares the artifact types it consumes/produces using the
    capability IO contract vocabulary in :mod:`.contracts`. The
    chaining engine, scenario planner, AI orchestrator, and report
    surfaces all read this attribute; the registry contract test in
    ``tests/test_module_io_contracts.py`` enforces that every
    registered module either declares a meaningful contract or
    explicitly opts out via ``not_applicable=True``.
    """

    name: str = "base"
    attack_techniques: tuple[str, ...] = ()
    io_contract: CapabilityIOContract = CapabilityIOContract()

    def __init__(self) -> None:
        self._config: Dict[str, Any] = {}

    def update_config(self, config: Mapping[str, Any]) -> None:
        """Receive merged module configuration from orchestrator."""
        self._config = dict(config)

    def validate(self, params: Mapping[str, Any]) -> Optional[str]:
        """Return validation error text, or None when valid."""
        _ = params
        return None

    @abstractmethod
    def execute(self, params: Mapping[str, Any], context: Mapping[str, Any]) -> ModuleResult:
        """Run the module operation and return a structured result."""
        raise NotImplementedError


def resolve_target_from_step(
    params: Mapping[str, Any],
    context: Mapping[str, Any],
    *,
    fallback: str,
    param_key: str = "target",
    step_param_key: str = "target_from_step",
) -> Tuple[str, Optional[str]]:
    """Resolve a downstream module's target with optional upstream propagation.

    Returns ``(effective_target, propagated_from_step_id_or_None)``.

    Resolution order:

    1. **Explicit ``params[param_key]``** — wins. Always.
    2. **``params[step_param_key]``** — if set, look up
       ``context["previous_step_results"][<step_id>]["artifacts"]`` and
       pick a value: ``artifacts["target"]`` (single-target upstream
       modules) takes precedence, then the first entry of
       ``artifacts["targets"]`` (multi-target modules like discovery).
    3. **``fallback``** — when neither explicit nor propagated value
       resolves, the caller's documented default.

    Read-only: the helper never mutates ``previous_step_results`` and
    never auto-injects values into ``params``. Modules opt in by
    declaring ``step_param_key`` in their step YAML; the runtime never
    auto-wires anything.

    Returns ``propagated_from_step_id`` set only when the value came
    from an upstream step result, so callers can record the
    propagation in their artifacts / detection_hints / report output.
    """
    explicit = str(params.get(param_key) or "").strip()
    if explicit:
        return explicit, None

    step_id = str(params.get(step_param_key) or "").strip()
    if step_id:
        prior_results = context.get("previous_step_results")
        if isinstance(prior_results, Mapping):
            prior = prior_results.get(step_id)
            if isinstance(prior, Mapping):
                artifacts = prior.get("artifacts")
                if isinstance(artifacts, Mapping):
                    single = artifacts.get("target")
                    if isinstance(single, str) and single.strip():
                        return single.strip(), step_id
                    targets = artifacts.get("targets")
                    if isinstance(targets, list) and targets:
                        first = targets[0]
                        if isinstance(first, str) and first.strip():
                            return first.strip(), step_id

    return fallback, None
