"""Static scenario chain graph computation.

The orchestrator's :class:`ChainContext` records typed propagation at
**runtime** — once a step has executed, the runtime indexes its
artifacts under the canonical artifact-type vocabulary so downstream
consumers can look up "the latest credential", "the most recent host",
etc. The runtime view is precise but only exists post-execution; an
operator who is *planning* a chain (deciding whether to deepen
``fin7_initial_access_to_c2``, picking the next module to slot into
``apt29_credential_access``, reviewing whether
``healthcare_ransomware`` actually wires up its lateral pivot) needs
the same view BEFORE running anything.

This module computes that **static** view from a scenario YAML alone.
It walks each step, looks up the registered module's
:class:`CapabilityIOContract`, and produces:

- :class:`ChainGraphNode` per step (module, IO contract surface,
  per-step objective);
- :class:`ChainGraphEdge` per typed propagation between two steps
  (explicit ``*_from_step`` references in scenario YAML, plus
  implicit contract-derived flows when a consumer's required slot
  has an earlier matching producer);
- :class:`ChainGraphWarning` rows for coverage gaps the graph
  detects (a required input the chain doesn't satisfy, a produced
  artifact no later step consumes, and a high-value subset of the
  unused-emission case for chain types like ``c2_endpoint`` and
  ``credential`` that defenders care most about).

The module is **deterministic** — same scenario plus same registry
returns the same graph, byte for byte. It does NOT execute modules,
write scenario YAML, or contact any remote service. It is the
foundation for:

- the operator console's chain-graph view (Priority 2 in the
  current handoff backlog);
- the manifest's static ``chain.graph`` block (so post-run
  bundles ship the predicted-vs-actual chain shape);
- the scenario planner's gap-detection narrative (a "we will run
  exfiltration but no upstream step produces a credential"
  finding the planner can surface during chain authoring).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .modules import build_runtime_modules
from .modules.contracts import (
    ArtifactSpec,
    CapabilityIOContract,
    is_meaningful_contract,
)


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ChainGraphNode:
    """A single step in the scenario chain graph.

    ``produces`` / ``consumes`` / ``required_consumes`` are the
    canonical artifact-type sets the registered module declares,
    NOT the runtime-emitted artifacts (which only exist post-run).
    ``objective`` is the per-step ``objective:`` line from the
    scenario YAML when present, else the empty string.
    """

    step_id: str
    step_index: int
    step_name: str
    module: str
    objective: str
    produces: Tuple[str, ...]
    consumes: Tuple[str, ...]
    required_consumes: Tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ChainGraphEdge:
    """A typed propagation edge between two scenario steps.

    ``explicit`` is ``True`` when the scenario YAML has a
    ``*_from_step`` parameter binding the consumer to an upstream
    producer (the high-fidelity case — defenders see this in the
    runtime manifest as a propagation edge). ``explicit`` is
    ``False`` when the edge is inferred from the consumer's
    contract: an earlier step produces a type the consumer
    declares as a consumed slot.

    ``source_key`` is the producer's :class:`ArtifactSpec.key`
    (best guess — empty when the producer's contract has no spec
    matching the artifact type, e.g. for legacy adapters).
    ``target_key`` is the consumer's slot key (``target`` /
    ``source`` / ``c2_endpoint`` for the explicit axes; the
    consumer's spec key for implicit edges).
    """

    source_step_id: str
    target_step_id: str
    artifact_type: str
    source_key: str
    target_key: str
    explicit: bool
    required: bool


@dataclass(frozen=True, slots=True)
class ChainGraphWarning:
    """A coverage-gap finding the static graph surfaced.

    Severities:

    - ``missing_required`` — a consumer step has a required
      consumed slot AND no upstream step (explicit or implicit)
      satisfies that type. The chain would record a runtime
      warning when actually executed.
    - ``unused_emission`` — a producer step emits a typed artifact
      AND no downstream step consumes it. Defenders may still
      pivot from the artifact in their telemetry, but the chain
      graph treats it as a dangling producer.
    - ``high_value_unused`` — the ``unused_emission`` case for
      types that materially shape the intrusion chain
      (``c2_endpoint``, ``credential``, ``exfil_package``,
      ``staged_file``, ``impact_target``). Surfaced separately
      so the operator console can highlight the gap.

    ``step_id`` is the step the warning attaches to: the consumer
    for ``missing_required``, the producer for ``unused_emission``
    / ``high_value_unused``.
    """

    severity: str
    step_id: str
    artifact_type: str
    message: str


@dataclass(frozen=True, slots=True)
class ChainGraph:
    """The full static graph for a scenario."""

    nodes: Tuple[ChainGraphNode, ...]
    edges: Tuple[ChainGraphEdge, ...]
    warnings: Tuple[ChainGraphWarning, ...]

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict view of the full graph.

        Used by callers that embed the graph in the run manifest or
        ship it to the operator console renderer. The shape is
        deterministic (sorted edges + sorted warnings) so two builds
        of the same scenario produce byte-identical output.
        """

        return {
            "nodes": [_node_to_dict(node) for node in self.nodes],
            "edges": [_edge_to_dict(edge) for edge in self.edges],
            "warnings": [_warning_to_dict(warning) for warning in self.warnings],
        }


# ---------------------------------------------------------------------------
# Public construction surface
# ---------------------------------------------------------------------------


# (param_key, consumer_slot_key, default_artifact_type) — the three
# explicit propagation axes the runtime understands today. Adding a new
# axis here expands the static graph to recognise it; the runtime side
# already lives in ``standard_modules.py`` (``resolve_target_from_step``)
# and the manifest side in ``reporting/manifest.py``
# (``_PROPAGATION_NARRATIVE_TEMPLATES``).
_FROM_STEP_AXES: Tuple[Tuple[str, str, str], ...] = (
    ("target_from_step", "target", "host"),
    ("source_from_step", "source", "host"),
    ("c2_endpoint_from_step", "c2_endpoint", "c2_endpoint"),
)


# Artifact types defenders care most about when an upstream step
# produces them but no downstream step consumes them. Surfaced as a
# separate ``high_value_unused`` warning so the operator console can
# render the gap with extra emphasis.
_HIGH_VALUE_TYPES: frozenset = frozenset(
    {
        "c2_endpoint",
        "credential",
        "exfil_package",
        "impact_target",
        "staged_file",
        "token",
    }
)


def build_scenario_graph(
    steps: Sequence[Any],
    *,
    registry: Optional[Mapping[str, Any]] = None,
) -> ChainGraph:
    """Compute the static chain graph for a scenario step sequence.

    Each ``step`` may be either:

    - a mapping with ``step_id`` (or ``id``) / ``module`` / ``params``
      / ``objective`` / ``name`` keys (the orchestrator's per-step
      result shape, the manifest's per-step entry shape);
    - a :class:`ScenarioStep` instance from
      :mod:`src.core.scenario` (duck-typed via attribute access).

    The optional ``registry`` argument lets tests inject a stand-in
    module set; the default uses :func:`build_runtime_modules`. When
    a step's module is not in the registry, the resulting node has
    empty ``produces`` / ``consumes`` tuples and the graph treats
    the step as a chain-neutral pass-through (no edges, no
    warnings tied to its contract surface).

    The returned :class:`ChainGraph` is deterministic: edges are
    sorted by source step index, then target step index, then
    artifact type, then explicit-before-implicit, then target key.
    Warnings are sorted by severity, then step index, then type.
    """

    registry_map: Mapping[str, Any] = (
        registry if registry is not None else build_runtime_modules()
    )

    # Phase 1: build the node list.
    nodes: List[ChainGraphNode] = []
    contracts: List[Optional[CapabilityIOContract]] = []
    # Per-step list of producer specs the planner expects this step to
    # emit at runtime — i.e. specs whose ``produced_if`` discriminator
    # passes against the scenario step's params, plus every spec that
    # has no discriminator. Used for both the node's ``produces`` tuple
    # and the downstream implicit-edge pass.
    producing_specs: List[Tuple[ArtifactSpec, ...]] = []
    for index, raw_step in enumerate(steps):
        step_id, module, params, objective, name = _coerce_step(raw_step, index)
        module_obj = registry_map.get(module)
        contract = _resolve_contract(module_obj)
        contracts.append(contract)
        active = _active_produced_specs(contract, params)
        producing_specs.append(active)
        produces_types = tuple(sorted({spec.type for spec in active}))
        consumes_types = _consumed_types(contract)
        required_types = _required_consumed_types(contract)
        nodes.append(
            ChainGraphNode(
                step_id=step_id,
                step_index=index,
                step_name=name,
                module=module,
                objective=objective,
                produces=produces_types,
                consumes=consumes_types,
                required_consumes=required_types,
            )
        )

    step_index_by_id: Dict[str, int] = {}
    for node in nodes:
        step_index_by_id.setdefault(node.step_id, node.step_index)

    # Phase 2: walk steps in order, build edges, accumulate warnings.
    edges: List[ChainGraphEdge] = []
    warnings: List[ChainGraphWarning] = []
    # type → list of (step_index, step_id, source_key) producers seen so far.
    produced_so_far: Dict[str, List[Tuple[int, str, str]]] = {}
    # Per-step: ``(target_step_index, artifact_type, target_key)`` triples
    # already covered by explicit edges, so the implicit pass doesn't
    # double-count for the same slot. The triple-keying matters for
    # consumers like ``lateral_movement`` that declare two slots of the
    # same type (``target`` and ``source`` both = host); without
    # ``target_key`` in the key, an explicit ``target_from_step`` would
    # silently mask the implicit fallback for ``source`` and the graph
    # would under-count host edges.
    explicit_covered: set = set()

    for index, raw_step in enumerate(steps):
        step_id, module, params, _objective, _name = _coerce_step(raw_step, index)
        contract = contracts[index]

        # 2a. Explicit ``*_from_step`` references in the scenario YAML.
        for param_key, consumer_slot, default_type in _FROM_STEP_AXES:
            raw_source = params.get(param_key)
            if not raw_source:
                continue
            source_step_id = str(raw_source)
            source_index = step_index_by_id.get(source_step_id)
            if source_index is None or source_index >= index:
                # Forward reference (impossible at runtime) or unknown
                # source id — surface a warning, do not add an edge.
                warnings.append(
                    ChainGraphWarning(
                        severity="missing_required",
                        step_id=step_id,
                        artifact_type=default_type,
                        message=(
                            f"{module}: explicit {param_key}={source_step_id!r} "
                            f"does not point at any earlier step"
                        ),
                    )
                )
                continue

            slot_type, slot_required = _consumer_slot_type(
                contract, consumer_slot, default_type
            )
            source_key = _producer_source_key(contracts[source_index], slot_type)
            edges.append(
                ChainGraphEdge(
                    source_step_id=source_step_id,
                    target_step_id=step_id,
                    artifact_type=slot_type,
                    source_key=source_key,
                    target_key=consumer_slot,
                    explicit=True,
                    required=slot_required,
                )
            )
            explicit_covered.add((index, slot_type, consumer_slot))

        # 2b. Implicit edges for declared consumed types not covered.
        if contract is not None and is_meaningful_contract(contract):
            for spec in contract.consumes:
                if (index, spec.type, spec.key) in explicit_covered:
                    continue
                # Inline-satisfied slots: a scenario step that writes
                # ``target: lab-host`` directly in its params doesn't
                # need an upstream producer. The runtime reads the
                # inline value; the chain graph treats the slot as
                # satisfied so it neither emits a phantom implicit
                # edge (which would mislead defenders into believing
                # the value flowed from a chain step) nor a
                # ``missing_required`` warning. This matches the
                # runtime behaviour of every standard module's
                # ``resolve_target_from_step`` fallback.
                if _slot_set_inline(params, spec.key):
                    continue
                producers = produced_so_far.get(spec.type)
                if producers:
                    src_index, src_id, src_key = producers[-1]
                    edges.append(
                        ChainGraphEdge(
                            source_step_id=src_id,
                            target_step_id=step_id,
                            artifact_type=spec.type,
                            source_key=src_key,
                            target_key=spec.key,
                            explicit=False,
                            required=bool(spec.required),
                        )
                    )
                elif spec.required:
                    warnings.append(
                        ChainGraphWarning(
                            severity="missing_required",
                            step_id=step_id,
                            artifact_type=spec.type,
                            message=(
                                f"{module}: required {spec.type} input "
                                f"({spec.key or 'unnamed slot'}) has no upstream producer"
                            ),
                        )
                    )

        # 2c. Index this step's emissions for downstream consumers.
        # Walk only the discriminator-active specs so a discovery step
        # with ``discovery_type: files`` indexes only ``file`` (not also
        # ``host``, ``service``, ``share``, ``user``, ``impact_target``).
        # Without the discriminator gate, a single discovery step would
        # appear to satisfy seven different downstream consumer types,
        # masking real coverage gaps with phantom propagation.
        for spec in producing_specs[index]:
            produced_so_far.setdefault(spec.type, []).append(
                (index, step_id, spec.key)
            )

    # Phase 3: dangling-producer warnings — types produced upstream that
    # no edge in the graph consumes.
    consumed_sources: Dict[str, set] = {}
    for edge in edges:
        src_index = step_index_by_id.get(edge.source_step_id)
        if src_index is not None:
            consumed_sources.setdefault(edge.artifact_type, set()).add(src_index)

    for artifact_type, producers in produced_so_far.items():
        consumed = consumed_sources.get(artifact_type, set())
        for src_index, src_id, _src_key in producers:
            if src_index in consumed:
                continue
            severity = (
                "high_value_unused"
                if artifact_type in _HIGH_VALUE_TYPES
                else "unused_emission"
            )
            module_name = nodes[src_index].module if src_index < len(nodes) else "?"
            warnings.append(
                ChainGraphWarning(
                    severity=severity,
                    step_id=src_id,
                    artifact_type=artifact_type,
                    message=(
                        f"{module_name}: produced {artifact_type} but "
                        f"no downstream step consumes it"
                    ),
                )
            )

    # Phase 4: deterministic ordering.
    edges.sort(
        key=lambda e: (
            step_index_by_id.get(e.source_step_id, 99999),
            step_index_by_id.get(e.target_step_id, 99999),
            e.artifact_type,
            0 if e.explicit else 1,
            e.target_key,
        )
    )
    _SEVERITY_ORDER: Dict[str, int] = {
        "missing_required": 0,
        "high_value_unused": 1,
        "unused_emission": 2,
    }
    warnings.sort(
        key=lambda w: (
            _SEVERITY_ORDER.get(w.severity, 99),
            step_index_by_id.get(w.step_id, 99999),
            w.artifact_type,
            w.message,
        )
    )

    return ChainGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        warnings=tuple(warnings),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_step(
    step: Any, fallback_index: int
) -> Tuple[str, str, Mapping[str, Any], str, str]:
    """Extract ``(step_id, module, params, objective, name)`` from any step shape.

    Accepts either a mapping (the orchestrator's per-step result dict
    or the manifest's per-step entry) or a :class:`ScenarioStep`-like
    object exposing the same attributes via getattr.
    """

    if isinstance(step, Mapping):
        step_id = str(step.get("step_id") or step.get("id") or f"step-{fallback_index + 1}")
        module = str(step.get("module") or "")
        raw_params = step.get("params") or step.get("operation") or {}
        params = raw_params if isinstance(raw_params, Mapping) else {}
        objective = str(step.get("objective") or "").strip()
        name = str(step.get("name") or step_id)
        return step_id, module, params, objective, name
    step_id = str(getattr(step, "step_id", "") or f"step-{fallback_index + 1}")
    module = str(getattr(step, "module", "") or "")
    raw_params = getattr(step, "params", None)
    params = raw_params if isinstance(raw_params, Mapping) else {}
    objective = str(getattr(step, "objective", "") or "").strip()
    name = str(getattr(step, "name", "") or step_id)
    return step_id, module, params, objective, name


def _resolve_contract(module_obj: Any) -> Optional[CapabilityIOContract]:
    """Return the module's :class:`CapabilityIOContract` or ``None``.

    Modules opting out via ``not_applicable=True`` return their own
    contract object (so the planner can surface the opt-out reason);
    modules without any contract attribute return ``None``.
    """

    if module_obj is None:
        return None
    contract = getattr(module_obj, "io_contract", None)
    if contract is None:
        return None
    if not isinstance(contract, CapabilityIOContract):
        return None
    return contract


def _active_produced_specs(
    contract: Optional[CapabilityIOContract],
    params: Mapping[str, Any],
) -> Tuple[ArtifactSpec, ...]:
    """Return only the produced specs whose discriminator passes against ``params``.

    Mirrors the runtime gate in :func:`src.core.modules.chain._spec_applies_to_run`
    (which evaluates ``produced_if`` against the runtime artifacts dict).
    At planning time the artifacts dict doesn't exist yet, but the
    scenario step's ``params`` carries the same discriminator key
    (``discovery_type``, ``resource_type``, ``channel`` ...) that the
    runtime later echoes into artifacts, so the same gate works at
    plan time. Specs without ``produced_if`` are always active.
    """

    if contract is None or not is_meaningful_contract(contract):
        return ()
    active: List[ArtifactSpec] = []
    for spec in contract.produces:
        if _produced_if_matches(spec, params):
            active.append(spec)
    return tuple(active)


def _slot_set_inline(params: Mapping[str, Any], slot_key: str) -> bool:
    """Return ``True`` when a consumer slot has a non-empty inline value.

    A consumer that writes ``target: lab-host`` directly in its
    scenario params is satisfied without upstream propagation; the
    chain graph treats this as a self-contained slot and skips both
    the implicit edge and the ``missing_required`` warning.

    An empty key (the consumer's spec carries no ``key``) cannot be
    set inline by name, so falls through to the upstream producer
    pathway.
    """

    if not slot_key:
        return False
    value = params.get(slot_key)
    return value not in (None, "", [], {})


def _produced_if_matches(spec: ArtifactSpec, params: Mapping[str, Any]) -> bool:
    """Return ``True`` when a spec's ``produced_if`` predicate passes."""

    discriminator = getattr(spec, "produced_if", None)
    if discriminator is None:
        return True
    try:
        key, expected = discriminator
    except (TypeError, ValueError):
        return True
    actual = params.get(key)
    if isinstance(expected, (tuple, list, set, frozenset)):
        return actual in expected
    return actual == expected


def _consumed_types(contract: Optional[CapabilityIOContract]) -> Tuple[str, ...]:
    if contract is None or not is_meaningful_contract(contract):
        return ()
    return tuple(contract.consumed_types())


def _required_consumed_types(
    contract: Optional[CapabilityIOContract],
) -> Tuple[str, ...]:
    if contract is None or not is_meaningful_contract(contract):
        return ()
    return tuple(contract.required_consumed_types())


def _consumer_slot_type(
    contract: Optional[CapabilityIOContract],
    consumer_slot: str,
    default_type: str,
) -> Tuple[str, bool]:
    """Return ``(artifact_type, required)`` for the consumer's slot key.

    Falls back to ``(default_type, True)`` when the consumer module has
    no contract or the contract does not declare a spec with the
    matching ``key``. The default ``required=True`` matches the
    runtime semantic: the operator opted into propagation by writing a
    ``*_from_step`` reference in the scenario YAML.
    """

    if contract is None or not is_meaningful_contract(contract):
        return default_type, True
    for spec in contract.consumes:
        if spec.key == consumer_slot:
            return spec.type, bool(spec.required)
    return default_type, True


def _producer_source_key(
    contract: Optional[CapabilityIOContract], artifact_type: str
) -> str:
    """Return the producer spec key matching ``artifact_type`` (or "")."""

    if contract is None or not is_meaningful_contract(contract):
        return ""
    for spec in contract.produces:
        if spec.type == artifact_type:
            return spec.key or ""
    return ""


def _node_to_dict(node: ChainGraphNode) -> Dict[str, Any]:
    return {
        "step_id": node.step_id,
        "step_index": node.step_index,
        "step_name": node.step_name,
        "module": node.module,
        "objective": node.objective,
        "produces": list(node.produces),
        "consumes": list(node.consumes),
        "required_consumes": list(node.required_consumes),
    }


def _edge_to_dict(edge: ChainGraphEdge) -> Dict[str, Any]:
    return {
        "source_step_id": edge.source_step_id,
        "target_step_id": edge.target_step_id,
        "artifact_type": edge.artifact_type,
        "source_key": edge.source_key,
        "target_key": edge.target_key,
        "explicit": edge.explicit,
        "required": edge.required,
    }


def _warning_to_dict(warning: ChainGraphWarning) -> Dict[str, Any]:
    return {
        "severity": warning.severity,
        "step_id": warning.step_id,
        "artifact_type": warning.artifact_type,
        "message": warning.message,
    }


__all__ = [
    "ChainGraph",
    "ChainGraphEdge",
    "ChainGraphNode",
    "ChainGraphWarning",
    "build_scenario_graph",
]
