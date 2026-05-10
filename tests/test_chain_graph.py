"""Static scenario chain graph — pinned behaviour.

The :mod:`src.core.chain_graph` module computes a node + edge view of
a scenario from its YAML alone (without execution): nodes are steps,
edges are typed propagation between producer and consumer steps, and
warnings flag coverage gaps. These tests pin:

- node shape (one per step, registered module's IO contract surfaced)
- explicit ``*_from_step`` edges from scenario YAML (``target_from_step``,
  ``source_from_step``, ``c2_endpoint_from_step``)
- implicit contract-derived edges when no explicit reference exists
  but a consumer's slot has an earlier matching producer
- warnings (``missing_required``, ``unused_emission``,
  ``high_value_unused``)
- determinism + JSON serialisability of the graph dict
- per-scenario explicit-edge counts for every tier-1 shipped
  scenario so a regression that drops a chain pair gets caught
  before runtime
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from src.core.chain_graph import (
    ChainGraph,
    ChainGraphEdge,
    ChainGraphNode,
    ChainGraphWarning,
    build_scenario_graph,
)
from src.core.modules import (
    ArtifactSpec,
    CapabilityIOContract,
    consumes,
    produces,
)
from src.core.modules.contracts import (
    C2_ENDPOINT,
    CREDENTIAL,
    EXFIL_PACKAGE,
    FILE,
    HOST,
    STAGED_FILE,
    USER,
)
from src.core.scenario import load_scenario


# ---------------------------------------------------------------------------
# Stub registry helpers (synthetic chain shapes for focused unit tests)
# ---------------------------------------------------------------------------


class _StubModule:
    """Bare-minimum module shape the chain graph reads.

    Only exposes ``io_contract`` because :func:`build_scenario_graph`
    looks the contract up via ``getattr(module, 'io_contract', None)``.
    """

    def __init__(self, contract: CapabilityIOContract) -> None:
        self.io_contract = contract


def _producer(*specs: ArtifactSpec) -> _StubModule:
    return _StubModule(CapabilityIOContract(produces=produces(*specs)))


def _consumer(*specs: ArtifactSpec) -> _StubModule:
    return _StubModule(CapabilityIOContract(consumes=consumes(*specs)))


def _producer_consumer(
    *,
    produces_specs: tuple = (),
    consumes_specs: tuple = (),
) -> _StubModule:
    return _StubModule(
        CapabilityIOContract(
            produces=produces(*produces_specs) if produces_specs else (),
            consumes=consumes(*consumes_specs) if consumes_specs else (),
        )
    )


def _step(
    step_id: str,
    module: str,
    params: Mapping[str, Any] | None = None,
    *,
    objective: str = "",
    name: str = "",
) -> dict:
    return {
        "step_id": step_id,
        "module": module,
        "params": dict(params or {}),
        "objective": objective,
        "name": name or step_id,
    }


# ---------------------------------------------------------------------------
# Empty / degenerate inputs
# ---------------------------------------------------------------------------


def test_empty_steps_yields_empty_graph() -> None:
    graph = build_scenario_graph([], registry={})
    assert graph.nodes == ()
    assert graph.edges == ()
    assert graph.warnings == ()


def test_unknown_module_is_chain_neutral_pass_through() -> None:
    """A step whose module isn't in the registry contributes a node
    with empty produces/consumes and no edges or warnings.

    This matters for legacy / experimental scenarios that reference
    modules an installation may not have loaded — the graph should
    still render the step instead of raising.
    """

    graph = build_scenario_graph(
        [_step("only-step", "no_such_module")],
        registry={},
    )
    assert len(graph.nodes) == 1
    assert graph.nodes[0].module == "no_such_module"
    assert graph.nodes[0].produces == ()
    assert graph.nodes[0].consumes == ()
    assert graph.edges == ()
    assert graph.warnings == ()


def test_unknown_module_with_from_step_reference_is_still_neutral() -> None:
    """An unknown module that carries an explicit ``*_from_step``
    reference must NOT synthesise a chain edge against axis defaults.

    Without this gate, a step like
    ``module: no_such_module`` + ``target_from_step: source-step``
    would produce a phantom host edge using fallback axis defaults,
    misleading defenders into thinking the chain propagated. The
    chain-neutral-pass-through behaviour extends to the explicit-
    axis pass too. (Codex P2 on PR #164.)
    """

    registry = {
        "discovery": _producer(
            ArtifactSpec(type=HOST, key="targets"),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("disc", "discovery"),
            _step(
                "unknown",
                "no_such_module",
                {"target_from_step": "disc"},
            ),
        ],
        registry=registry,
    )
    edges_to_unknown = [e for e in graph.edges if e.target_step_id == "unknown"]
    assert edges_to_unknown == []
    warnings_for_unknown = [w for w in graph.warnings if w.step_id == "unknown"]
    assert warnings_for_unknown == []


def test_inline_slot_check_aligns_with_runtime_truthiness_rules() -> None:
    """Runtime resolution uses ``str(params.get(key) or "").strip()``
    so falsy values (``False`` / ``0`` / empty list) fall through to
    the upstream propagation. The static graph must mirror that —
    treating ``target: false`` as inline-set would suppress the
    edge AND the warning even though runtime would propagate.
    (Codex P2 on PR #164.)
    """

    registry = {
        "discovery": _producer(
            ArtifactSpec(type=HOST, key="targets"),
        ),
        "credential_access": _consumer(
            ArtifactSpec(type=HOST, key="target"),
        ),
    }
    # Falsy-but-not-None values should NOT count as inline-set.
    for falsy_value in (False, 0, [], {}):
        graph = build_scenario_graph(
            [
                _step("disc", "discovery"),
                _step(
                    "creds",
                    "credential_access",
                    {
                        "target": falsy_value,
                        "target_from_step": "disc",
                    },
                ),
            ],
            registry=registry,
        )
        edges_to_creds = [e for e in graph.edges if e.target_step_id == "creds"]
        assert any(
            e.explicit and e.source_step_id == "disc" for e in edges_to_creds
        ), (
            f"target={falsy_value!r} suppressed the explicit edge — "
            f"should fall through to upstream propagation per runtime rules"
        )

    # Truthy values continue to suppress propagation.
    graph_truthy = build_scenario_graph(
        [
            _step("disc", "discovery"),
            _step(
                "creds",
                "credential_access",
                {
                    "target": "lab-host",
                    "target_from_step": "disc",
                },
            ),
        ],
        registry=registry,
    )
    edges_to_creds = [e for e in graph_truthy.edges if e.target_step_id == "creds"]
    assert edges_to_creds == []


# ---------------------------------------------------------------------------
# Node shape
# ---------------------------------------------------------------------------


def test_node_surfaces_contract_produces_consumes_required() -> None:
    registry = {
        "p": _producer(
            ArtifactSpec(type=HOST, key="targets", description="hosts"),
        ),
        "c": _consumer(
            ArtifactSpec(type=HOST, key="target"),
            ArtifactSpec(type=USER, key="user", required=False),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("p1", "p", objective="enumerate hosts"),
            _step("c1", "c"),
        ],
        registry=registry,
    )
    producer, consumer = graph.nodes
    assert producer.step_id == "p1"
    assert producer.step_index == 0
    assert producer.objective == "enumerate hosts"
    assert producer.produces == ("host",)
    assert producer.consumes == ()
    assert producer.required_consumes == ()
    assert consumer.consumes == ("host", "user")
    assert consumer.required_consumes == ("host",)


# ---------------------------------------------------------------------------
# Explicit *_from_step edges
# ---------------------------------------------------------------------------


def test_explicit_target_from_step_creates_explicit_edge() -> None:
    registry = {
        "discovery": _producer(
            ArtifactSpec(type=HOST, key="targets"),
        ),
        "credential_access": _consumer(
            ArtifactSpec(type=HOST, key="target"),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("disc", "discovery"),
            _step("creds", "credential_access", {"target_from_step": "disc"}),
        ],
        registry=registry,
    )
    explicit = [e for e in graph.edges if e.explicit]
    assert len(explicit) == 1
    edge = explicit[0]
    assert edge.source_step_id == "disc"
    assert edge.target_step_id == "creds"
    assert edge.artifact_type == "host"
    assert edge.target_key == "target"
    assert edge.required is True


def test_explicit_c2_endpoint_from_step_uses_contract_slot_key() -> None:
    """``c2_endpoint_from_step`` resolves to the consumer's actual
    contract slot key (``endpoint`` on command_control), not the axis
    hint (``c2_endpoint``).

    Without this resolution the dedup key in the implicit pass would
    not match the explicit-edge entry and a phantom duplicate edge
    would land for the same chain flow. Codex P1 on PR #164.
    """

    registry = {
        "resource_development": _producer(
            ArtifactSpec(type=C2_ENDPOINT, key="target"),
        ),
        "command_control": _consumer(
            ArtifactSpec(type=C2_ENDPOINT, key="endpoint", required=False),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("stage", "resource_development"),
            _step("c2", "command_control", {"c2_endpoint_from_step": "stage"}),
        ],
        registry=registry,
    )
    explicit = [e for e in graph.edges if e.explicit]
    assert len(explicit) == 1
    edge = explicit[0]
    assert edge.artifact_type == "c2_endpoint"
    # The actual contract slot key on command_control is ``endpoint``.
    assert edge.target_key == "endpoint"
    assert edge.source_key == "target"
    # The optional flag on the consumer's spec must propagate to the
    # edge — the contract spec is required=False, so the explicit
    # edge inherits required=False rather than the strict axis default.
    assert edge.required is False
    # And no implicit duplicate for the same flow lands (the dedup
    # set carries (index, c2_endpoint, endpoint), which the implicit
    # pass also reaches via spec.key=endpoint).
    assert len(graph.edges) == 1


def test_explicit_c2_endpoint_from_step_skipped_when_inline_c2_url_set() -> None:
    """When the consumer step writes ``c2_url: <inline>``, the runtime
    short-circuits the upstream walk (``resolve_target_from_step``
    returns the inline value before reading ``previous_step_results``).

    The static graph mirrors that precedence: emitting an explicit
    propagation edge would mislead the operator into believing the
    ``c2_endpoint_from_step`` propagation actually fired at runtime.
    Codex P1 on PR #164.
    """

    registry = {
        "resource_development": _producer(
            ArtifactSpec(type=C2_ENDPOINT, key="target"),
        ),
        "command_control": _consumer(
            ArtifactSpec(type=C2_ENDPOINT, key="endpoint", required=False),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("stage", "resource_development"),
            _step(
                "c2",
                "command_control",
                {
                    "c2_url": "https://attacker.example.invalid/inline",
                    "c2_endpoint_from_step": "stage",
                },
            ),
        ],
        registry=registry,
    )
    # No edge to ``c2``: the inline c2_url won, the propagation never
    # actually fires at runtime, the static view doesn't overstate it.
    edges_to_c2 = [e for e in graph.edges if e.target_step_id == "c2"]
    assert edges_to_c2 == []


def test_explicit_target_from_step_skipped_when_inline_target_set() -> None:
    """Symmetrical pin for the ``target_from_step`` axis: when the
    consumer step has ``target: lab-host`` inline, the runtime ignores
    the upstream propagation and the static graph must too."""

    registry = {
        "discovery": _producer(
            ArtifactSpec(type=HOST, key="targets"),
        ),
        "credential_access": _consumer(
            ArtifactSpec(type=HOST, key="target"),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("disc", "discovery"),
            _step(
                "creds",
                "credential_access",
                {
                    "target": "inline-host.example.lab",
                    "target_from_step": "disc",
                },
            ),
        ],
        registry=registry,
    )
    edges_to_creds = [e for e in graph.edges if e.target_step_id == "creds"]
    # Inline target wins → no explicit edge AND no implicit fallback
    # (the inline-slot check in the implicit pass also short-circuits).
    assert edges_to_creds == []


def test_explicit_source_from_step_skipped_when_inline_source_set() -> None:
    """Symmetrical pin for the ``source_from_step`` axis."""

    registry = {
        "creds": _producer(ArtifactSpec(type=HOST, key="target")),
        "lateral_movement": _consumer(
            ArtifactSpec(type=HOST, key="target"),
            ArtifactSpec(type=HOST, key="source", required=False),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("creds", "creds"),
            _step(
                "lat",
                "lateral_movement",
                {
                    "target": "remote-host",
                    "source": "attacker-host",
                    "target_from_step": "creds",
                    "source_from_step": "creds",
                },
            ),
        ],
        registry=registry,
    )
    edges_to_lat = [e for e in graph.edges if e.target_step_id == "lat"]
    assert edges_to_lat == []


def test_explicit_target_from_step_satisfies_polymorphic_required_slot() -> None:
    """A consumer with two ``key="target"`` specs of different types
    (e.g. ``impact`` declares ``impact_target/required`` AND
    ``host/optional`` for the same ``target`` slot) must NOT emit a
    ``missing_required`` warning when the explicit ``target_from_step``
    fires.

    The runtime resolves ``target_from_step`` polymorphically — the
    upstream's primary value lands in ``params.target`` regardless of
    its canonical type, and the consumer interprets it however its
    module logic needs. The static graph mirrors this by treating
    every spec sharing the resolved slot key as covered by the
    explicit edge, not just the type-matched one.

    Caught while addressing Codex P1 #2 against the
    ``enterprise_intrusion_chain`` ``ransomware-impact`` step.
    """

    registry = {
        "collection": _producer(
            ArtifactSpec(type=STAGED_FILE, key="staged_file"),
        ),
        "impact": _consumer(
            # Required impact_target sibling.
            ArtifactSpec(type="impact_target", key="target"),
            # Optional host alternate-interpretation sibling.
            ArtifactSpec(type=HOST, key="target", required=False),
            ArtifactSpec(type=STAGED_FILE, key="staged_file", required=False),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("stage", "collection"),
            _step(
                "impact",
                "impact",
                {"target_from_step": "stage"},
            ),
        ],
        registry=registry,
    )
    # The explicit edge resolves to the required impact_target sibling
    # (not the optional host sibling) because the resolver prefers
    # required-by-key matches.
    explicit = [e for e in graph.edges if e.explicit and e.target_step_id == "impact"]
    assert len(explicit) == 1
    assert explicit[0].artifact_type == "impact_target"
    assert explicit[0].target_key == "target"
    assert explicit[0].required is True

    # No phantom implicit edge for the host sibling — both share the
    # ``target`` slot so the explicit edge covers both.
    host_edges = [
        e
        for e in graph.edges
        if e.target_step_id == "impact" and e.artifact_type == "host"
    ]
    assert host_edges == []

    # And no missing_required warning for the impact_target slot.
    missing = [
        w for w in graph.warnings if w.severity == "missing_required" and w.step_id == "impact"
    ]
    assert missing == []

    # The staged_file slot is satisfied via implicit edge from the
    # upstream collection step (separate slot key).
    staged_edges = [
        e
        for e in graph.edges
        if e.target_step_id == "impact" and e.artifact_type == "staged_file"
    ]
    assert len(staged_edges) == 1
    assert staged_edges[0].explicit is False


def test_explicit_source_and_target_from_step_emit_two_edges_for_dual_host_consumer() -> None:
    """Lateral movement consumes ``target`` (host) AND ``source`` (host).

    A scenario that explicitly wires both must emit two edges, one per
    slot, even though both are the same artifact type. Without
    per-target-key dedup the second slot would get silently dropped.
    """

    registry = {
        "discovery": _producer(
            ArtifactSpec(type=HOST, key="targets"),
        ),
        "credential_access": _producer(
            ArtifactSpec(type=HOST, key="target"),  # source host re-emitted
        ),
        "lateral_movement": _consumer(
            ArtifactSpec(type=HOST, key="target"),
            ArtifactSpec(type=HOST, key="source", required=False),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("disc", "discovery"),
            _step("creds", "credential_access"),
            _step(
                "lat",
                "lateral_movement",
                {
                    "target_from_step": "disc",
                    "source_from_step": "creds",
                },
            ),
        ],
        registry=registry,
    )
    explicit = [e for e in graph.edges if e.explicit and e.target_step_id == "lat"]
    assert len(explicit) == 2
    edges_by_key = {e.target_key: e for e in explicit}
    assert edges_by_key["target"].source_step_id == "disc"
    assert edges_by_key["source"].source_step_id == "creds"
    assert edges_by_key["target"].artifact_type == "host"
    assert edges_by_key["source"].artifact_type == "host"


def test_forward_reference_in_from_step_emits_warning_no_edge() -> None:
    """``*_from_step`` pointing at a later step is impossible at runtime.

    The graph surfaces a ``missing_required`` warning instead of
    silently producing a forward edge.
    """

    registry = {
        "command_control": _consumer(
            ArtifactSpec(type=C2_ENDPOINT, key="endpoint", required=False),
        ),
        "resource_development": _producer(
            ArtifactSpec(type=C2_ENDPOINT, key="target"),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("c2", "command_control", {"c2_endpoint_from_step": "stage"}),
            _step("stage", "resource_development"),
        ],
        registry=registry,
    )
    assert all(not e.explicit or e.target_step_id != "c2" for e in graph.edges)
    missing = [w for w in graph.warnings if w.severity == "missing_required"]
    assert any("does not point at any earlier step" in w.message for w in missing)


# ---------------------------------------------------------------------------
# Implicit edges
# ---------------------------------------------------------------------------


def test_implicit_edge_when_consumer_has_no_explicit_from_step() -> None:
    """A consumer whose slot type matches an upstream producer gets
    an implicit edge even without ``*_from_step``."""

    registry = {
        "discovery": _producer(
            ArtifactSpec(type=HOST, key="targets"),
        ),
        "exfiltration": _consumer(
            ArtifactSpec(type=HOST, key="target"),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("disc", "discovery"),
            _step("exfil", "exfiltration"),  # no target_from_step
        ],
        registry=registry,
    )
    edges = [e for e in graph.edges if e.target_step_id == "exfil"]
    assert len(edges) == 1
    assert edges[0].explicit is False
    assert edges[0].source_step_id == "disc"
    assert edges[0].artifact_type == "host"


def test_explicit_edge_suppresses_redundant_implicit_for_same_slot() -> None:
    """When an explicit ``target_from_step`` already covers a slot,
    the implicit pass must not add a duplicate edge for the same
    ``(target_step, type, target_key)`` triple."""

    registry = {
        "discovery": _producer(
            ArtifactSpec(type=HOST, key="targets"),
        ),
        "extra": _producer(
            ArtifactSpec(type=HOST, key="target"),
        ),
        "credential_access": _consumer(
            ArtifactSpec(type=HOST, key="target"),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("disc", "discovery"),
            _step("extra", "extra"),
            _step("creds", "credential_access", {"target_from_step": "disc"}),
        ],
        registry=registry,
    )
    edges = [e for e in graph.edges if e.target_step_id == "creds"]
    # One explicit (disc → creds), zero implicit duplicates (extra is
    # later but the explicit reference already pins disc).
    assert len(edges) == 1
    assert edges[0].explicit is True
    assert edges[0].source_step_id == "disc"


# ---------------------------------------------------------------------------
# Warnings
# ---------------------------------------------------------------------------


def test_missing_required_warning_when_no_upstream_producer() -> None:
    registry = {
        "exfiltration": _consumer(
            ArtifactSpec(type=HOST, key="target"),
            ArtifactSpec(type=STAGED_FILE, key="staged_file", required=False),
        ),
    }
    graph = build_scenario_graph(
        [_step("exfil", "exfiltration")],
        registry=registry,
    )
    missing = [w for w in graph.warnings if w.severity == "missing_required"]
    assert len(missing) == 1
    assert missing[0].step_id == "exfil"
    assert missing[0].artifact_type == "host"


def test_optional_consumer_slot_does_not_emit_missing_required() -> None:
    """An optional slot has a documented default; a missing producer
    must not surface as a warning."""

    registry = {
        "anti_detection": _consumer(
            ArtifactSpec(type=HOST, key="target", required=False),
        ),
    }
    graph = build_scenario_graph(
        [_step("evade", "anti_detection")],
        registry=registry,
    )
    assert graph.warnings == ()


def test_high_value_unused_warning_for_dangling_credential() -> None:
    """A credential producer with no downstream consumer surfaces
    as ``high_value_unused`` so the operator console highlights it."""

    registry = {
        "credential_access": _producer(
            ArtifactSpec(type=CREDENTIAL, key="technique"),
        ),
    }
    graph = build_scenario_graph(
        [_step("creds", "credential_access")],
        registry=registry,
    )
    high_value = [w for w in graph.warnings if w.severity == "high_value_unused"]
    assert len(high_value) == 1
    assert high_value[0].artifact_type == "credential"


def test_unused_emission_warning_for_low_value_dangling_type() -> None:
    """A non-high-value emission (e.g. ``user``) surfaces as the
    plain ``unused_emission`` severity."""

    registry = {
        "discovery": _producer(
            ArtifactSpec(type=USER, key="targets"),
        ),
    }
    graph = build_scenario_graph(
        [_step("disc", "discovery")],
        registry=registry,
    )
    unused = [w for w in graph.warnings if w.severity == "unused_emission"]
    assert len(unused) == 1
    assert unused[0].artifact_type == "user"


# ---------------------------------------------------------------------------
# Discriminator-aware producing
# ---------------------------------------------------------------------------


def test_produced_if_discriminator_filters_node_produces() -> None:
    """A producer with discriminator-gated specs only emits the
    types the params actually trigger.

    Mirrors the runtime ``_spec_applies_to_run`` gate so a
    discovery step with ``discovery_type: files`` shows
    ``produces=('file',)`` not all six discriminated types.
    """

    registry = {
        "discovery": _producer(
            ArtifactSpec(
                type=HOST,
                key="targets",
                produced_if=("discovery_type", ("host_discovery",)),
            ),
            ArtifactSpec(
                type=FILE,
                key="targets",
                produced_if=("discovery_type", ("files",)),
            ),
        ),
    }
    graph = build_scenario_graph(
        [_step("disc", "discovery", {"discovery_type": "files"})],
        registry=registry,
    )
    assert graph.nodes[0].produces == ("file",)


def test_produced_if_discriminator_drives_implicit_edges() -> None:
    """When the producer's discriminator-gated spec is the only
    source of a consumed type, the implicit edge fires only for
    matching params."""

    registry = {
        "discovery": _producer(
            ArtifactSpec(
                type=HOST,
                key="targets",
                produced_if=("discovery_type", ("host_discovery",)),
            ),
        ),
        "exfiltration": _consumer(
            ArtifactSpec(type=HOST, key="target"),
        ),
    }
    # discovery_type=files: no host emission → exfil's required slot
    # is unsatisfied.
    graph_files = build_scenario_graph(
        [
            _step("disc", "discovery", {"discovery_type": "files"}),
            _step("exfil", "exfiltration"),
        ],
        registry=registry,
    )
    assert all(e.target_step_id != "exfil" for e in graph_files.edges)
    assert any(
        w.severity == "missing_required" and w.artifact_type == "host"
        for w in graph_files.warnings
    )

    # discovery_type=host_discovery: host emission → implicit edge.
    graph_host = build_scenario_graph(
        [
            _step("disc", "discovery", {"discovery_type": "host_discovery"}),
            _step("exfil", "exfiltration"),
        ],
        registry=registry,
    )
    edges = [e for e in graph_host.edges if e.target_step_id == "exfil"]
    assert len(edges) == 1
    assert edges[0].explicit is False
    assert edges[0].source_step_id == "disc"


# ---------------------------------------------------------------------------
# Determinism + serialisation
# ---------------------------------------------------------------------------


def test_graph_is_deterministic_across_repeated_builds() -> None:
    registry = {
        "p": _producer(ArtifactSpec(type=HOST, key="targets")),
        "c": _consumer(ArtifactSpec(type=HOST, key="target")),
    }
    steps = [
        _step("p1", "p"),
        _step("c1", "c", {"target_from_step": "p1"}),
    ]
    first = build_scenario_graph(steps, registry=registry).to_dict()
    second = build_scenario_graph(steps, registry=registry).to_dict()
    assert first == second


def test_graph_to_dict_is_json_serialisable() -> None:
    registry = {
        "p": _producer(ArtifactSpec(type=HOST, key="targets")),
        "c": _producer_consumer(
            produces_specs=(ArtifactSpec(type=EXFIL_PACKAGE, key="bundle"),),
            consumes_specs=(ArtifactSpec(type=HOST, key="target"),),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("p1", "p"),
            _step("c1", "c", {"target_from_step": "p1"}),
        ],
        registry=registry,
    )
    payload = graph.to_dict()
    rendered = json.dumps(payload)
    re_loaded = json.loads(rendered)
    assert re_loaded["nodes"][0]["step_id"] == "p1"
    assert re_loaded["edges"][0]["explicit"] is True
    # high_value_unused warning for the dangling exfil_package
    severities = [w["severity"] for w in re_loaded["warnings"]]
    assert "high_value_unused" in severities


def test_edge_ordering_is_deterministic() -> None:
    """Edges sort by source index, then target index, then type, then
    explicit-before-implicit, then target_key."""

    registry = {
        "p1": _producer(ArtifactSpec(type=HOST, key="targets")),
        "p2": _producer(ArtifactSpec(type=HOST, key="target")),
        "c": _consumer(
            ArtifactSpec(type=HOST, key="target"),
            ArtifactSpec(type=HOST, key="source", required=False),
        ),
    }
    graph = build_scenario_graph(
        [
            _step("a", "p1"),
            _step("b", "p2"),
            _step(
                "c",
                "c",
                {"target_from_step": "a", "source_from_step": "b"},
            ),
        ],
        registry=registry,
    )
    keys = [(e.source_step_id, e.target_key, e.explicit) for e in graph.edges]
    # Both source ids resolve to step indices; the triple is sorted in a
    # stable way regardless of dict ordering.
    assert keys == [
        ("a", "target", True),
        ("b", "source", True),
    ]


# ---------------------------------------------------------------------------
# Real shipped scenarios — pin the explicit-edge counts
# ---------------------------------------------------------------------------


_SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"


def _load_steps(scenario_filename: str):
    """Helper: load a shipped scenario and return its step list."""

    return load_scenario(_SCENARIOS_DIR / scenario_filename).steps


def test_fin7_scenario_graph_pins_seven_nodes_two_explicit_edges() -> None:
    steps = _load_steps("fin7_initial_access_to_c2.yaml")
    graph = build_scenario_graph(steps)
    assert len(graph.nodes) == 7
    explicit_edges = [e for e in graph.edges if e.explicit]
    # FIN7 wires `c2_endpoint_from_step` (resource_dev → C2) and
    # `target_from_step` (discovery → exfil) — two explicit edges.
    assert len(explicit_edges) == 2
    edges_by_target = {e.target_step_id: e for e in explicit_edges}
    assert edges_by_target["c2-https"].source_step_id == "stage-fin7-domain"
    assert edges_by_target["c2-https"].artifact_type == "c2_endpoint"
    assert edges_by_target["exfil-over-c2"].source_step_id == "pos-environment-recon"
    assert edges_by_target["exfil-over-c2"].artifact_type == "host"


def test_apt29_scenario_graph_pins_eight_nodes_three_explicit_edges() -> None:
    steps = _load_steps("apt29_credential_access.yaml")
    graph = build_scenario_graph(steps)
    assert len(graph.nodes) == 8
    explicit_edges = [e for e in graph.edges if e.explicit]
    # APT29 wires source_from_step (1) + target_from_step (2) — three
    # explicit edges.
    assert len(explicit_edges) == 3
    edges_by_key = sorted(
        ((e.source_step_id, e.target_step_id, e.target_key) for e in explicit_edges),
        key=lambda row: (row[1], row[2]),
    )
    assert ("harvest-browser-creds", "lateral-pivot", "source") in edges_by_key
    assert ("discover-finance-hosts", "lateral-pivot", "target") in edges_by_key


def test_healthcare_scenario_graph_pins_ten_nodes_five_explicit_edges() -> None:
    steps = _load_steps("healthcare_ransomware.yaml")
    graph = build_scenario_graph(steps)
    assert len(graph.nodes) == 10
    explicit_edges = [e for e in graph.edges if e.explicit]
    # Healthcare ransomware wires source_from_step (1) +
    # target_from_step (4) — five explicit edges.
    assert len(explicit_edges) == 5


def test_insider_scenario_graph_pins_seven_nodes_three_explicit_edges() -> None:
    steps = _load_steps("insider_exfil_dns.yaml")
    graph = build_scenario_graph(steps)
    assert len(graph.nodes) == 7
    explicit_edges = [e for e in graph.edges if e.explicit]
    # Insider DNS wires target_from_step (2) + c2_endpoint_from_step (1)
    # — three explicit edges.
    assert len(explicit_edges) == 3


def test_enterprise_scenario_graph_pins_twelve_nodes_five_explicit_edges() -> None:
    steps = _load_steps("enterprise_intrusion_chain.yaml")
    graph = build_scenario_graph(steps)
    assert len(graph.nodes) == 12
    explicit_edges = [e for e in graph.edges if e.explicit]
    # Enterprise wires target_from_step (3) + source_from_step (1) +
    # c2_endpoint_from_step (1) — five explicit edges.
    assert len(explicit_edges) == 5


def test_all_tier_one_scenarios_have_no_missing_required_warnings() -> None:
    """The tier-1 deepened scenarios should each be coherent: every
    required slot is satisfied, either explicitly or implicitly.

    Catches a regression where a future scenario edit drops the
    explicit ``*_from_step`` reference without re-shaping upstream
    to satisfy the slot some other way.
    """

    tier_1 = (
        "fin7_initial_access_to_c2.yaml",
        "apt29_credential_access.yaml",
        "healthcare_ransomware.yaml",
        "insider_exfil_dns.yaml",
        "enterprise_intrusion_chain.yaml",
    )
    for filename in tier_1:
        steps = _load_steps(filename)
        graph = build_scenario_graph(steps)
        missing = [w for w in graph.warnings if w.severity == "missing_required"]
        assert missing == [], (
            f"{filename}: missing_required warnings: "
            f"{[(w.step_id, w.artifact_type, w.message) for w in missing]}"
        )


def test_real_scenario_graph_to_dict_round_trips_through_json() -> None:
    """The shipped scenario graphs must serialise cleanly so the
    manifest writer + operator console can embed them as JSON
    (no ``ChainArtifact``-style dataclasses leaking to stdout)."""

    steps = _load_steps("fin7_initial_access_to_c2.yaml")
    graph = build_scenario_graph(steps)
    rendered = json.dumps(graph.to_dict(), sort_keys=True)
    parsed = json.loads(rendered)
    assert isinstance(parsed["nodes"], list)
    assert isinstance(parsed["edges"], list)
    assert isinstance(parsed["warnings"], list)
    assert all(isinstance(node["produces"], list) for node in parsed["nodes"])
