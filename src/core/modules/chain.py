"""Chain context built on top of capability IO contracts.

The orchestrator's ``previous_step_results`` map is keyed by ``step_id``
and lets a downstream module look up an exact upstream step's
``artifacts`` dict. That is precise but it forces every consumer to
hard-code the upstream step_id, which makes scenarios brittle and
makes the chain illegible to the planner / report / AI orchestrator.

:class:`ChainContext` is the read-only view that sits on top of that
map and exposes the same data **typed**: "give me the latest credential
the chain has produced", "give me every step that emitted a host", etc.

The mapping is built incrementally by the orchestrator from the
declared :class:`CapabilityIOContract` of the producing module. A
producer's contract names which artifact dict keys correspond to which
artifact types; the chain context indexes each entry under those types.

The chain context is **advisory** — modules that want the precise old
behaviour (look up a specific upstream by step_id) can keep using
``context["previous_step_results"]``. The richer view is exposed under
``context["chain"]``.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .contracts import CapabilityIOContract, normalise_artifact_type


@dataclass(frozen=True, slots=True)
class ChainArtifact:
    """A single typed artifact entry produced by an upstream step.

    ``provenance`` is the step_id + module name + artifact key that
    produced this entry, so consumers / report views / dashboards can
    explain *where* a propagated value came from.
    """

    type: str
    value: Any
    step_id: str
    module: str
    key: str

    @property
    def provenance(self) -> Dict[str, str]:
        """Return a human-readable provenance dict for reporting."""

        return {
            "step_id": self.step_id,
            "module": self.module,
            "key": self.key,
        }


@dataclass(slots=True)
class ChainContext:
    """Read-only typed view over the chain's accumulated artifacts.

    Holds a snapshot of every typed artifact emitted upstream, indexed
    by canonical artifact type and by step_id. Consumers ask
    "what's the latest <type>?" or "do we have any <type>?" without
    knowing which upstream step produced it.

    Build via :func:`build_chain_context`. Once built, the context is
    deep-copied at lookup time so a consuming module cannot mutate
    upstream state through the chain view (the orchestrator already
    deep-copies into ``previous_step_results`` for the bare map; the
    chain view layers on top).
    """

    by_type: Dict[str, List[ChainArtifact]] = field(default_factory=dict)
    by_step: Dict[str, List[ChainArtifact]] = field(default_factory=dict)
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    # Records every step the chain has seen via :meth:`record_step`,
    # regardless of whether the step emitted any typed artifacts. The
    # ``by_step`` index above is keyed by step_id but only populated
    # when a step's contract produced rows; a step that ran but
    # emitted nothing has no entry in ``by_step``. Downstream
    # consumers (planner module-reuse penalty, dashboards) need to
    # know "which modules ran" independent of artifact emission, so
    # this field tracks the (step_id, module) tuples explicitly.
    # Insertion-ordered so a consumer can walk the chain in original
    # step order. (Codex P2 on PR #198.)
    steps_recorded: List[Dict[str, str]] = field(default_factory=list)

    # ----------------------------------------------------------------
    # Public lookup surface
    #
    # Lookups normalise the input artifact_type via
    # :func:`normalise_artifact_type` so an operator-friendly alias
    # (``credentials`` / ``hosts`` / ``c2_endpoints``) lands on the
    # same canonical row :meth:`record_step` indexed under. This
    # mirrors the helper functions :func:`latest_artifact_value` and
    # :func:`chain_provenance` which already normalise; without it,
    # callers that use ``ChainContext`` directly would silently miss
    # valid upstream data when they passed an alias. Unknown labels
    # resolve to "no match" (the helpers below raise on unknown; the
    # in-memory builder API stays permissive).

    def has(self, artifact_type: str) -> bool:
        """Return True when at least one upstream step emitted this type."""

        canonical = self._canonical_type(artifact_type)
        if canonical is None:
            return False
        return canonical in self.by_type and bool(self.by_type[canonical])

    def latest_artifact(self, artifact_type: str) -> Optional[ChainArtifact]:
        """Return the most-recent typed artifact, or None when absent.

        "Most recent" is the last entry inserted into the by-type list,
        which preserves orchestrator step order.
        """

        canonical = self._canonical_type(artifact_type)
        if canonical is None:
            return None
        rows = self.by_type.get(canonical) or []
        if not rows:
            return None
        return _deep_copy_artifact(rows[-1])

    def candidate_artifacts(self, artifact_type: str) -> Tuple[ChainArtifact, ...]:
        """Return every typed artifact emitted upstream, in insertion order."""

        canonical = self._canonical_type(artifact_type)
        if canonical is None:
            return ()
        rows = self.by_type.get(canonical) or []
        return tuple(_deep_copy_artifact(row) for row in rows)

    @staticmethod
    def _canonical_type(artifact_type: str) -> Optional[str]:
        """Normalise an alias to the canonical artifact type, or ``None``.

        Returns ``None`` for unknown labels so the calling lookup
        treats the type as missing rather than raising.
        """

        try:
            return normalise_artifact_type(artifact_type)
        except ValueError:
            return None

    def artifacts_by_type(self) -> Dict[str, Tuple[ChainArtifact, ...]]:
        """Return the full type-indexed view as immutable tuples."""

        return {
            artifact_type: tuple(_deep_copy_artifact(row) for row in rows)
            for artifact_type, rows in self.by_type.items()
        }

    def artifacts_by_step(self, step_id: str) -> Tuple[ChainArtifact, ...]:
        """Return every typed artifact emitted by a specific upstream step."""

        rows = self.by_step.get(step_id) or []
        return tuple(_deep_copy_artifact(row) for row in rows)

    # ----------------------------------------------------------------
    # Public construction surface (used by the orchestrator)

    def record_step(
        self,
        *,
        step_id: str,
        module: str,
        contract: CapabilityIOContract | None,
        artifacts: Mapping[str, Any],
    ) -> None:
        """Index a completed upstream step's artifacts under their declared types.

        The producer's :class:`CapabilityIOContract` names which keys in
        ``artifacts`` correspond to which canonical artifact types.
        Missing keys are silently skipped — the contract is advisory,
        not a runtime schema, so a module that doesn't actually emit a
        particular optional slot in this run is not a defect.

        When multiple specs share the same ``key`` (e.g. discovery's
        ``targets`` shared across host / service / share / file / etc.),
        each spec's optional :attr:`ArtifactSpec.produced_if`
        discriminator is evaluated against the run's artifacts dict;
        specs whose predicate fails are skipped so a single ``targets``
        value does not get indexed under every declared type. Specs
        without a discriminator stay always-applicable for their key.
        """

        # Always record the step's existence, regardless of whether
        # the contract has produced specs or whether those specs
        # actually fire. ``steps_recorded`` is the canonical
        # "modules-ever-run" view for downstream consumers
        # (planner module-reuse penalty, dashboards). Keep this BEFORE
        # the contract / produces walk so even an empty-emission step
        # gets recorded.
        self.steps_recorded.append({"step_id": step_id, "module": module})
        if contract is None or not contract.produces:
            return
        for spec in contract.produces:
            value = artifacts.get(spec.key) if spec.key else None
            if value is None or value == "" or value == [] or value == {}:
                continue
            if not _spec_applies_to_run(spec, artifacts):
                continue
            entry = ChainArtifact(
                type=spec.type,
                value=copy.deepcopy(value),
                step_id=step_id,
                module=module,
                key=spec.key,
            )
            self.by_type.setdefault(spec.type, []).append(entry)
            self.by_step.setdefault(step_id, []).append(entry)

    def record_consumer_warning(
        self,
        *,
        step_id: str,
        module: str,
        contract: CapabilityIOContract | None,
    ) -> None:
        """Record warnings when a consumer wants a type the chain has not produced.

        Walks the consumer's required ``consumes`` slots and emits a
        warning row for any required type the chain has not produced
        upstream. Optional slots are silently skipped — they have a
        documented default in the consumer module.

        The warning is advisory metadata for the report / planner /
        dashboard. The consumer still runs; the chain does NOT abort
        on a missing optional input.
        """

        if contract is None or not contract.consumes:
            return
        for spec in contract.consumes:
            if not spec.required:
                continue
            if spec.type in self.by_type and self.by_type[spec.type]:
                continue
            self.warnings.append(
                {
                    "step_id": step_id,
                    "module": module,
                    "missing_type": spec.type,
                    "missing_key": spec.key,
                }
            )

    # ----------------------------------------------------------------
    # Snapshot for inclusion in the per-step context payload

    def snapshot(self) -> Dict[str, Any]:
        """Return a serialisable, deep-copied snapshot of the chain.

        Suitable for embedding in the orchestrator's ``_module_context``
        payload as ``context["chain"]``. Modules read it as a plain
        mapping; the snapshot is independent of the live builder so
        the consumer cannot mutate the chain.
        """

        return {
            "artifacts_by_type": {
                artifact_type: [_artifact_to_dict(row) for row in rows]
                for artifact_type, rows in self.by_type.items()
            },
            "artifacts_by_step": {
                step_id: [_artifact_to_dict(row) for row in rows]
                for step_id, rows in self.by_step.items()
            },
            "warnings": [dict(warning) for warning in self.warnings],
            "steps_recorded": [dict(entry) for entry in self.steps_recorded],
        }


def _artifact_to_dict(row: ChainArtifact) -> Dict[str, Any]:
    return {
        "type": row.type,
        "value": copy.deepcopy(row.value),
        "step_id": row.step_id,
        "module": row.module,
        "key": row.key,
    }


def _spec_applies_to_run(spec: Any, artifacts: Mapping[str, Any]) -> bool:
    """Return ``True`` when an :class:`ArtifactSpec`'s discriminator
    matches the run's artifacts dict (or no discriminator was set).

    Used by :meth:`ChainContext.record_step` to disambiguate specs that
    share the same artifact-dict key. Without this gate a single
    discovery ``targets`` list would be indexed under host AND service
    AND share AND user AND file AND impact_target, which is wrong: the
    runtime only enumerated one of those at a time.

    The discriminator value can be a single scalar or a tuple/frozenset
    of acceptable values (any-match wins). Falls open (``True``) when
    the spec carries no ``produced_if``.
    """

    discriminator = getattr(spec, "produced_if", None)
    if discriminator is None:
        return True
    try:
        key, expected = discriminator
    except (TypeError, ValueError):
        # Malformed predicate: treat as always-applicable rather than
        # silently dropping a real emission. The contract test surfaces
        # malformed shapes at registration time.
        return True
    actual = artifacts.get(key)
    if isinstance(expected, (tuple, frozenset, set, list)):
        return actual in expected
    return actual == expected


def _deep_copy_artifact(row: ChainArtifact) -> ChainArtifact:
    return ChainArtifact(
        type=row.type,
        value=copy.deepcopy(row.value),
        step_id=row.step_id,
        module=row.module,
        key=row.key,
    )


def latest_artifact_value(
    chain_snapshot: Mapping[str, Any] | None,
    artifact_type: str,
) -> Optional[Any]:
    """Resolve the latest value for ``artifact_type`` from a chain snapshot.

    Convenience helper for modules that don't want to instantiate
    :class:`ChainContext` again from the snapshot. Returns ``None``
    when the chain has not produced anything matching the requested
    type, or when the snapshot is missing entirely.
    """

    if not chain_snapshot:
        return None
    by_type = chain_snapshot.get("artifacts_by_type") or {}
    canonical = normalise_artifact_type(artifact_type)
    rows = by_type.get(canonical) or []
    if not rows:
        return None
    return copy.deepcopy(rows[-1].get("value"))


def chain_provenance(
    chain_snapshot: Mapping[str, Any] | None,
    artifact_type: str,
) -> Optional[Dict[str, str]]:
    """Return ``{step_id, module, key}`` for the latest entry of a type."""

    if not chain_snapshot:
        return None
    by_type = chain_snapshot.get("artifacts_by_type") or {}
    canonical = normalise_artifact_type(artifact_type)
    rows = by_type.get(canonical) or []
    if not rows:
        return None
    latest = rows[-1]
    return {
        "step_id": str(latest.get("step_id", "")),
        "module": str(latest.get("module", "")),
        "key": str(latest.get("key", "")),
    }


__all__ = [
    "ChainArtifact",
    "ChainContext",
    "chain_provenance",
    "latest_artifact_value",
]
