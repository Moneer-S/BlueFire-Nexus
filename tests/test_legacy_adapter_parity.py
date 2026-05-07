"""Cross-adapter parity audit for the legacy capability packs.

Per-adapter test files (``test_legacy_credential_access.py`` etc.)
already cover their adapter's individual contract end-to-end. This
file asserts the *cross-adapter* invariants that nobody else
asserts directly — a meta-test that fails if any single legacy
adapter drifts away from the family pattern.

Pinned invariants:

1. **Class-level ``attack_techniques`` matches dispatch reality**
   for every tactic-level legacy adapter. The advertised set
   (used by registry coverage tests, ATT&CK reports, and operator
   docs) MUST equal the set of canonical MITRE IDs reachable via
   the adapter's ``TECHNIQUE_KEYS`` / ``_SUPPORTED`` map. A drift
   in either direction is a real bug:
   - Advertised but not reachable → operator docs over-promise.
   - Reachable but not advertised → registry coverage tests miss
     the technique and reports under-count it.
2. **Every dispatch key produces a successful simulate-mode result**
   with non-empty details, ``mitre_technique`` metadata, the
   legacy pack/capability/mode envelope, and a ``runtime_outcome``
   that explicitly records ``simulated``.
3. **Adapter-facing MITRE IDs are modern / canonical** for every
   legacy adapter — none of the deprecated IDs the legacy classes
   emit raw (e.g. ``T1145`` for SSH key access) are surfaced as
   the result's ``techniques`` value. Closes the prior pattern
   established by PR #38 (SSH legacy MITRE normalisation) for the
   whole family.
4. **Result envelope shape is uniform** across the seven
   tactic-level adapters: ``status="success"``, single MITRE in
   ``techniques``, artifact dict with ``legacy.pack`` /
   ``legacy.capability`` / ``legacy.mode`` / ``legacy.payload``.

Each test runs the adapter through the full ``BlueFireNexus``
orchestrator with simulate-mode lab confirmation enabled in a temp
config, so no real subprocess / network call is ever issued. CI
guarantees match the local-first baseline.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.legacy_packs import (
    LegacyCollectionModule,
    LegacyCredentialAccessModule,
    LegacyImpactModule,
    LegacyLateralMovementModule,
    LegacyPrivilegeEscalationModule,
    LegacyProtocolResearchModule,
    LegacyStealthResearchModule,
)
from src.core.modules.impl.legacy_runtime import (
    COLLECTION_TECHNIQUE_KEYS,
    CREDENTIAL_TECHNIQUE_KEYS,
    IMPACT_TECHNIQUE_KEYS,
    LATERAL_MOVEMENT_TECHNIQUE_KEYS,
    PRIVILEGE_ESCALATION_TECHNIQUE_KEYS,
)


# ---------------------------------------------------------------------------
# Adapter catalog: one record per legacy_* tactic adapter
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _AdapterSpec:
    """Per-adapter parity spec.

    Keeps the dispatch metadata local to this test so a drift
    between source and test surfaces here as a clear failure
    rather than an opaque traceback.
    """

    module_name: str  # registry name (e.g. "legacy_credential_access")
    adapter_class: type
    pack_name: str
    capability_name: str  # capability used to gate config (sometimes overridden per-call)
    technique_param: str  # param key the adapter reads to pick a technique
    # technique_key -> canonical MITRE id pinned by the adapter's runtime layer.
    technique_to_mitre: Mapping[str, str]


def _credential_map() -> Dict[str, str]:
    return {key: mitre for key, (_handler, mitre) in CREDENTIAL_TECHNIQUE_KEYS.items()}


def _lateral_map() -> Dict[str, str]:
    return {
        key: mitre
        for key, (_branch, _handler, mitre) in LATERAL_MOVEMENT_TECHNIQUE_KEYS.items()
    }


def _privilege_map() -> Dict[str, str]:
    return {
        key: mitre
        for key, (_branch, _handler, mitre) in PRIVILEGE_ESCALATION_TECHNIQUE_KEYS.items()
    }


def _impact_map() -> Dict[str, str]:
    return {
        key: mitre
        for key, (_branch, _handler, mitre) in IMPACT_TECHNIQUE_KEYS.items()
    }


def _collection_map() -> Dict[str, str]:
    return {
        key: mitre
        for key, (_branch, _handler, mitre) in COLLECTION_TECHNIQUE_KEYS.items()
    }


def _protocol_map() -> Dict[str, str]:
    return {
        key: mitre
        for key, (mitre, _transport) in LegacyProtocolResearchModule._SUPPORTED.items()
    }


def _stealth_map() -> Dict[str, str]:
    return {
        key: mitre
        for key, (mitre, _action) in LegacyStealthResearchModule._SUPPORTED.items()
    }


_ADAPTERS: tuple[_AdapterSpec, ...] = (
    _AdapterSpec(
        module_name="legacy_credential_access",
        adapter_class=LegacyCredentialAccessModule,
        pack_name="tactic_pack",
        capability_name="credential_access",
        technique_param="technique",
        technique_to_mitre=_credential_map(),
    ),
    _AdapterSpec(
        module_name="legacy_lateral_movement",
        adapter_class=LegacyLateralMovementModule,
        pack_name="tactic_pack",
        capability_name="lateral_movement",
        technique_param="technique",
        technique_to_mitre=_lateral_map(),
    ),
    _AdapterSpec(
        module_name="legacy_privilege_escalation",
        adapter_class=LegacyPrivilegeEscalationModule,
        pack_name="tactic_pack",
        capability_name="privilege_escalation",
        technique_param="technique",
        technique_to_mitre=_privilege_map(),
    ),
    _AdapterSpec(
        module_name="legacy_impact",
        adapter_class=LegacyImpactModule,
        pack_name="tactic_pack",
        capability_name="impact",
        technique_param="technique",
        technique_to_mitre=_impact_map(),
    ),
    _AdapterSpec(
        module_name="legacy_collection",
        adapter_class=LegacyCollectionModule,
        pack_name="tactic_pack",
        capability_name="collection",
        technique_param="technique",
        technique_to_mitre=_collection_map(),
    ),
    _AdapterSpec(
        module_name="legacy_protocol_research",
        adapter_class=LegacyProtocolResearchModule,
        pack_name="c2_pack",
        # Capability is set per-call from the ``protocol`` param;
        # ``dns_tunneling`` is the documented default.
        capability_name="dns_tunneling",
        technique_param="protocol",
        technique_to_mitre=_protocol_map(),
    ),
    _AdapterSpec(
        module_name="legacy_stealth_research",
        adapter_class=LegacyStealthResearchModule,
        pack_name="stealth_pack",
        capability_name="anti_forensic",
        technique_param="capability",
        technique_to_mitre=_stealth_map(),
    ),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _enable_capability_simulate(
    cfg_path: Path, *, pack: str, capability: str
) -> None:
    """Enable a single legacy capability in simulate mode for an isolated config."""
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(cfg_path.parent / "output"))
    base = f"modules.legacy.{pack}.capabilities.{capability}"
    cfg.set(f"{base}.enabled", True)
    cfg.set(f"{base}.mode", "simulate")
    cfg.set(f"{base}.lab_confirmation", False)
    cfg.save()


def _enable_pack_simulate(cfg_path: Path, *, pack: str, capabilities: Iterable[str]) -> None:
    """Enable an entire pack in simulate mode (all listed capabilities at once)."""
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(cfg_path.parent / "output"))
    for capability in capabilities:
        base = f"modules.legacy.{pack}.capabilities.{capability}"
        cfg.set(f"{base}.enabled", True)
        cfg.set(f"{base}.mode", "simulate")
        cfg.set(f"{base}.lab_confirmation", False)
    cfg.save()


def _spec_ids(specs: Iterable[_AdapterSpec]) -> list[str]:
    return [spec.module_name for spec in specs]


# ---------------------------------------------------------------------------
# 1. attack_techniques class attribute matches dispatch reality
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec", _ADAPTERS, ids=_spec_ids(_ADAPTERS))
def test_advertised_attack_techniques_match_dispatch_reality(spec: _AdapterSpec) -> None:
    """Class-level advertising MUST match the canonical MITRE set the dispatch produces.

    This is the canonical drift detector: registry coverage tests
    rely on ``adapter.attack_techniques`` to assert ATT&CK
    coverage; a stale class attribute means downstream coverage
    reports are wrong.
    """
    advertised = set(spec.adapter_class.attack_techniques)
    reachable = set(spec.technique_to_mitre.values())

    missing_from_advertised = reachable - advertised
    extra_in_advertised = advertised - reachable
    assert missing_from_advertised == set(), (
        f"{spec.module_name}: dispatch reaches MITRE IDs not advertised: "
        f"{sorted(missing_from_advertised)}"
    )
    assert extra_in_advertised == set(), (
        f"{spec.module_name}: advertised MITRE IDs not reachable via dispatch: "
        f"{sorted(extra_in_advertised)}"
    )


# ---------------------------------------------------------------------------
# 2. Adapter-facing MITRE IDs are modern / canonical
# ---------------------------------------------------------------------------


# Deprecated MITRE technique IDs that should NOT appear as the
# ADAPTER-facing canonical id (they may still appear in the legacy
# class's raw output under runtime_outcome.details; this test only
# pins the surface ids the adapter exposes via class attribute /
# techniques mapping).
#
# Sourced from the prior fix patterns (PR #38 normalised T1145 ->
# T1552.004 for SSH key access; PR #37 aligned lateral_movement
# MITRE ids). Adding new entries here when ATT&CK deprecates an id
# is the natural drift catcher.
_DEPRECATED_MITRE_IDS: frozenset[str] = frozenset(
    {
        "T1145",  # deprecated by T1552.004 (Private Keys)
        "T1086",  # deprecated by T1059.001 (PowerShell)
        "T1064",  # deprecated by T1059 (Command and Scripting Interpreter)
    }
)


@pytest.mark.parametrize("spec", _ADAPTERS, ids=_spec_ids(_ADAPTERS))
def test_adapter_does_not_advertise_deprecated_mitre_ids(spec: _AdapterSpec) -> None:
    """No adapter exposes a deprecated MITRE id as its canonical surface.

    Closes the SSH-T1145 pattern from PR #38 across the whole
    family: legacy classes are allowed to emit deprecated ids in
    their raw details (preserved as ``legacy_mitre_technique_id``),
    but the adapter MUST normalise to the modern canonical id
    before surfacing on ``adapter.attack_techniques`` /
    ``ProviderResponse.techniques``.
    """
    advertised = set(spec.adapter_class.attack_techniques)
    reachable = set(spec.technique_to_mitre.values())
    deprecated_in_advertised = advertised & _DEPRECATED_MITRE_IDS
    deprecated_in_reachable = reachable & _DEPRECATED_MITRE_IDS
    assert deprecated_in_advertised == set(), (
        f"{spec.module_name}: deprecated MITRE ids in advertised set: "
        f"{sorted(deprecated_in_advertised)}"
    )
    assert deprecated_in_reachable == set(), (
        f"{spec.module_name}: deprecated MITRE ids reachable via dispatch: "
        f"{sorted(deprecated_in_reachable)}"
    )


# ---------------------------------------------------------------------------
# 3. Every dispatch key produces a working simulate-mode result
# ---------------------------------------------------------------------------


def _collect_dispatch_cases() -> list[tuple[_AdapterSpec, str, str]]:
    """Yield (adapter, technique_key, expected_mitre) for every dispatch entry."""
    cases: list[tuple[_AdapterSpec, str, str]] = []
    for spec in _ADAPTERS:
        for technique_key, mitre in spec.technique_to_mitre.items():
            cases.append((spec, technique_key, mitre))
    return cases


_DISPATCH_CASES = _collect_dispatch_cases()
_DISPATCH_IDS = [
    f"{spec.module_name}::{technique_key}" for spec, technique_key, _ in _DISPATCH_CASES
]


@pytest.mark.parametrize(
    "spec,technique_key,expected_mitre", _DISPATCH_CASES, ids=_DISPATCH_IDS
)
def test_every_dispatch_key_produces_simulate_mode_result(
    spec: _AdapterSpec,
    technique_key: str,
    expected_mitre: str,
    tmp_path: Path,
) -> None:
    """Every key in every adapter's dispatch map produces a clean simulate run.

    Runs through the full orchestrator (not the module class
    directly) so the legacy gating path, telemetry bus, detection
    writer, and report renderer are all exercised. Failures here
    almost always mean a recently-added technique was wired into
    the dispatch map but its handler/notes/profile entry was
    skipped — the per-adapter test files cover ONE technique each
    by design, so this parametrised meta-test is the safety net.
    """
    cfg_path = tmp_path / "config.yaml"
    # Use the per-call capability the adapter normalises to. For the
    # tactic_pack adapters the capability_name is fixed; for protocol
    # / stealth research it varies per-technique, so enable the whole
    # pack at once.
    if spec.pack_name == "c2_pack":
        _enable_pack_simulate(
            cfg_path, pack=spec.pack_name, capabilities=spec.technique_to_mitre.keys()
        )
    elif spec.pack_name == "stealth_pack":
        _enable_pack_simulate(
            cfg_path, pack=spec.pack_name, capabilities=spec.technique_to_mitre.keys()
        )
    else:
        _enable_capability_simulate(
            cfg_path, pack=spec.pack_name, capability=spec.capability_name
        )
    nexus = BlueFireNexus(str(cfg_path))

    # Some adapters need an extra parameter alongside the technique
    # selector to satisfy domain-allowlist checks (legacy_protocol_
    # research validates ``endpoint`` against allowed lab domains).
    extra_params: Dict[str, Any] = {}
    if spec.module_name == "legacy_protocol_research":
        # Use the adapter's own default endpoint per protocol so the
        # domain-allowlist guard passes.
        extra_params["endpoint"] = (
            LegacyProtocolResearchModule._DEFAULT_ENDPOINTS.get(technique_key, "")
        )

    result = nexus.execute_operation(
        spec.module_name,
        {spec.technique_param: technique_key, **extra_params},
    )
    assert result["status"] == "success", (
        f"{spec.module_name}::{technique_key} failed: {result}"
    )
    # MITRE id surfaces in the result's techniques list.
    assert expected_mitre in result.get("techniques", []), (
        f"{spec.module_name}::{technique_key} missing MITRE {expected_mitre}; "
        f"got techniques={result.get('techniques')}"
    )
    # Every adapter writes the legacy pack/capability/mode envelope.
    legacy_artifact = (result.get("artifacts") or {}).get("legacy")
    assert isinstance(legacy_artifact, dict), (
        f"{spec.module_name}::{technique_key} missing legacy artifact envelope"
    )
    assert legacy_artifact.get("pack") == spec.pack_name
    # capability_name on the artifact may be the per-call value (legacy_protocol_research /
    # legacy_stealth_research mutate it); the tactic-level adapters keep the class default.
    capability_value = legacy_artifact.get("capability")
    assert capability_value, (
        f"{spec.module_name}::{technique_key} legacy artifact missing capability"
    )
    assert legacy_artifact.get("mode") == "simulate"
    payload = legacy_artifact.get("payload") or {}
    assert payload, (
        f"{spec.module_name}::{technique_key} legacy artifact payload empty"
    )
    # Every payload carries the technique-or-protocol-or-capability key
    # under at least one canonical name. Adapters use slightly different
    # spellings; the union catches all current callers.
    technique_key_in_payload = any(
        payload.get(key) == technique_key
        for key in ("technique", "protocol", "capability")
    )
    assert technique_key_in_payload, (
        f"{spec.module_name}::{technique_key} payload missing technique key: "
        f"{payload.keys()}"
    )
    # Simulate mode runtime_outcome must explicitly say "simulated"
    # so reports cannot accidentally show as having executed against
    # real targets.
    runtime_outcome = payload.get("runtime_outcome") or {}
    assert runtime_outcome.get("status") == "simulated", (
        f"{spec.module_name}::{technique_key} runtime_outcome status: {runtime_outcome}"
    )


# ---------------------------------------------------------------------------
# 4. Result envelope shape parity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec", _ADAPTERS, ids=_spec_ids(_ADAPTERS))
def test_default_technique_result_envelope_shape(
    spec: _AdapterSpec, tmp_path: Path
) -> None:
    """The default technique on every adapter produces the canonical envelope shape.

    Pinning the shape uniformly (``techniques`` is exactly one
    canonical MITRE id; artifacts.legacy carries pack / capability
    / mode / payload; payload.tradecraft_notes or equivalent is
    populated) means a future adapter that diverges from the
    family contract is caught here even before its per-adapter
    test file is updated.
    """
    cfg_path = tmp_path / "config.yaml"
    if spec.pack_name == "c2_pack":
        _enable_pack_simulate(
            cfg_path, pack=spec.pack_name, capabilities=spec.technique_to_mitre.keys()
        )
    elif spec.pack_name == "stealth_pack":
        _enable_pack_simulate(
            cfg_path, pack=spec.pack_name, capabilities=spec.technique_to_mitre.keys()
        )
    else:
        _enable_capability_simulate(
            cfg_path, pack=spec.pack_name, capability=spec.capability_name
        )
    nexus = BlueFireNexus(str(cfg_path))
    # Calling without a technique selector → adapter falls back to its
    # documented default.
    result = nexus.execute_operation(spec.module_name, {})
    assert result["status"] == "success"
    techniques = result.get("techniques") or []
    assert len(techniques) == 1, (
        f"{spec.module_name} default emitted {len(techniques)} techniques: {techniques}"
    )
    legacy_artifact = (result.get("artifacts") or {}).get("legacy") or {}
    assert legacy_artifact.get("pack") == spec.pack_name
    assert legacy_artifact.get("mode") == "simulate"
    payload = legacy_artifact.get("payload") or {}
    assert payload  # non-empty
