"""Cross-adapter consistency for the legacy tactic_pack family.

Three structural invariants are pinned here so future changes to
either side of the dispatch boundary cannot drift:

1. Every dispatch-table entry resolves to a handler that actually
   exists on the preserved legacy class. The earlier Bugbot finding
   that exposed empty `details` for non-first-stage techniques came
   from indirect routing through a staged pipeline; this test pins
   the direct binding.

2. Every MITRE id the dispatch table can emit appears in the
   adapter class's ``attack_techniques`` tuple — the public
   advertised technique surface. Conversely, every advertised
   technique must be reachable from the dispatch table. Either
   direction failing means the public surface lies about what the
   adapter can do.

3. Every dispatch table key has a corresponding tradecraft-notes
   entry in the adapter's per-technique notes dict. A missing entry
   means a technique would render with no defender-facing notes,
   silently degrading the simulate-mode signal.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

import pytest

from src.core.collection.collection import Collection
from src.core.credential.credential_access import CredentialAccess
from src.core.impact.impact import Impact
from src.core.modules.impl.legacy_packs import (
    LegacyCollectionModule,
    LegacyCredentialAccessModule,
    LegacyImpactModule,
    LegacyLateralMovementModule,
    LegacyPrivilegeEscalationModule,
    _LEGACY_COLLECTION_NOTES,
    _LEGACY_CREDENTIAL_NOTES,
    _LEGACY_IMPACT_NOTES,
    _LEGACY_LATERAL_MOVEMENT_NOTES,
    _LEGACY_PRIVILEGE_ESCALATION_NOTES,
)
from src.core.modules.impl.legacy_runtime import (
    COLLECTION_TECHNIQUE_KEYS,
    CREDENTIAL_TECHNIQUE_KEYS,
    IMPACT_TECHNIQUE_KEYS,
    LATERAL_MOVEMENT_TECHNIQUE_KEYS,
    PRIVILEGE_ESCALATION_TECHNIQUE_KEYS,
)
from src.core.movement.lateral_movement import LateralMovement
from src.core.privilege.privilege_escalation import PrivilegeEscalation


# (adapter_name, dispatch_table, method_index_in_row, mitre_index_in_row,
#  legacy_class, adapter_class, notes_dict)
_ADAPTERS: Tuple[Tuple[Any, ...], ...] = (
    (
        "credential_access",
        CREDENTIAL_TECHNIQUE_KEYS,
        0,  # 2-tuple: (method, mitre)
        1,
        CredentialAccess,
        LegacyCredentialAccessModule,
        _LEGACY_CREDENTIAL_NOTES,
    ),
    (
        "lateral_movement",
        LATERAL_MOVEMENT_TECHNIQUE_KEYS,
        1,  # 3-tuple: (branch, method, mitre)
        2,
        LateralMovement,
        LegacyLateralMovementModule,
        _LEGACY_LATERAL_MOVEMENT_NOTES,
    ),
    (
        "privilege_escalation",
        PRIVILEGE_ESCALATION_TECHNIQUE_KEYS,
        1,
        2,
        PrivilegeEscalation,
        LegacyPrivilegeEscalationModule,
        _LEGACY_PRIVILEGE_ESCALATION_NOTES,
    ),
    (
        "impact",
        IMPACT_TECHNIQUE_KEYS,
        1,
        2,
        Impact,
        LegacyImpactModule,
        _LEGACY_IMPACT_NOTES,
    ),
    (
        "collection",
        COLLECTION_TECHNIQUE_KEYS,
        1,
        2,
        Collection,
        LegacyCollectionModule,
        _LEGACY_COLLECTION_NOTES,
    ),
)


@pytest.mark.parametrize("entry", _ADAPTERS, ids=lambda e: e[0])
def test_every_dispatch_entry_has_a_handler(entry: Tuple[Any, ...]) -> None:
    name, table, method_idx, _mitre_idx, legacy_cls, _adapter_cls, _notes = entry
    missing = []
    for technique, row in table.items():
        method = row[method_idx]
        if not hasattr(legacy_cls, f"_handle_{method}"):
            missing.append((technique, method))
    assert not missing, (
        f"{name} dispatch table references handlers that do not exist on "
        f"{legacy_cls.__name__}: {missing}"
    )


@pytest.mark.parametrize("entry", _ADAPTERS, ids=lambda e: e[0])
def test_dispatch_emittable_mitre_subset_of_advertised(entry: Tuple[Any, ...]) -> None:
    """Every MITRE id the dispatch table can emit must be advertised."""
    name, table, _method_idx, mitre_idx, _legacy_cls, adapter_cls, _notes = entry
    emitted = {row[mitre_idx] for row in table.values()}
    advertised = set(getattr(adapter_cls, "attack_techniques", ()))
    missing = sorted(emitted - advertised)
    assert not missing, (
        f"{name}: dispatch table emits MITRE ids that {adapter_cls.__name__}"
        f".attack_techniques does NOT advertise: {missing}"
    )


@pytest.mark.parametrize("entry", _ADAPTERS, ids=lambda e: e[0])
def test_advertised_mitre_reachable_from_dispatch(entry: Tuple[Any, ...]) -> None:
    """Every advertised MITRE id must be reachable from the dispatch table.

    Parent-of-subtechnique reachability counts: if the adapter advertises
    `T1555` and the dispatch can emit `T1555.003`, that's reachable.
    """
    name, table, _method_idx, mitre_idx, _legacy_cls, adapter_cls, _notes = entry
    emitted = {row[mitre_idx] for row in table.values()}
    advertised = set(getattr(adapter_cls, "attack_techniques", ()))
    unreachable = []
    for tech in advertised:
        if tech in emitted:
            continue
        if any(t.startswith(f"{tech}.") for t in emitted):
            continue
        unreachable.append(tech)
    assert not unreachable, (
        f"{name}: {adapter_cls.__name__}.attack_techniques advertises MITRE "
        f"ids that NO dispatch entry can emit (false advertising): "
        f"{sorted(unreachable)}"
    )


@pytest.mark.parametrize("entry", _ADAPTERS, ids=lambda e: e[0])
def test_every_dispatch_entry_has_tradecraft_notes(entry: Tuple[Any, ...]) -> None:
    name, table, _method_idx, _mitre_idx, _legacy_cls, _adapter_cls, notes = entry
    missing_notes = sorted(set(table.keys()) - set(notes.keys()))
    assert not missing_notes, (
        f"{name}: dispatch entries lack tradecraft-notes entries (defender-"
        f"facing simulate-mode rendering would be empty): {missing_notes}"
    )


@pytest.mark.parametrize("entry", _ADAPTERS, ids=lambda e: e[0])
def test_tradecraft_notes_have_no_orphans(entry: Tuple[Any, ...]) -> None:
    name, table, _method_idx, _mitre_idx, _legacy_cls, _adapter_cls, notes = entry
    orphans = sorted(set(notes.keys()) - set(table.keys()))
    assert not orphans, (
        f"{name}: tradecraft-notes entries reference techniques NOT in the "
        f"dispatch table (dead notes): {orphans}"
    )
