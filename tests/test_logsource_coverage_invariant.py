"""Logsource coverage invariant for every registered runtime module.

The Sigma generator (``src/core/detections/sigma.py``) and the YARA-L
generator (``src/core/detections/yara_l.py``) both fall back to a
hardcoded ``{"category": "process_creation", "product": "windows"}``
when a hint omits ``logsource``. That fallback was conservative when
every shipped module targeted Windows process_creation telemetry, but
the runtime now spans process_access / file_event / registry_event /
image_load / network_connection / dns / email / threat_intelligence /
service_creation / service_modification / etc.

A future module that forgets to set ``logsource`` would silently
produce mis-labeled detection drafts: a registry-poking module's
Sigma rule would claim to be a process_creation/windows rule and
the YARA-L event_type would default to PROCESS_LAUNCH. A defender
analyst reading the rule would be confused and the rule would not
fire on the right telemetry.

This test runs every registered module with minimal valid params,
inspects the resulting ``ModuleResult.detection_hints``, and asserts
that the hint either:
- includes a ``logsource`` block (a dict with at least ``category``
  and ``product`` keys), OR
- is intentionally empty (the metadata-only modules listed in
  :data:`_INTENTIONALLY_EMPTY_HINT_MODULES` like
  ``legacy_capability_summary``).

Catches the audit gap that surfaced in the post-rc1 stub/skeleton
review: ``LegacyWrappedModule`` previously emitted
``hints = {"mitre_technique": "T0000"}`` with no logsource, so its
generated Sigma drafts were mis-labeled as Windows process_creation
rules regardless of what the wrapped legacy module actually did.
"""

from __future__ import annotations

import pytest

from src.core.modules.registry import build_runtime_modules


# Modules that intentionally emit no detection hints (control-plane
# reporting modules with no MITRE techniques). They must not be
# subject to the logsource invariant.
_INTENTIONALLY_EMPTY_HINT_MODULES: set[str] = {"legacy_capability_summary"}


# Per-module minimal-valid params for `module.execute(params, context)`.
# Most modules accept an empty dict; some need at least a hint of
# what they're being asked to do. Keep this map deliberately
# minimal — the invariant we're testing is "does the resulting
# hint carry a logsource", not "is the module's full param surface
# correct".
_MINIMAL_PARAMS: dict[str, dict] = {
    # standard modules
    "execution": {"command": "echo test"},
    "exfiltration": {"method": "via_c2", "targets": ["10.0.0.1"]},
    "initial_access": {"vector": "phishing_email"},
    "lateral_movement": {"target": "lab-host"},
    "credential_access": {"target": "lab-host"},
    "persistence": {"target": "lab-host"},
    "defense_evasion": {"target": "lab-host"},
    "anti_detection": {"target": "lab-host"},
    "discovery": {"target": "lab-host"},
    "command_control": {"channel": "http"},
    "intelligence": {"focus": "lab"},
    "network_obfuscator": {},
    "resource_development": {},
    "reconnaissance": {},
    "privilege_escalation": {"target": "lab-host"},
    "impact": {"target": "lab-host"},
    "collection": {"target": "lab-host"},
    # legacy adapters - all accept a `capability` param + optional target.
    "legacy_actor_profile": {"capability": "apt29"},
    "legacy_protocol_research": {"capability": "dns_tunneling"},
    "legacy_stealth_research": {"capability": "anti_forensic"},
    "legacy_credential_access": {"capability": "lsass_dump", "target": "lab-host"},
    "legacy_lateral_movement": {"capability": "psexec", "target": "lab-host"},
    "legacy_privilege_escalation": {"capability": "token_creation", "target": "lab-host"},
    "legacy_impact": {"capability": "data_destruction", "target": "lab-host"},
    "legacy_collection": {"capability": "file_collection", "target": "lab-host"},
    # Per-actor legacy adapters; each takes the actor's research-pack
    # capability invocation through the same gating layer.
    "legacy_apt28_research": {"capability": "actor_profile"},
    "legacy_apt29_research": {"capability": "actor_profile"},
    "legacy_apt32_research": {"capability": "actor_profile"},
    "legacy_apt38_research": {"capability": "actor_profile"},
    "legacy_apt41_research": {"capability": "actor_profile"},
    # control-plane summary module (excluded from invariant via
    # _INTENTIONALLY_EMPTY_HINT_MODULES)
    "legacy_capability_summary": {},
}


def _ctx(tmp_path):
    return {
        "run_id": "logsource-invariant-test",
        "output_dir": tmp_path,
        "config": {
            "modules": {
                "legacy": {
                    "enable_all_lab_capabilities": True,
                    "lab_confirmation": True,
                }
            }
        },
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


@pytest.fixture(scope="module")
def _registered_modules() -> dict:
    """Lazily build the runtime registry once per test module."""
    return build_runtime_modules()


def test_minimal_params_map_covers_every_registered_module(_registered_modules) -> None:
    """If a new module ships, the maintainer should be forced to either
    add minimal params for it OR explicitly mark it as exempt."""
    missing = sorted(set(_registered_modules) - set(_MINIMAL_PARAMS))
    assert missing == [], (
        f"Registered modules without minimal-params entry: {missing}. "
        f"Add them to _MINIMAL_PARAMS in this file or, if they emit no "
        f"detection hints by design, to _INTENTIONALLY_EMPTY_HINT_MODULES."
    )


@pytest.mark.parametrize(
    "module_name",
    sorted(set(_MINIMAL_PARAMS) - _INTENTIONALLY_EMPTY_HINT_MODULES),
)
def test_module_emits_logsource_in_detection_hints(
    module_name: str, _registered_modules, tmp_path
) -> None:
    """Every registered module that produces detection hints must
    include a ``logsource`` block. Otherwise the Sigma / YARA-L
    generators silently fall back to
    ``{"category": "process_creation", "product": "windows"}`` and
    the resulting drafts mis-label the technique.
    """
    module = _registered_modules[module_name]
    params = _MINIMAL_PARAMS[module_name]
    result = module.execute(params, _ctx(tmp_path))

    hints = result.detection_hints
    assert isinstance(hints, dict), (
        f"{module_name}: detection_hints should be a dict, got {type(hints)}"
    )
    # Skipped / blocked / errored results may legitimately omit a
    # logsource. The invariant only applies when the module reached
    # a success-shaped status (success / partial_success), since
    # those are the results the engine writes detection drafts for.
    if result.status not in {"success", "partial_success"}:
        pytest.skip(
            f"{module_name}: status was {result.status!r}; logsource "
            f"requirement only applies to success-shaped results"
        )
    assert "logsource" in hints, (
        f"{module_name}: detection_hints missing `logsource` block. The "
        f"Sigma / YARA-L generators would silently fall back to "
        f"`process_creation/windows`, mis-labeling the technique."
    )
    logsource = hints["logsource"]
    assert isinstance(logsource, dict), (
        f"{module_name}: logsource should be a dict, got {type(logsource)}"
    )
    assert "category" in logsource and "product" in logsource, (
        f"{module_name}: logsource missing required keys "
        f"(`category` / `product`); got {logsource!r}"
    )
    assert isinstance(logsource["category"], str) and logsource["category"], (
        f"{module_name}: logsource.category must be a non-empty string"
    )
    assert isinstance(logsource["product"], str) and logsource["product"], (
        f"{module_name}: logsource.product must be a non-empty string"
    )


def test_intentionally_empty_modules_truly_emit_empty_hints(
    _registered_modules, tmp_path
) -> None:
    """Modules listed in :data:`_INTENTIONALLY_EMPTY_HINT_MODULES`
    must actually emit empty detection_hints. If a future change
    makes one of them start emitting a hint, the maintainer should
    be forced to either remove the exemption or namespace the new
    hint appropriately.
    """
    for module_name in _INTENTIONALLY_EMPTY_HINT_MODULES:
        if module_name not in _registered_modules:
            continue
        module = _registered_modules[module_name]
        params = _MINIMAL_PARAMS.get(module_name, {})
        result = module.execute(params, _ctx(tmp_path))
        assert result.detection_hints == {}, (
            f"{module_name}: marked intentionally-empty but emitted "
            f"hints {result.detection_hints!r}. Remove from "
            f"_INTENTIONALLY_EMPTY_HINT_MODULES or namespace the new "
            f"hint correctly."
        )
