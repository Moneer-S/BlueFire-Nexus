"""Operator-facing execution mode definitions.

BlueFire-Nexus has three conceptual execution modes the operator
chooses between when planning a run:

- ``simulate`` — the default. Every module synthesises plausible
  artifacts but produces no real-world side effect. Safe for
  unattended use, demos, and detection-rule iteration.
- ``emulate`` — modules execute their logic against the local
  filesystem (writing real artifacts under ``output_root``) but
  still suppress outbound network calls and real process spawns.
  Per-legacy-pack ``lab_confirmation`` is required when a scenario
  references a legacy pack.
- ``live-lab`` — modules perform real network calls inside
  ``allowed_subnets`` and may spawn real subprocesses. Requires
  explicit ``lab_confirmation`` across the board AND a configured
  ``allowed_subnets`` list. Designed for isolated lab networks
  only — never for shared / production environments.

This module is the single source of truth for what each mode
implies. The CLI surfaces (``explain-mode`` /
``mode-plan``) read from here, as does the operator console's
mode panel (in a follow-up PR). Adding a new mode means adding
one entry to :data:`MODE_METADATA` — the rest of the surfaces
read off the dataclass fields.

The module is **declarative only**: it does NOT mutate config,
does not enforce gates, and does not start any execution. The
runtime safety model lives in :mod:`src.core.safety` /
:mod:`src.core.legacy_controls` and is unchanged by this module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple


@dataclass(frozen=True, slots=True)
class ModeDefinition:
    """Declarative description of a single operator mode.

    ``required_gates`` enumerates the human-readable confirmations
    the operator must satisfy before the runtime accepts the mode
    (``i_understand_this_is_a_lab``, ``allowed_subnets`` configured,
    per-pack ``lab_confirmation`` etc.).

    ``config_overrides`` is the minimal dot-path config patch a
    config writer would apply to enter this mode. The chain graph /
    mode planner uses these as the canonical mode→config translation
    so an operator inspecting ``mode-plan --mode <mode>`` sees the
    exact key/value pairs that would be written.

    ``side_effects`` lists, in plain prose, the categories of real-
    world side effects the mode permits (filesystem writes /
    outbound network / process spawns / registry writes).
    Defender-readable so an operator can sanity-check whether the
    mode is safe for their target environment.

    ``warnings`` lists the operator-facing cautions the CLI / console
    should print before allowing the mode to be entered. Empty for
    ``simulate``; loud for ``live-lab``.
    """

    name: str
    description: str
    required_gates: Tuple[str, ...] = ()
    config_overrides: Tuple[Tuple[str, Any], ...] = ()
    side_effects: Tuple[str, ...] = ()
    warnings: Tuple[str, ...] = ()
    safe_for_unattended: bool = True


# Canonical mode order. Drives the order ``explain-mode`` and the
# operator console render in. Earliest = safest.
MODE_NAMES: Tuple[str, ...] = ("simulate", "emulate", "live-lab")


MODE_METADATA: Dict[str, ModeDefinition] = {
    "simulate": ModeDefinition(
        name="simulate",
        description=(
            "Safe-by-default. Every module synthesises plausible "
            "artifacts but produces no real-world side effect. The "
            "scenario timeline, manifest, detection drafts, viewer, "
            "and operator console all populate from synthetic data. "
            "Suitable for unattended use, demos, and detection-rule "
            "iteration. The runtime baseline."
        ),
        required_gates=(),
        config_overrides=(
            ("general.dry_run", True),
            ("modules.legacy.enable_all_lab_capabilities", False),
        ),
        side_effects=(
            "writes artifacts under output_root (manifest, report, "
            "detection drafts, telemetry).",
            "no outbound network calls.",
            "no real subprocess spawns.",
            "no registry / system-state mutation.",
        ),
        warnings=(),
        safe_for_unattended=True,
    ),
    "emulate": ModeDefinition(
        name="emulate",
        description=(
            "Modules execute their logic against the local filesystem "
            "(writing more detailed artifacts under output_root) but "
            "still suppress outbound network calls and real process "
            "spawns. Per-legacy-pack ``lab_confirmation`` is required "
            "when a scenario references a legacy pack. Suitable for "
            "rich-artifact rehearsals on a single host."
        ),
        required_gates=(
            "Per-pack ``modules.legacy.<pack>.lab_confirmation: true`` "
            "for any legacy pack the scenario uses.",
            "Per-pack ``modules.legacy.<pack>.mode: emulate``.",
        ),
        config_overrides=(
            ("general.dry_run", False),
            ("modules.legacy.global_mode", "emulate"),
        ),
        side_effects=(
            "writes deeper, more-detailed artifacts under output_root.",
            "may write to local lab filesystem paths the scenario "
            "operates on.",
            "no outbound network calls.",
            "no real subprocess spawns.",
        ),
        warnings=(
            "Inspect every per-pack lab_confirmation before running. "
            "Emulate mode landing on a shared host can leave deeper "
            "artifacts than simulate mode does.",
        ),
        safe_for_unattended=False,
    ),
    "live-lab": ModeDefinition(
        name="live-lab",
        description=(
            "Modules perform REAL outbound network calls inside "
            "``allowed_subnets`` and may spawn REAL subprocesses. "
            "Requires explicit ``lab_confirmation`` across the board "
            "AND a configured ``allowed_subnets`` list. Designed for "
            "isolated lab networks only -- never for shared or "
            "production environments."
        ),
        required_gates=(
            "``modules.legacy.global_lab_acknowledged: true``.",
            "``modules.legacy.lab_confirmation: true``.",
            "``general.safeties.allowed_subnets: [...]`` populated with "
            "the lab network's CIDR ranges.",
            "Per-pack ``modules.legacy.<pack>.lab_confirmation: true`` "
            "for every legacy pack the scenario uses.",
            "Per-step ``network_touch: true`` on steps that should "
            "actually fire real network traffic.",
        ),
        config_overrides=(
            ("general.dry_run", False),
            ("modules.legacy.enable_all_lab_capabilities", True),
            ("modules.legacy.global_lab_acknowledged", True),
            ("modules.legacy.lab_confirmation", True),
            ("modules.legacy.global_mode", "emulate"),
        ),
        side_effects=(
            "real outbound network calls inside allowed_subnets.",
            "real subprocess spawns where modules support them.",
            "registry / system-state mutation in scope of the lab "
            "host.",
            "filesystem writes to lab paths beyond output_root.",
        ),
        warnings=(
            "live-lab is NOT a default. Never enable live-lab on a "
            "shared host or production environment.",
            "Confirm the lab network is isolated from production "
            "before populating allowed_subnets.",
            "Live-lab will modify real system state. Snapshot the "
            "lab host before running.",
            "Every legacy pack used in live-lab requires its own "
            "lab_confirmation -- review them before each run.",
        ),
        safe_for_unattended=False,
    ),
}


def resolve_mode(name: str) -> ModeDefinition:
    """Return the :class:`ModeDefinition` for ``name`` or raise ``ValueError``.

    Accepts the canonical name or a small set of aliases (``sim`` /
    ``simulate``, ``em`` / ``emulate``, ``live`` / ``lab`` /
    ``live-lab`` / ``live_lab``) so the CLI is forgiving on minor
    typing variation while the underlying surface stays canonical.
    """

    canonical = (name or "").strip().lower().replace("_", "-")
    aliases = {
        "sim": "simulate",
        "simulate": "simulate",
        "em": "emulate",
        "emulate": "emulate",
        "live": "live-lab",
        "lab": "live-lab",
        "live-lab": "live-lab",
    }
    resolved = aliases.get(canonical, canonical)
    if resolved not in MODE_METADATA:
        raise ValueError(
            f"Unknown mode {name!r}. Expected one of: "
            f"{', '.join(MODE_NAMES)}"
        )
    return MODE_METADATA[resolved]


# ---------------------------------------------------------------------------
# Mode plan: per-scenario projection
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ModePlan:
    """Per-scenario projection of what running in a given mode would mean.

    Composes the static :class:`ModeDefinition` with scenario-specific
    detail: which modules are touched, which legacy packs the scenario
    references (and therefore which per-pack ``lab_confirmation``
    rows the operator must satisfy), and a rendered config patch.

    The plan is deterministic and offline -- it never mutates config,
    never starts execution, never opens a network connection. It is
    a planning aid: the operator reviews the plan, confirms they
    accept the gates / warnings, and then applies the config patch
    via the ordinary config-writer path before running the scenario.
    """

    mode: str
    scenario_name: str
    scenario_id: str
    step_count: int
    modules: Tuple[str, ...]
    legacy_packs: Tuple[str, ...]
    config_overrides: Tuple[Tuple[str, Any], ...]
    required_gates: Tuple[str, ...]
    warnings: Tuple[str, ...]
    side_effects: Tuple[str, ...]
    safe_for_unattended: bool

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serialisable dict of the full plan."""

        return {
            "mode": self.mode,
            "scenario_name": self.scenario_name,
            "scenario_id": self.scenario_id,
            "step_count": self.step_count,
            "modules": list(self.modules),
            "legacy_packs": list(self.legacy_packs),
            "config_overrides": [
                {"key": key, "value": value}
                for key, value in self.config_overrides
            ],
            "required_gates": list(self.required_gates),
            "warnings": list(self.warnings),
            "side_effects": list(self.side_effects),
            "safe_for_unattended": self.safe_for_unattended,
        }


# Legacy module-name → pack mapping (mirrors the operator-console
# categorisation from PR #167's v2 quality indicators). When a
# scenario references one of these modules, the corresponding pack's
# ``lab_confirmation`` becomes a required gate for any non-simulate
# mode.
_LEGACY_MODULE_PACK: Dict[str, str] = {
    "legacy_actor_profile": "actor_pack",
    "legacy_apt28_research": "actor_pack",
    "legacy_apt29_research": "actor_pack",
    "legacy_apt32_research": "actor_pack",
    "legacy_apt38_research": "actor_pack",
    "legacy_apt41_research": "actor_pack",
    "legacy_protocol_research": "c2_pack",
    "legacy_stealth_research": "stealth_pack",
    "legacy_collection": "tactic_pack",
    "legacy_credential_access": "tactic_pack",
    "legacy_impact": "tactic_pack",
    "legacy_lateral_movement": "tactic_pack",
    "legacy_privilege_escalation": "tactic_pack",
}


def build_mode_plan(
    scenario: Any,
    mode: str,
) -> ModePlan:
    """Compute a :class:`ModePlan` for a scenario and a target mode.

    ``scenario`` is the loaded :class:`src.core.scenario.Scenario`.
    ``mode`` accepts the same name / alias set as :func:`resolve_mode`.

    The plan composes the mode metadata with the scenario's specific
    module list and legacy-pack references. Per-pack
    ``lab_confirmation`` rows are appended to ``required_gates`` so
    the operator sees one consolidated gate list rather than having
    to cross-reference the mode definition with the scenario's
    module list.
    """

    definition = resolve_mode(mode)
    steps = list(getattr(scenario, "steps", []) or [])
    modules: List[str] = []
    legacy_packs: List[str] = []
    seen_modules: set = set()
    seen_packs: set = set()
    for step in steps:
        module = str(getattr(step, "module", "") or "").strip()
        if not module or module in seen_modules:
            continue
        seen_modules.add(module)
        modules.append(module)
        pack = _LEGACY_MODULE_PACK.get(module)
        if pack and pack not in seen_packs:
            seen_packs.add(pack)
            legacy_packs.append(pack)

    # Compose required gates: mode-level gates + per-pack confirmation
    # rows for every legacy pack the scenario actually uses. The
    # per-pack rows are skipped for ``simulate`` (which has no gates
    # at all by definition) so a no-legacy scenario in simulate mode
    # surfaces a clean empty gate list.
    gates: List[str] = list(definition.required_gates)
    if definition.name != "simulate":
        for pack in legacy_packs:
            gates.append(
                f"``modules.legacy.{pack}.lab_confirmation: true`` "
                f"for the {pack} pack referenced by this scenario."
            )

    return ModePlan(
        mode=definition.name,
        scenario_name=str(getattr(scenario, "name", "") or ""),
        scenario_id=str(getattr(scenario, "id", "") or ""),
        step_count=len(steps),
        modules=tuple(modules),
        legacy_packs=tuple(legacy_packs),
        config_overrides=tuple(definition.config_overrides),
        required_gates=tuple(gates),
        warnings=tuple(definition.warnings),
        side_effects=tuple(definition.side_effects),
        safe_for_unattended=definition.safe_for_unattended,
    )


__all__ = [
    "MODE_METADATA",
    "MODE_NAMES",
    "ModeDefinition",
    "ModePlan",
    "build_mode_plan",
    "resolve_mode",
]
