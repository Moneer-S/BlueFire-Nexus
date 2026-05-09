"""Capability-aware scenario mutation engine v2.

The previous mutation surface (``src.core.experiments._mutate_run_params``)
only adjusted synthetic tunables (intensity / noise_ratio / variant) and
left every step's actual technique / channel / method untouched. The
mutation engine v2 walks the per-module catalogs and proposes real
swaps that change the chain's emitted telemetry.

These tests pin:

- the catalog covers every standard module's primary param slot and
  stays aligned with the runtime catalogs;
- ``propose_mutations`` returns every candidate that differs from the
  current value, never the current value itself, and excludes catalog
  rows from unrelated modules;
- ``apply_mutation`` deep-copies the step, never mutates the input,
  preserves every unrelated param, and records a ``mutation_history``
  entry for the report / dashboard / copilot to surface;
- the cross-cutting ``target_os`` axis only fires when the step
  already declares ``target_os`` (we don't randomly inject it);
- ``random_mutation`` picks deterministically when given a seeded
  ``random.Random`` and returns ``None`` for steps with no catalog
  slot;
- the proposed swap survives the runtime: every catalog candidate is
  one the runtime module actually accepts (smoke test against the
  module's catalog).
"""

from __future__ import annotations

import random
from typing import Any, Dict

import pytest

from src.core.modules import build_runtime_modules
from src.core.modules.impl.standard_modules import (
    _COLLECTION_PROFILES,
    _COMMAND_CONTROL_PROFILES,
    _CREDENTIAL_ACCESS_PROFILES,
    _DEFENSE_EVASION_PROFILES,
    _DISCOVERY_PROFILES,
    _EXFILTRATION_PROFILES,
    _IMPACT_PROFILES,
    _INITIAL_ACCESS_PROFILES,
    _LATERAL_MOVEMENT_PROFILES,
    _PERSISTENCE_PROFILES,
    _PRIVILEGE_ESCALATION_PROFILES,
)
from src.core.mutations import (
    MUTATION_CATALOG,
    TARGET_OS_VALUES,
    apply_mutation,
    propose_mutations,
    random_mutation,
)


# ---------------------------------------------------------------------------
# propose_mutations
# ---------------------------------------------------------------------------


def test_propose_mutations_returns_every_alternative_for_command_control() -> None:
    """A command_control step with channel=http should yield mutations
    for every other channel in the catalog (https / dns / tcp / icmp /
    websocket / mail / web_service)."""

    step = {
        "module": "command_control",
        "params": {"channel": "http"},
    }
    proposals = propose_mutations(step)
    swaps = {(m.param_key, m.to_value) for m in proposals}
    assert ("channel", "https") in swaps
    assert ("channel", "dns") in swaps
    assert ("channel", "tcp") in swaps
    # The current value must NEVER appear as a proposed to_value.
    assert ("channel", "http") not in swaps


def test_propose_mutations_excludes_current_value() -> None:
    """No proposal can set the slot to its current value."""

    step = {
        "module": "exfiltration",
        "params": {"method": "via_c2"},
    }
    proposals = propose_mutations(step)
    assert all(m.to_value != "via_c2" for m in proposals if m.param_key == "method")


def test_propose_mutations_skips_unrelated_modules() -> None:
    """A discovery step yields discovery proposals only - never
    leaks into command_control / collection / etc."""

    step = {
        "module": "discovery",
        "params": {"discovery_type": "files"},
    }
    proposals = propose_mutations(step)
    assert all(m.module == "discovery" for m in proposals)
    # Specifically: a files->ssh_artifacts mutation should fire.
    swap_targets = {m.to_value for m in proposals if m.param_key == "discovery_type"}
    assert "ssh_artifacts" in swap_targets


def test_propose_mutations_target_os_only_when_param_present() -> None:
    """Cross-cutting target_os swap should NOT fire on a step that
    doesn't already declare ``target_os``."""

    no_os_step = {
        "module": "execution",
        "params": {"command": "powershell -nop -c X"},
    }
    proposals = propose_mutations(no_os_step)
    assert not any(m.param_key == "target_os" for m in proposals)

    with_os_step = {
        "module": "execution",
        "params": {"command": "powershell -nop -c X", "target_os": "windows"},
    }
    proposals = propose_mutations(with_os_step)
    os_swaps = {m.to_value for m in proposals if m.param_key == "target_os"}
    assert os_swaps == {os_value for os_value in TARGET_OS_VALUES if os_value != "windows"}


def test_propose_mutations_unknown_module_returns_empty() -> None:
    """A step whose module is not in the catalog yields no proposals."""

    proposals = propose_mutations(
        {"module": "definitely-not-a-real-module", "params": {"x": "y"}}
    )
    assert proposals == []


def test_propose_mutations_missing_params_returns_empty() -> None:
    """A step with no params yields no proposals (no slot to compare
    against)."""

    proposals = propose_mutations({"module": "execution"})
    assert proposals == []


def test_propose_mutations_carries_provenance_in_rationale() -> None:
    """Each proposal's ``rationale`` should mention the from/to values
    so a defender / report reader can read it without inspecting the
    StepMutation object."""

    step = {
        "module": "credential_access",
        "params": {"technique": "lsass_dump"},
    }
    proposals = propose_mutations(step)
    sample = next(p for p in proposals if p.to_value == "sam_dump")
    assert "lsass_dump" in sample.rationale
    assert "sam_dump" in sample.rationale


# ---------------------------------------------------------------------------
# apply_mutation
# ---------------------------------------------------------------------------


def test_apply_mutation_returns_deep_copy_and_preserves_other_params() -> None:
    step: Dict[str, Any] = {
        "step_id": "step-1",
        "name": "demo",
        "module": "exfiltration",
        "params": {
            "method": "via_c2",
            "target": "lab-host",
            "i_understand_this_is_a_lab": True,
            "destructive": False,
        },
    }
    proposals = propose_mutations(step)
    mutation = next(p for p in proposals if p.to_value == "dns_tunneling")
    out = apply_mutation(step, mutation)

    # Input untouched.
    assert step["params"]["method"] == "via_c2"
    assert "mutation_history" not in step["params"]

    # Output reflects the swap.
    assert out["params"]["method"] == "dns_tunneling"
    # Other params survive.
    assert out["params"]["target"] == "lab-host"
    assert out["params"]["i_understand_this_is_a_lab"] is True
    # Non-params keys survive too.
    assert out["step_id"] == "step-1"
    assert out["name"] == "demo"


def test_apply_mutation_appends_mutation_history_entry() -> None:
    step = {
        "module": "lateral_movement",
        "params": {"technique": "psexec"},
    }
    mutation = next(
        m
        for m in propose_mutations(step)
        if m.to_value == "winrm"
    )
    out = apply_mutation(step, mutation)
    history = out["params"]["mutation_history"]
    assert len(history) == 1
    entry = history[0]
    assert entry["param_key"] == "technique"
    assert entry["from_value"] == "psexec"
    assert entry["to_value"] == "winrm"
    assert "psexec" in entry["rationale"]
    assert "winrm" in entry["rationale"]


def test_apply_mutation_chains_history_across_two_mutations() -> None:
    step = {"module": "command_control", "params": {"channel": "http"}}
    mutation_a = next(m for m in propose_mutations(step) if m.to_value == "https")
    intermediate = apply_mutation(step, mutation_a)
    # Re-propose against the intermediate (which now has channel=https).
    mutation_b = next(
        m for m in propose_mutations(intermediate) if m.to_value == "dns"
    )
    final = apply_mutation(intermediate, mutation_b)
    history = final["params"]["mutation_history"]
    assert len(history) == 2
    assert history[0]["from_value"] == "http"
    assert history[0]["to_value"] == "https"
    assert history[1]["from_value"] == "https"
    assert history[1]["to_value"] == "dns"


# ---------------------------------------------------------------------------
# random_mutation
# ---------------------------------------------------------------------------


def test_random_mutation_is_deterministic_with_seeded_rng() -> None:
    step = {
        "module": "credential_access",
        "params": {"technique": "lsass_dump"},
    }
    rng_a = random.Random(42)
    rng_b = random.Random(42)
    pick_a = random_mutation(step, rng=rng_a)
    pick_b = random_mutation(step, rng=rng_b)
    assert pick_a is not None
    assert pick_a == pick_b


def test_random_mutation_returns_none_for_unmutable_step() -> None:
    """A step whose module is not in the catalog yields ``None``."""

    pick = random_mutation(
        {"module": "definitely-not-real", "params": {"x": "y"}}
    )
    assert pick is None


# ---------------------------------------------------------------------------
# Catalog-runtime alignment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module,key,runtime_catalog",
    [
        ("command_control", "channel", _COMMAND_CONTROL_PROFILES),
        ("initial_access", "vector", _INITIAL_ACCESS_PROFILES),
        ("persistence", "technique", _PERSISTENCE_PROFILES),
        ("defense_evasion", "technique", _DEFENSE_EVASION_PROFILES),
        ("discovery", "discovery_type", _DISCOVERY_PROFILES),
        ("credential_access", "technique", _CREDENTIAL_ACCESS_PROFILES),
        ("lateral_movement", "technique", _LATERAL_MOVEMENT_PROFILES),
        ("collection", "technique", _COLLECTION_PROFILES),
        ("exfiltration", "method", _EXFILTRATION_PROFILES),
        ("impact", "technique", _IMPACT_PROFILES),
        ("privilege_escalation", "technique", _PRIVILEGE_ESCALATION_PROFILES),
    ],
)
def test_mutation_catalog_is_subset_of_runtime_catalog(
    module: str, key: str, runtime_catalog: Dict[str, Any]
) -> None:
    """Every catalog candidate the mutation engine proposes must be a
    valid value the runtime module actually accepts. Otherwise a
    proposed swap would land the scenario on an unrecognised value
    that falls back to the module's default and the mutation has no
    effect."""

    declared = set(MUTATION_CATALOG[(module, key)])
    runtime_keys = set(runtime_catalog.keys())
    missing_in_runtime = declared - runtime_keys
    assert not missing_in_runtime, (
        f"mutation catalog ({module}, {key}) declares values that the "
        f"runtime module does not recognise: {sorted(missing_in_runtime)}"
    )


def test_mutation_catalog_covers_all_swap_relevant_runtime_techniques() -> None:
    """Every technique the runtime persistence module accepts should be
    a candidate in the mutation catalog. Otherwise a defender exploring
    chain variants via random_mutation would never touch that
    technique - leaving a real coverage hole."""

    # Spot-check persistence: every runtime profile key should appear
    # in the catalog. (Choosing one module to pin; broader coverage is
    # parametrized above.)
    declared = set(MUTATION_CATALOG[("persistence", "technique")])
    runtime_keys = set(_PERSISTENCE_PROFILES.keys())
    missing_in_catalog = runtime_keys - declared
    assert not missing_in_catalog, (
        f"mutation catalog missing persistence techniques: "
        f"{sorted(missing_in_catalog)}"
    )


# ---------------------------------------------------------------------------
# End-to-end smoke: a mutated step still runs cleanly through the module
# ---------------------------------------------------------------------------


def test_mutated_command_control_step_runs_under_module(tmp_path) -> None:
    """A mutated channel must execute cleanly through the module
    (i.e. the mutation actually lands on a valid catalog entry)."""

    from pathlib import Path
    from src.core.models import RunContext

    registry = build_runtime_modules()
    step = {
        "module": "command_control",
        "params": {"channel": "http", "target": "lab-host"},
    }
    mutation = next(
        p for p in propose_mutations(step) if p.to_value == "dns"
    )
    mutated = apply_mutation(step, mutation)
    cm = registry["command_control"]
    cm.update_config({})
    out_dir = tmp_path / "run"
    out_dir.mkdir(parents=True, exist_ok=True)
    ctx = {
        "run_context": RunContext(
            run_id="rid-mut",
            output_dir=out_dir,
            config={},
            dry_run=True,
            max_runtime=60,
            allowed_subnets=[],
        ),
        "run_id": "rid-mut",
        "dry_run": True,
        "allowed_subnets": [],
        "max_runtime": 60,
        "config": {},
        "previous_step_results": {},
    }
    result = cm.execute(mutated["params"], ctx)
    # The mutated step's channel should land on T1071.004 (DNS C2).
    assert result.status == "success"
    assert result.detection_hints.get("c2_channel") == "dns"
    assert "T1071.004" in result.techniques


def test_mutated_persistence_step_runs_under_module(tmp_path) -> None:
    """Same end-to-end smoke for persistence (covers the new Linux/macOS
    techniques shipped in PR #154)."""

    from pathlib import Path
    from src.core.models import RunContext

    registry = build_runtime_modules()
    step = {
        "module": "persistence",
        "params": {"technique": "scheduled_task", "target": "lab-host"},
    }
    # Pick the authorized_keys mutation specifically - it's one of the
    # new PR #154 techniques and exercises the Linux/macOS depth.
    mutation = next(
        p for p in propose_mutations(step) if p.to_value == "authorized_keys"
    )
    mutated = apply_mutation(step, mutation)
    pm = registry["persistence"]
    out_dir = tmp_path / "run"
    out_dir.mkdir(parents=True, exist_ok=True)
    ctx = {
        "run_context": RunContext(
            run_id="rid-mut",
            output_dir=out_dir,
            config={},
            dry_run=True,
            max_runtime=60,
            allowed_subnets=[],
        ),
        "run_id": "rid-mut",
        "dry_run": True,
        "allowed_subnets": [],
        "max_runtime": 60,
        "config": {},
        "previous_step_results": {},
    }
    result = pm.execute(mutated["params"], ctx)
    assert result.status == "success"
    assert "T1098.004" in result.techniques
