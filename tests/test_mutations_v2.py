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


_RUNTIME_CATALOG_NAMES: Dict[Tuple[str, str], str] = {
    ("anti_detection", "method"): "_ANTI_DETECTION_PROFILES",
    ("collection", "technique"): "_COLLECTION_PROFILES",
    ("command_control", "channel"): "_COMMAND_CONTROL_PROFILES",
    ("credential_access", "technique"): "_CREDENTIAL_ACCESS_PROFILES",
    ("defense_evasion", "technique"): "_DEFENSE_EVASION_PROFILES",
    ("discovery", "discovery_type"): "_DISCOVERY_PROFILES",
    ("exfiltration", "method"): "_EXFILTRATION_PROFILES",
    ("impact", "technique"): "_IMPACT_PROFILES",
    ("initial_access", "vector"): "_INITIAL_ACCESS_PROFILES",
    ("intelligence", "intelligence_type"): "_INTELLIGENCE_PROFILES",
    ("lateral_movement", "technique"): "_LATERAL_MOVEMENT_PROFILES",
    ("network_obfuscator", "protocol"): "_NETWORK_OBFUSCATOR_PROFILES",
    ("persistence", "technique"): "_PERSISTENCE_PROFILES",
    ("privilege_escalation", "technique"): "_PRIVILEGE_ESCALATION_PROFILES",
    ("reconnaissance", "source"): "_RECONNAISSANCE_PROFILES",
    ("resource_development", "resource_type"): "_RESOURCE_DEVELOPMENT_PROFILES",
}


# Slots intentionally absent from MUTATION_CATALOG even though the
# runtime has a matching profile catalog. Each entry must include a
# rationale so a future contributor reading the test understands why
# the mutation surface skips the slot. An empty set means every
# slot in ``_RUNTIME_CATALOG_NAMES`` MUST be present in
# ``MUTATION_CATALOG`` - the test fails loudly otherwise.
_INTENTIONALLY_ABSENT_FROM_MUTATION_CATALOG: Dict[Tuple[str, str], str] = {}


@pytest.mark.parametrize(
    "module,key",
    sorted(_RUNTIME_CATALOG_NAMES.keys()),
)
def test_mutation_catalog_is_subset_of_runtime_catalog(
    module: str, key: str
) -> None:
    """Every catalog candidate the mutation engine proposes must be a
    valid value the runtime module actually accepts. Otherwise a
    proposed swap lands on an unrecognised value, falls back to the
    module's default, and the mutation is silently a no-op.

    Codex P1 (PR #155) caught this for execution / network_obfuscator
    / anti_detection / reconnaissance: the catalog had values that
    didn't exist in the runtime profile catalogs. This test now
    walks every ``MUTATION_CATALOG`` slot rather than the original
    11; a future drift between the mutation catalog and the runtime
    catalog surfaces as a parametrized failure naming both modules.

    Codex follow-up P2 (PR #155) caught a related defect: silently
    skipping when a slot is missing from MUTATION_CATALOG meant
    deleting a mutation slot would still pass CI. The fix below
    treats every runtime slot as required-in-mutation-catalog
    unless the slot is explicitly listed in
    :data:`_INTENTIONALLY_ABSENT_FROM_MUTATION_CATALOG` with a
    documented rationale.
    """

    from src.core.modules.impl import standard_modules

    if (module, key) not in MUTATION_CATALOG:
        if (module, key) in _INTENTIONALLY_ABSENT_FROM_MUTATION_CATALOG:
            return
        pytest.fail(
            f"runtime module {module!r} has a profile catalog at "
            f"{_RUNTIME_CATALOG_NAMES[(module, key)]!r} but no "
            f"corresponding mutation slot ({module}, {key}) - either "
            f"add the slot to MUTATION_CATALOG or list it in "
            f"_INTENTIONALLY_ABSENT_FROM_MUTATION_CATALOG with a "
            f"reason. Without a mutation slot, defenders running "
            f"random_mutation will never explore this module's "
            f"alternative techniques."
        )
    runtime_catalog = getattr(
        standard_modules, _RUNTIME_CATALOG_NAMES[(module, key)]
    )
    declared = set(MUTATION_CATALOG[(module, key)])
    runtime_keys = set(runtime_catalog.keys())
    missing_in_runtime = declared - runtime_keys
    assert not missing_in_runtime, (
        f"mutation catalog ({module}, {key}) declares values that the "
        f"runtime module does not recognise: {sorted(missing_in_runtime)}"
    )


def test_mutation_catalog_does_not_declare_execution_slot() -> None:
    """ExecutionModule reads ``command`` / ``cmd`` (free-form), not a
    catalog-keyed slot. Pin the absence of any execution entry so a
    future contributor doesn't reintroduce a no-op like the original
    PR #155 ``("execution", "command_template")`` (Codex P1)."""

    execution_entries = [
        slot for slot in MUTATION_CATALOG if slot[0] == "execution"
    ]
    assert execution_entries == [], (
        f"unexpected execution entries in MUTATION_CATALOG: {execution_entries}; "
        "execution accepts a free-form command string, not a catalog slot"
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


# ---------------------------------------------------------------------------
# Execution interpreter swap (content-aware command rewrite)
# ---------------------------------------------------------------------------


def test_propose_command_interpreter_swaps_powershell_to_cmd_bash_python() -> None:
    """A canonical ``powershell -nop -c <payload>`` step should yield
    rewrite mutations to cmd / bash / python."""

    from src.core.mutations import propose_command_interpreter_swaps

    step = {
        "module": "execution",
        "params": {"command": "powershell -nop -c Get-Date"},
    }
    swaps = propose_command_interpreter_swaps(step)
    rewritten = {s.to_value for s in swaps}
    assert "cmd /c Get-Date" in rewritten
    assert "bash -c Get-Date" in rewritten
    assert "python -c Get-Date" in rewritten
    # Should NOT propose a swap to itself.
    assert all("powershell" not in s.to_value for s in swaps)


def test_propose_command_interpreter_swaps_returns_empty_for_unknown_interpreter() -> None:
    """A command using an interpreter outside the catalog (e.g.
    ``rundll32.exe``) yields no rewrite mutations."""

    from src.core.mutations import propose_command_interpreter_swaps

    step = {
        "module": "execution",
        "params": {"command": "rundll32.exe shell32.dll,Control_RunDLL"},
    }
    assert propose_command_interpreter_swaps(step) == []


def test_propose_command_interpreter_swaps_skips_encoded_commands() -> None:
    """``-EncodedCommand`` payloads are operator content, not catalog
    swaps - encoding semantics don't translate across interpreters."""

    from src.core.mutations import propose_command_interpreter_swaps

    encoded_step = {
        "module": "execution",
        "params": {"command": "powershell -nop -w hidden -enc UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwA="},
    }
    assert propose_command_interpreter_swaps(encoded_step) == []


def test_propose_command_interpreter_swaps_rejects_non_execution_step() -> None:
    """Only execution steps get interpreter rewrites - a
    persistence step with a coincidental ``command`` param yields
    nothing."""

    from src.core.mutations import propose_command_interpreter_swaps

    step = {
        "module": "persistence",
        "params": {"command": "powershell -nop -c X"},
    }
    assert propose_command_interpreter_swaps(step) == []


def test_propose_command_interpreter_swaps_handles_quoted_path() -> None:
    """A quoted-path PowerShell invocation (``"C:\\Program Files
    \\PowerShell\\7\\pwsh.exe" -nop -c X``) should still resolve
    to the powershell entry."""

    from src.core.mutations import propose_command_interpreter_swaps

    step = {
        "module": "execution",
        "params": {
            "command": '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -nop -c "Get-Date"'
        },
    }
    swaps = propose_command_interpreter_swaps(step)
    rewritten = {s.to_value for s in swaps}
    assert "cmd /c \"Get-Date\"" in rewritten
    assert "bash -c \"Get-Date\"" in rewritten


def test_propose_command_interpreter_swaps_recognises_cmd_bash_python() -> None:
    """Each canonical interpreter starting point should yield swaps
    to the other three."""

    from src.core.mutations import propose_command_interpreter_swaps

    for current_command, expected_prefix in [
        ("cmd /c whoami", "powershell -nop -c"),
        ("bash -c id", "cmd /c"),
        ("python -c print", "powershell -nop -c"),
    ]:
        step = {
            "module": "execution",
            "params": {"command": current_command},
        }
        swaps = propose_command_interpreter_swaps(step)
        rewritten = {s.to_value for s in swaps}
        # At least one of the three alternative prefixes must appear.
        assert any(
            expected_prefix in candidate
            for candidate in rewritten
        ), (
            f"expected prefix {expected_prefix!r} for command "
            f"{current_command!r}; got {rewritten}"
        )


def test_propose_mutations_includes_interpreter_swaps_for_execution_step() -> None:
    """The top-level ``propose_mutations`` should fold interpreter
    rewrites into the result for execution steps so callers don't
    need to know about the second helper."""

    from src.core.mutations import propose_mutations

    step = {
        "module": "execution",
        "params": {"command": "powershell -nop -c Get-Date"},
    }
    proposals = propose_mutations(step)
    rewritten_commands = {
        m.to_value for m in proposals if m.param_key == "command"
    }
    assert "cmd /c Get-Date" in rewritten_commands
    assert "bash -c Get-Date" in rewritten_commands
    assert "python -c Get-Date" in rewritten_commands


def test_apply_mutation_with_interpreter_swap_sets_command_and_history() -> None:
    """An interpreter swap mutation applied via ``apply_mutation``
    should overwrite ``params.command`` and append the rewrite
    rationale to ``mutation_history``."""

    from src.core.mutations import (
        apply_mutation,
        propose_command_interpreter_swaps,
    )

    step = {
        "step_id": "exec-1",
        "module": "execution",
        "params": {"command": "powershell -nop -c Get-Date"},
    }
    mutation = next(
        s for s in propose_command_interpreter_swaps(step)
        if s.to_value.startswith("cmd /c")
    )
    out = apply_mutation(step, mutation)
    assert out["params"]["command"] == "cmd /c Get-Date"
    history = out["params"]["mutation_history"]
    assert len(history) == 1
    assert "powershell" in history[0]["rationale"]
    assert "cmd" in history[0]["rationale"]


def test_propose_command_interpreter_swaps_handles_cmd_alias() -> None:
    """The ``cmd`` interpreter doesn't have a payload-flag conflict;
    extracting payload after ``/c`` should preserve the entire
    remaining command line."""

    from src.core.mutations import propose_command_interpreter_swaps

    step = {
        "module": "execution",
        "params": {"command": "cmd /c \"echo hello world\""},
    }
    swaps = propose_command_interpreter_swaps(step)
    # The payload "echo hello world" (with quotes) should appear in
    # every alternative.
    for s in swaps:
        assert "hello world" in s.to_value


def test_propose_command_interpreter_swaps_returns_empty_for_empty_params() -> None:
    """A step with no command field yields no swaps."""

    from src.core.mutations import propose_command_interpreter_swaps

    assert propose_command_interpreter_swaps(
        {"module": "execution", "params": {}}
    ) == []
    assert propose_command_interpreter_swaps(
        {"module": "execution"}
    ) == []
    assert propose_command_interpreter_swaps(
        {"module": "execution", "params": {"command": ""}}
    ) == []


def test_propose_command_interpreter_swaps_recognises_cmd_param_alias() -> None:
    """The runtime accepts ``params.cmd`` as an alias for ``command``;
    the interpreter rewrite should support both."""

    from src.core.mutations import propose_command_interpreter_swaps

    step = {
        "module": "execution",
        "params": {"cmd": "powershell -nop -c Get-Date"},
    }
    swaps = propose_command_interpreter_swaps(step)
    assert swaps
    # The mutation should target the ``cmd`` key, not ``command``.
    assert all(s.param_key == "cmd" for s in swaps)
