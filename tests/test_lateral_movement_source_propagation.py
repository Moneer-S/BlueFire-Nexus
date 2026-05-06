"""`lateral_movement` consumes upstream credential_access target via previous_step_results.

Pinned invariants (third `previous_step_results` consumer pair after
PRs #43 and #48):

1. Explicit ``source`` in step params always wins over upstream
   ``source_from_step`` propagation.
2. When ``source`` is absent and ``source_from_step`` is set, the
   lateral_movement module picks the upstream step's
   ``artifacts.target`` (single-target upstream like
   credential_access) as the effective `source` and records the
   propagation in artifacts / detection_hints / telemetry details.
3. ``target_from_step`` is the orthogonal slot for the destination
   host. ``source_from_step`` and ``target_from_step`` are
   independent — explicit values, propagation slots, and fallbacks
   are evaluated per-axis.
4. Missing or empty ``previous_step_results`` falls back to the
   documented module defaults (``lab-attacker`` for ``source``,
   ``lab-host`` for ``target``).
5. Detection-hint ``source_host`` / ``target_host`` keys reflect
   the resolved values so SIEM searches and report tables can
   group by either axis.
6. End-to-end the shipped ``enterprise_intrusion_chain`` scenario
   surfaces the propagated source on the `lateral-to-fileshare`
   step.

Helper-level edge cases (mutation safety, list/scalar precedence,
missing upstream) stay pinned in
``tests/test_credential_access_target_propagation.py`` — not
duplicated here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.standard_modules import LateralMovementModule


def _lateral_context(
    output_dir: Path, *, previous: Dict[str, Dict[str, Any]] | None = None
) -> Dict[str, Any]:
    return {
        "run_id": "lateral-prop-test",
        "output_dir": output_dir,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
        "previous_step_results": dict(previous or {}),
    }


# ---------------------------------------------------------------------------
# source_from_step (the new slot)
# ---------------------------------------------------------------------------


def test_lateral_reads_source_from_upstream_credential_access(tmp_path: Path) -> None:
    module = LateralMovementModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    upstream = {
        "harvest-browser-creds": {
            "status": "success",
            "module": "credential_access",
            "techniques": ["T1555.003"],
            "artifacts": {
                "technique": "browser_credentials",
                "target": "finance-analyst-laptop",
                "mitre_technique": "T1555.003",
            },
        }
    }

    result = module.execute(
        {
            "technique": "psexec",
            "source_from_step": "harvest-browser-creds",
            "target": "corp-fileshare",
            "network_touch": False,
        },
        _lateral_context(output_dir, previous=upstream),
    )

    assert result.status == "success"
    assert result.artifacts["source"] == "finance-analyst-laptop"
    assert result.artifacts["target"] == "corp-fileshare"
    assert (
        result.artifacts["source_propagated_from_step"] == "harvest-browser-creds"
    )
    # Target was explicit — no propagation marker for it.
    assert "target_propagated_from_step" not in result.artifacts

    assert result.detection_hints["source_host"] == "finance-analyst-laptop"
    assert result.detection_hints["target_host"] == "corp-fileshare"
    assert (
        result.detection_hints["source_propagated_from_step"]
        == "harvest-browser-creds"
    )

    telemetry = result.telemetry[0].details
    assert telemetry["source"] == "finance-analyst-laptop"
    assert telemetry["target"] == "corp-fileshare"
    assert telemetry["source_propagated_from_step"] == "harvest-browser-creds"
    assert "target_propagated_from_step" not in telemetry


def test_lateral_explicit_source_wins_over_source_from_step(tmp_path: Path) -> None:
    module = LateralMovementModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    upstream = {
        "harvest-browser-creds": {
            "artifacts": {"target": "upstream-host"},
        }
    }

    result = module.execute(
        {
            "technique": "psexec",
            "source": "explicit-attacker",
            "source_from_step": "harvest-browser-creds",
            "target": "corp-fileshare",
            "network_touch": False,
        },
        _lateral_context(output_dir, previous=upstream),
    )

    assert result.status == "success"
    assert result.artifacts["source"] == "explicit-attacker"
    assert "source_propagated_from_step" not in result.artifacts
    assert "source_propagated_from_step" not in result.detection_hints
    assert result.detection_hints["source_host"] == "explicit-attacker"


# ---------------------------------------------------------------------------
# target_from_step still works (keeps PR #43-style contract intact)
# ---------------------------------------------------------------------------


def test_lateral_reads_target_from_upstream_discovery(tmp_path: Path) -> None:
    module = LateralMovementModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    upstream = {
        "enumerate-shares": {
            "status": "success",
            "module": "discovery",
            "techniques": ["T1135"],
            "artifacts": {
                "discovery_type": "shares",
                "targets": ["corp-fileshare", "corp-archive"],
            },
        }
    }

    result = module.execute(
        {
            "technique": "psexec",
            "source": "finance-analyst-laptop",
            "target_from_step": "enumerate-shares",
            "network_touch": False,
        },
        _lateral_context(output_dir, previous=upstream),
    )

    assert result.status == "success"
    assert result.artifacts["target"] == "corp-fileshare"
    assert (
        result.artifacts["target_propagated_from_step"] == "enumerate-shares"
    )
    assert (
        result.detection_hints["target_propagated_from_step"]
        == "enumerate-shares"
    )
    assert result.detection_hints["target_host"] == "corp-fileshare"


def test_lateral_both_axes_propagated_independently(tmp_path: Path) -> None:
    """source_from_step and target_from_step are independent slots —
    a scenario can propagate both in one step."""
    module = LateralMovementModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    upstream = {
        "harvest-browser-creds": {
            "artifacts": {"target": "finance-analyst-laptop"},
        },
        "enumerate-shares": {
            "artifacts": {"targets": ["corp-fileshare"]},
        },
    }

    result = module.execute(
        {
            "technique": "psexec",
            "source_from_step": "harvest-browser-creds",
            "target_from_step": "enumerate-shares",
            "network_touch": False,
        },
        _lateral_context(output_dir, previous=upstream),
    )

    assert result.artifacts["source"] == "finance-analyst-laptop"
    assert result.artifacts["target"] == "corp-fileshare"
    assert (
        result.artifacts["source_propagated_from_step"] == "harvest-browser-creds"
    )
    assert (
        result.artifacts["target_propagated_from_step"] == "enumerate-shares"
    )


# ---------------------------------------------------------------------------
# Fallbacks
# ---------------------------------------------------------------------------


def test_lateral_no_upstream_falls_back_to_documented_defaults(tmp_path: Path) -> None:
    module = LateralMovementModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    result = module.execute(
        {"technique": "psexec", "network_touch": False},
        _lateral_context(output_dir),
    )

    assert result.status == "success"
    assert result.artifacts["source"] == "lab-attacker"
    assert result.artifacts["target"] == "lab-host"
    assert "source_propagated_from_step" not in result.artifacts
    assert "target_propagated_from_step" not in result.artifacts


def test_lateral_unknown_upstream_step_falls_back_per_axis(tmp_path: Path) -> None:
    """A `*_from_step` pointing at a non-existent step falls back to
    the per-axis documented default; the other axis is unaffected."""
    module = LateralMovementModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    result = module.execute(
        {
            "technique": "psexec",
            "source_from_step": "missing-step",
            "target": "corp-fileshare",
            "network_touch": False,
        },
        _lateral_context(output_dir),
    )

    assert result.artifacts["source"] == "lab-attacker"
    assert "source_propagated_from_step" not in result.artifacts
    assert result.artifacts["target"] == "corp-fileshare"


# ---------------------------------------------------------------------------
# Artifact-path discipline
# ---------------------------------------------------------------------------


def test_lateral_artifact_paths_remain_under_output_dir(tmp_path: Path) -> None:
    module = LateralMovementModule()
    output_dir = (tmp_path / "run").resolve()
    output_dir.mkdir(parents=True)

    upstream = {"harvest-browser-creds": {"artifacts": {"target": "finance-laptop"}}}
    result = module.execute(
        {
            "technique": "psexec",
            "source_from_step": "harvest-browser-creds",
            "target": "corp-fileshare",
            "network_touch": False,
        },
        _lateral_context(output_dir, previous=upstream),
    )
    for value in result.artifacts.values():
        if isinstance(value, str):
            candidate = Path(value)
            if candidate.exists() and candidate.is_file():
                assert (
                    output_dir in candidate.resolve().parents
                    or candidate.resolve() == output_dir
                )


# ---------------------------------------------------------------------------
# End-to-end scenario test
# ---------------------------------------------------------------------------


def test_enterprise_intrusion_chain_propagates_credential_access_target_into_lateral_source(
    tmp_path: Path,
) -> None:
    """The shipped enterprise_intrusion_chain scenario chains
    credential_access -> lateral_movement via source_from_step. The
    lateral step must end up with the credential-access step's host
    (`finance-analyst-laptop`) as the pivot source rather than the
    module default.
    """
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))

    result = nexus.run_scenario_file("scenarios/enterprise_intrusion_chain.yaml")
    assert result["status"] in {"success", "partial_success"}

    lateral_step = next(
        s for s in result["steps"] if s["step_id"] == "lateral-to-fileshare"
    )
    assert lateral_step["status"] == "success"
    artifacts = lateral_step["artifacts"]
    assert artifacts["source"] == "finance-analyst-laptop"
    assert (
        artifacts["source_propagated_from_step"] == "harvest-browser-creds"
    )
    assert artifacts["target"] == "corp-fileshare"
    # Target was explicit in the scenario — no propagation marker.
    assert "target_propagated_from_step" not in artifacts
