"""`credential_access` consumes upstream discovery target via previous_step_results.

Pinned invariants:

1. Explicit ``target`` in step params always wins over upstream
   propagation.
2. When ``target`` is absent and ``target_from_step`` is set, the
   credential-access module picks the upstream step's
   ``artifacts.targets[0]`` as the effective target and records the
   propagation in artifacts / detection_hints / telemetry details.
3. Missing or empty ``previous_step_results`` falls back to the
   documented module default (``lab-host``).
4. The runtime does NOT mutate ``previous_step_results`` from inside
   the credential-access execute path (read-only contract).
5. The downstream module's artifact paths still resolve under
   ``context["output_dir"]`` (artifact-path discipline preserved).

The implementation lives behind a small generic helper
(``src.core.modules.base.resolve_target_from_step``) so future
downstream modules can adopt the same pattern.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.base import resolve_target_from_step
from src.core.modules.impl.standard_modules import CredentialAccessModule


# ---------------------------------------------------------------------------
# Helper-level tests (resolve_target_from_step)
# ---------------------------------------------------------------------------


def test_explicit_target_wins_over_upstream() -> None:
    target, propagated = resolve_target_from_step(
        {"target": "explicit-host", "target_from_step": "step-1"},
        {
            "previous_step_results": {
                "step-1": {"artifacts": {"targets": ["upstream-host"]}}
            }
        },
        fallback="default-host",
    )
    assert target == "explicit-host"
    assert propagated is None


def test_target_from_step_uses_artifacts_targets_list_first_entry() -> None:
    target, propagated = resolve_target_from_step(
        {"target_from_step": "step-1"},
        {
            "previous_step_results": {
                "step-1": {"artifacts": {"targets": ["host-a", "host-b"]}}
            }
        },
        fallback="default-host",
    )
    assert target == "host-a"
    assert propagated == "step-1"


def test_target_from_step_prefers_single_target_field_over_list() -> None:
    """Some upstream modules expose a scalar `target`; honour that first."""
    target, propagated = resolve_target_from_step(
        {"target_from_step": "step-1"},
        {
            "previous_step_results": {
                "step-1": {
                    "artifacts": {
                        "target": "single-host",
                        "targets": ["other-host-a", "other-host-b"],
                    }
                }
            }
        },
        fallback="default-host",
    )
    assert target == "single-host"
    assert propagated == "step-1"


def test_missing_previous_step_results_falls_back_safely() -> None:
    target, propagated = resolve_target_from_step(
        {"target_from_step": "step-1"},
        {},  # no previous_step_results at all
        fallback="default-host",
    )
    assert target == "default-host"
    assert propagated is None


def test_unknown_upstream_step_falls_back_safely() -> None:
    target, propagated = resolve_target_from_step(
        {"target_from_step": "step-3"},
        {
            "previous_step_results": {
                "step-1": {"artifacts": {"targets": ["host-a"]}}
            }
        },
        fallback="default-host",
    )
    assert target == "default-host"
    assert propagated is None


def test_upstream_with_empty_targets_list_falls_back_safely() -> None:
    target, propagated = resolve_target_from_step(
        {"target_from_step": "step-1"},
        {
            "previous_step_results": {
                "step-1": {"artifacts": {"targets": []}}
            }
        },
        fallback="default-host",
    )
    assert target == "default-host"
    assert propagated is None


def test_helper_does_not_mutate_previous_step_results() -> None:
    """Read-only contract: helper must never modify the accumulator."""
    accumulator: Dict[str, Dict[str, Any]] = {
        "step-1": {"artifacts": {"targets": ["host-a"]}}
    }
    snapshot_before = repr(accumulator)
    resolve_target_from_step(
        {"target_from_step": "step-1"},
        {"previous_step_results": accumulator},
        fallback="default-host",
    )
    assert repr(accumulator) == snapshot_before


# ---------------------------------------------------------------------------
# Module-level integration tests (CredentialAccessModule)
# ---------------------------------------------------------------------------


def _credential_context(
    output_dir: Path, *, previous: Dict[str, Dict[str, Any]] | None = None
) -> Dict[str, Any]:
    return {
        "run_id": "cred-prop-test",
        "output_dir": output_dir,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
        "previous_step_results": dict(previous or {}),
    }


def test_credential_access_reads_target_from_upstream_discovery(tmp_path: Path) -> None:
    module = CredentialAccessModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    upstream = {
        "discovery-step": {
            "status": "success",
            "module": "discovery",
            "techniques": ["T1083"],
            "artifacts": {
                "discovery_type": "files",
                "targets": ["finance-analyst-laptop"],
                "discovered": [],
            },
        }
    }

    result = module.execute(
        {
            "technique": "browser_credentials",
            "target_from_step": "discovery-step",
            "network_touch": False,
        },
        _credential_context(output_dir, previous=upstream),
    )

    assert result.status == "success"
    assert result.artifacts["target"] == "finance-analyst-laptop"
    assert (
        result.artifacts["target_propagated_from_step"] == "discovery-step"
    )
    assert (
        result.detection_hints["target_propagated_from_step"] == "discovery-step"
    )
    # Telemetry detail also records the propagation so report tables /
    # SIEM searches can surface "this step's target came from <step>".
    assert (
        result.telemetry[0].details["target_propagated_from_step"]
        == "discovery-step"
    )


def test_credential_access_explicit_target_wins_over_step_propagation(
    tmp_path: Path,
) -> None:
    module = CredentialAccessModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    upstream = {
        "discovery-step": {
            "status": "success",
            "module": "discovery",
            "techniques": ["T1083"],
            "artifacts": {"targets": ["upstream-host"]},
        }
    }

    result = module.execute(
        {
            "technique": "browser_credentials",
            "target": "explicit-host",
            "target_from_step": "discovery-step",
            "network_touch": False,
        },
        _credential_context(output_dir, previous=upstream),
    )

    assert result.status == "success"
    assert result.artifacts["target"] == "explicit-host"
    # No propagation marker when explicit target wins.
    assert "target_propagated_from_step" not in result.artifacts
    assert "target_propagated_from_step" not in result.detection_hints


def test_credential_access_no_upstream_falls_back_to_default(tmp_path: Path) -> None:
    module = CredentialAccessModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    # No previous_step_results, no target_from_step, no explicit target.
    result = module.execute(
        {"technique": "browser_credentials", "network_touch": False},
        _credential_context(output_dir),
    )

    assert result.status == "success"
    assert result.artifacts["target"] == "lab-host"
    assert "target_propagated_from_step" not in result.artifacts


def test_credential_access_artifact_paths_remain_under_output_dir(
    tmp_path: Path,
) -> None:
    """Artifact-path discipline preserved even with the new propagation path."""
    module = CredentialAccessModule()
    output_dir = (tmp_path / "run").resolve()
    output_dir.mkdir(parents=True)

    upstream = {
        "discovery-step": {
            "artifacts": {"targets": ["host-a"]},
        }
    }
    result = module.execute(
        {
            "technique": "browser_credentials",
            "target_from_step": "discovery-step",
            "network_touch": False,
        },
        _credential_context(output_dir, previous=upstream),
    )
    # Walk every string in artifacts; any that names a real on-disk
    # file must live under output_dir.
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


def test_enterprise_intrusion_chain_propagates_discovery_target_into_credential_access(
    tmp_path: Path,
) -> None:
    """Run the shipped enterprise_intrusion_chain scenario and confirm the
    credential-access step picks up its target from the discovery step
    rather than re-declaring it.
    """
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))

    result = nexus.run_scenario_file("scenarios/enterprise_intrusion_chain.yaml")
    assert result["status"] in {"success", "partial_success"}

    credential_step = next(
        s for s in result["steps"] if s["step_id"] == "harvest-browser-creds"
    )
    assert credential_step["status"] == "success"
    artifacts = credential_step["artifacts"]
    # The scenario YAML for harvest-browser-creds no longer declares an
    # explicit `target`; it sets `target_from_step: enumerate-files`.
    # The discovery step's artifacts.targets is ["finance-analyst-laptop"],
    # so the credential-access step must end up with that target and a
    # propagation marker.
    assert artifacts["target"] == "finance-analyst-laptop"
    assert artifacts["target_propagated_from_step"] == "enumerate-files"
