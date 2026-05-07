"""``impact`` consumes upstream collection target via previous_step_results.

Pinned invariants (mirror the exfiltration pair):

1. Explicit ``target`` in step params always wins over upstream
   propagation.
2. When ``target`` is absent and ``target_from_step`` is set, the
   impact module picks the upstream step's ``artifacts.target``
   (single-target upstream like collection) and records the
   propagation in artifacts / detection_hints / telemetry details.
3. Missing or empty ``previous_step_results`` falls back to the
   documented module default (``lab-host``).
4. ``target_host`` detection-hint key reflects the resolved target
   so SIEM searches can group impact events by victim host.
5. End-to-end the shipped ``enterprise_intrusion_chain`` scenario
   surfaces the propagated target on the ransomware-impact step.

Built on top of the same ``resolve_target_from_step`` helper as
the discovery -> credential_access and collection -> exfiltration
pairs, so helper-level edge cases (mutation safety, list/scalar
precedence, missing upstream) are pinned in
``test_credential_access_target_propagation.py`` and not duplicated
here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.standard_modules import ImpactModule


def _impact_context(
    output_dir: Path, *, previous: Dict[str, Dict[str, Any]] | None = None
) -> Dict[str, Any]:
    return {
        "run_id": "impact-prop-test",
        "output_dir": output_dir,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
        "previous_step_results": dict(previous or {}),
    }


# ---------------------------------------------------------------------------
# Module-level integration tests
# ---------------------------------------------------------------------------


def test_impact_reads_target_from_upstream_collection(tmp_path: Path) -> None:
    """The standard collection -> impact propagation pair.

    The ``stage-collected-data`` step writes ``artifacts.target=
    corp-fileshare``. A downstream impact step that opts in via
    ``target_from_step`` picks up that host as its target without
    re-declaring it, modelling a ransomware operator who encrypts
    exactly the host where collection staged data.
    """
    module = ImpactModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    upstream = {
        "stage-collected-data": {
            "status": "success",
            "module": "collection",
            "techniques": ["T1074.001"],
            "artifacts": {
                "technique": "file_staging",
                "target": "corp-fileshare",
                "mitre_technique": "T1074.001",
            },
        }
    }

    result = module.execute(
        {
            "technique": "data_encryption",
            "target_from_step": "stage-collected-data",
            "network_touch": False,
        },
        _impact_context(output_dir, previous=upstream),
    )

    assert result.status == "success"
    assert result.artifacts["target"] == "corp-fileshare"
    assert (
        result.artifacts["target_propagated_from_step"] == "stage-collected-data"
    )
    assert (
        result.detection_hints["target_propagated_from_step"]
        == "stage-collected-data"
    )
    # target_host hint reflects the resolved target so SIEM searches
    # can group impact events by victim host.
    assert result.detection_hints["target_host"] == "corp-fileshare"
    # Telemetry detail also records the propagation.
    assert (
        result.telemetry[0].details["target_propagated_from_step"]
        == "stage-collected-data"
    )
    assert result.telemetry[0].details["target"] == "corp-fileshare"


def test_impact_explicit_target_wins_over_step_propagation(
    tmp_path: Path,
) -> None:
    """Explicit ``target`` always wins over an upstream propagation.

    Same precedence as discovery -> credential_access (PR #43): the
    operator's explicit choice is never silently overridden by an
    upstream step's artifacts.
    """
    module = ImpactModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    upstream = {
        "stage-collected-data": {
            "status": "success",
            "module": "collection",
            "techniques": ["T1074.001"],
            "artifacts": {"target": "upstream-host"},
        }
    }

    result = module.execute(
        {
            "technique": "data_encryption",
            "target": "explicit-host",
            "target_from_step": "stage-collected-data",
            "network_touch": False,
        },
        _impact_context(output_dir, previous=upstream),
    )

    assert result.status == "success"
    assert result.artifacts["target"] == "explicit-host"
    # No propagation marker when the explicit target wins.
    assert "target_propagated_from_step" not in result.artifacts
    assert "target_propagated_from_step" not in result.detection_hints
    assert "target_propagated_from_step" not in result.telemetry[0].details


def test_impact_falls_back_to_default_when_no_propagation(tmp_path: Path) -> None:
    """No explicit target, no ``target_from_step``: fall back to the default."""
    module = ImpactModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    result = module.execute(
        {"technique": "data_encryption", "network_touch": False},
        _impact_context(output_dir),
    )

    assert result.status == "success"
    # Documented default for the impact module.
    assert result.artifacts["target"] == "lab-host"
    assert "target_propagated_from_step" not in result.artifacts


def test_impact_missing_upstream_step_falls_back_to_default(
    tmp_path: Path,
) -> None:
    """``target_from_step`` referencing a step that did not run falls back."""
    module = ImpactModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    upstream = {
        "some-other-step": {
            "status": "success",
            "module": "collection",
            "artifacts": {"target": "other-host"},
        }
    }

    result = module.execute(
        {
            "technique": "data_encryption",
            "target_from_step": "definitely-not-a-step",
            "network_touch": False,
        },
        _impact_context(output_dir, previous=upstream),
    )
    assert result.artifacts["target"] == "lab-host"
    assert "target_propagated_from_step" not in result.artifacts


# ---------------------------------------------------------------------------
# Multi-technique parametrised coverage
# ---------------------------------------------------------------------------


def test_impact_propagation_works_for_every_technique_profile(tmp_path: Path) -> None:
    """Every documented impact technique honours target propagation.

    Pins that the propagation hook is in the module's shared code
    path, not technique-specific. Techniques iterated explicitly so
    a future refactor cannot silently skip the propagation for any
    single profile.
    """
    module = ImpactModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    upstream = {
        "stage-collected-data": {
            "status": "success",
            "module": "collection",
            "techniques": ["T1074.001"],
            "artifacts": {"target": "corp-fileshare"},
        }
    }

    for technique in (
        "data_encryption",
        "data_destruction",
        "data_manipulation",
        "service_stop",
        "system_shutdown",
        "endpoint_dos",
        "resource_hijacking",
    ):
        result = module.execute(
            {
                "technique": technique,
                "target_from_step": "stage-collected-data",
                "network_touch": False,
            },
            _impact_context(output_dir, previous=upstream),
        )
        assert result.status == "success", technique
        assert result.artifacts["target"] == "corp-fileshare", technique
        assert (
            result.artifacts.get("target_propagated_from_step")
            == "stage-collected-data"
        ), technique


# ---------------------------------------------------------------------------
# End-to-end scenario propagation
# ---------------------------------------------------------------------------


def test_enterprise_intrusion_chain_impact_step_picks_up_collection_target(
    tmp_path: Path,
) -> None:
    """End-to-end: the impact step receives ``corp-fileshare`` from collection.

    Pins the YAML wiring in ``scenarios/enterprise_intrusion_chain
    .yaml``: a future edit that drops ``target_from_step`` from the
    ransomware-impact step will fail this test and surface the
    regression at the scenario level rather than only at the
    module-level test above.
    """
    config = ConfigManager().to_dict()
    nexus = BlueFireNexus.__new__(BlueFireNexus)
    nexus.__init__()  # type: ignore[misc]
    # Pin output root inside the test temp dir so the scenario
    # writes do not pollute the project ``output/`` tree. Mirrors
    # the convention used by other end-to-end propagation tests.
    nexus.config = dict(config)
    nexus.config.setdefault("general", {})["output_root"] = str(tmp_path)
    nexus.config_manager.set("general.output_root", str(tmp_path))

    summary = nexus.run_scenario_file(
        "scenarios/enterprise_intrusion_chain.yaml",
        run_id="impact-prop-e2e",
    )
    assert summary["status"] in {"success", "partial_success"}

    impact_step = next(
        (step for step in summary["steps"] if step.get("step_id") == "ransomware-impact"),
        None,
    )
    assert impact_step is not None, [s.get("step_id") for s in summary["steps"]]
    artifacts = impact_step.get("artifacts") or {}
    assert artifacts.get("target") == "corp-fileshare"
    assert artifacts.get("target_propagated_from_step") == "stage-collected-data"
