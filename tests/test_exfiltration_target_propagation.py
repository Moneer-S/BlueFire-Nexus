"""`exfiltration` consumes upstream collection target via previous_step_results.

Pinned invariants:

1. Explicit ``target`` in step params always wins over upstream
   propagation (mirrors discovery -> credential_access contract).
2. When ``target`` is absent and ``target_from_step`` is set, the
   exfiltration module picks the upstream step's ``artifacts.target``
   (single-target upstream like collection) and records the
   propagation in artifacts / detection_hints / telemetry details.
3. Missing or empty ``previous_step_results`` falls back to the
   documented module default (``lab-host``).
4. Destructive guard still fires before propagation resolves
   (lab-acknowledgment requirement is unchanged).
5. ``source_host`` detection-hint key reflects the resolved target so
   SIEM searches can group exfil events by source host.
6. End-to-end the shipped ``enterprise_intrusion_chain`` scenario
   surfaces the propagated target on the exfil-over-c2 step.

Built on top of the same ``resolve_target_from_step`` helper as
PR #43's discovery -> credential_access pair, so helper-level edge
cases (mutation safety, list/scalar precedence, missing upstream)
are pinned in ``test_credential_access_target_propagation.py`` and
not duplicated here.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.standard_modules import ExfiltrationModule


def _exfil_context(
    output_dir: Path, *, previous: Dict[str, Dict[str, Any]] | None = None
) -> Dict[str, Any]:
    return {
        "run_id": "exfil-prop-test",
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


def test_exfiltration_reads_target_from_upstream_collection(tmp_path: Path) -> None:
    module = ExfiltrationModule()
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
            "method": "via_c2",
            "target_from_step": "stage-collected-data",
            "network_touch": False,
        },
        _exfil_context(output_dir, previous=upstream),
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
    # source_host hint reflects the resolved target so SIEM searches
    # can group by source.
    assert result.detection_hints["source_host"] == "corp-fileshare"
    # Telemetry detail also records the propagation.
    assert (
        result.telemetry[0].details["target_propagated_from_step"]
        == "stage-collected-data"
    )
    assert result.telemetry[0].details["target"] == "corp-fileshare"


def test_exfiltration_explicit_target_wins_over_step_propagation(
    tmp_path: Path,
) -> None:
    module = ExfiltrationModule()
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
            "method": "via_c2",
            "target": "explicit-host",
            "target_from_step": "stage-collected-data",
            "network_touch": False,
        },
        _exfil_context(output_dir, previous=upstream),
    )

    assert result.status == "success"
    assert result.artifacts["target"] == "explicit-host"
    assert "target_propagated_from_step" not in result.artifacts
    assert "target_propagated_from_step" not in result.detection_hints
    # source_host still mirrors the resolved target.
    assert result.detection_hints["source_host"] == "explicit-host"


def test_exfiltration_no_upstream_falls_back_to_default(tmp_path: Path) -> None:
    module = ExfiltrationModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    result = module.execute(
        {"method": "via_c2", "network_touch": False},
        _exfil_context(output_dir),
    )

    assert result.status == "success"
    assert result.artifacts["target"] == "lab-host"
    assert "target_propagated_from_step" not in result.artifacts


def test_exfiltration_destructive_guard_fires_before_propagation(
    tmp_path: Path,
) -> None:
    """Lab-acknowledgment guard remains the first failure path.

    A destructive request without ``i_understand_this_is_a_lab`` must
    still fail with the documented marker even when an upstream
    propagation source exists — otherwise a destructive request could
    silently succeed by piggybacking on a chained scenario.
    """
    module = ExfiltrationModule()
    output_dir = tmp_path / "run"
    output_dir.mkdir(parents=True)

    upstream = {
        "stage-collected-data": {
            "artifacts": {"target": "corp-fileshare"},
        }
    }

    result = module.execute(
        {
            "method": "via_c2",
            "destructive": True,
            "target_from_step": "stage-collected-data",
        },
        _exfil_context(output_dir, previous=upstream),
    )

    assert result.status == "failure"
    assert result.error == "missing_lab_acknowledgment"


def test_exfiltration_artifact_paths_remain_under_output_dir(
    tmp_path: Path,
) -> None:
    """Artifact-path discipline preserved even with the new propagation path."""
    module = ExfiltrationModule()
    output_dir = (tmp_path / "run").resolve()
    output_dir.mkdir(parents=True)

    upstream = {"stage-collected-data": {"artifacts": {"target": "corp-fileshare"}}}
    result = module.execute(
        {
            "method": "via_c2",
            "target_from_step": "stage-collected-data",
            "network_touch": False,
        },
        _exfil_context(output_dir, previous=upstream),
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


def test_enterprise_intrusion_chain_propagates_collection_target_into_exfiltration(
    tmp_path: Path,
) -> None:
    """The shipped enterprise_intrusion_chain scenario chains
    collection -> exfiltration via target_from_step. The exfil step
    must end up with the collection step's host (`corp-fileshare`)
    rather than the module default.
    """
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))

    result = nexus.run_scenario_file("scenarios/enterprise_intrusion_chain.yaml")
    assert result["status"] in {"success", "partial_success"}

    exfil_step = next(s for s in result["steps"] if s["step_id"] == "exfil-over-c2")
    assert exfil_step["status"] == "success"
    artifacts = exfil_step["artifacts"]
    # The scenario YAML for exfil-over-c2 declares
    # `target_from_step: stage-collected-data` and no explicit
    # `target`. The collection step's artifact target is
    # `corp-fileshare`, so the exfil step must end up with that target
    # plus the propagation marker.
    assert artifacts["target"] == "corp-fileshare"
    assert artifacts["target_propagated_from_step"] == "stage-collected-data"
