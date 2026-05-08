"""C2-endpoint propagation pair (resource_development -> command_control).

The fifth `previous_step_results` consumer pair plumbed into the
shipped enterprise_intrusion_chain. The four pre-existing pairs cover
host-target propagation (discovery -> credential_access,
credential_access -> lateral_movement source, collection ->
exfiltration, collection -> impact). This pair covers a different
axis: an upstream `resource_development` step registers a domain;
the downstream `command_control` step picks up that registered
domain via `c2_endpoint_from_step` and shapes it into a c2_url.

Pinned invariants:

* Explicit `c2_url` always wins over `c2_endpoint_from_step`.
* When upstream emits a hostname (no scheme), the downstream
  shapes it into the default `https://<host>/c2` URL form.
* When upstream emits a value that already looks like a URL
  (has `://`), the downstream uses it verbatim.
* Propagation source is recorded in artifacts / hints / telemetry
  details under `c2_endpoint_propagated_from_step` so the report /
  dashboard can surface the cross-step linkage.
* End-to-end through the BlueFireNexus runtime: the shipped
  enterprise_intrusion_chain.yaml `c2-channel` step propagates
  from `stage-infrastructure` and the resulting artifact has the
  expected fields.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.standard_modules import CommandControlModule


def _ctx(tmp_path: Path, **overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "run_id": "c2-endpoint-propagation-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }
    base.update(overrides)
    return base


def test_explicit_c2_url_wins_over_propagation(tmp_path: Path) -> None:
    """When `c2_url` is set explicitly, propagation source is ignored."""
    mod = CommandControlModule()
    context = _ctx(
        tmp_path,
        previous_step_results={
            "stage-infrastructure": {
                "artifacts": {"target": "should-be-ignored.example.lab"}
            }
        },
    )
    result = mod.execute(
        {
            "channel": "https",
            "c2_url": "https://operator-supplied.example.lab/path",
            "c2_endpoint_from_step": "stage-infrastructure",
        },
        context,
    )
    assert result.artifacts["c2_url"] == "https://operator-supplied.example.lab/path"
    # Propagation source must NOT be recorded when explicit c2_url wins.
    assert "c2_endpoint_propagated_from_step" not in result.artifacts
    assert "c2_endpoint_propagated_from_step" not in result.detection_hints


def test_propagation_from_hostname_shapes_into_default_url(tmp_path: Path) -> None:
    """Upstream hostname (no scheme) -> downstream `https://<host>/c2`."""
    mod = CommandControlModule()
    context = _ctx(
        tmp_path,
        previous_step_results={
            "stage-infrastructure": {
                "artifacts": {"target": "exfil.example.lab"}
            }
        },
    )
    result = mod.execute(
        {"channel": "https", "c2_endpoint_from_step": "stage-infrastructure"},
        context,
    )
    assert result.artifacts["c2_url"] == "https://exfil.example.lab/c2"
    assert result.artifacts["c2_endpoint_propagated_from_step"] == "stage-infrastructure"
    assert result.detection_hints["c2_endpoint_propagated_from_step"] == "stage-infrastructure"
    assert result.telemetry[0].details["c2_endpoint_propagated_from_step"] == "stage-infrastructure"


def test_propagation_from_url_uses_value_verbatim(tmp_path: Path) -> None:
    """Upstream value that already has a scheme is used verbatim."""
    mod = CommandControlModule()
    context = _ctx(
        tmp_path,
        previous_step_results={
            "stage-infrastructure": {
                "artifacts": {"target": "http://staging.lab/api/beacon"}
            }
        },
    )
    result = mod.execute(
        {"channel": "http", "c2_endpoint_from_step": "stage-infrastructure"},
        context,
    )
    assert result.artifacts["c2_url"] == "http://staging.lab/api/beacon"
    assert result.artifacts["c2_endpoint_propagated_from_step"] == "stage-infrastructure"


def test_propagation_from_targets_list_picks_first(tmp_path: Path) -> None:
    """Multi-target upstream (e.g. discovery) -> propagation picks first target."""
    mod = CommandControlModule()
    context = _ctx(
        tmp_path,
        previous_step_results={
            "discovered-c2-candidates": {
                "artifacts": {
                    "targets": ["c2-1.lab", "c2-2.lab", "c2-3.lab"]
                }
            }
        },
    )
    result = mod.execute(
        {"channel": "https", "c2_endpoint_from_step": "discovered-c2-candidates"},
        context,
    )
    assert result.artifacts["c2_url"] == "https://c2-1.lab/c2"
    assert result.artifacts["c2_endpoint_propagated_from_step"] == "discovered-c2-candidates"


def test_no_propagation_no_c2_url_falls_back_to_default(tmp_path: Path) -> None:
    """No `c2_url` and no `c2_endpoint_from_step` -> default URL."""
    mod = CommandControlModule()
    result = mod.execute({"channel": "https"}, _ctx(tmp_path))
    assert result.artifacts["c2_url"] == "https://example.invalid/c2"
    assert "c2_endpoint_propagated_from_step" not in result.artifacts


def test_c2_endpoint_from_step_with_missing_upstream_falls_back(tmp_path: Path) -> None:
    """Forward / missing reference falls back to default; no propagation
    marker (so the runtime can't silently claim propagation succeeded)."""
    mod = CommandControlModule()
    context = _ctx(tmp_path, previous_step_results={})
    result = mod.execute(
        {"channel": "https", "c2_endpoint_from_step": "no-such-step"},
        context,
    )
    assert result.artifacts["c2_url"] == "https://example.invalid/c2"
    assert "c2_endpoint_propagated_from_step" not in result.artifacts


def test_propagation_surfaces_in_detection_hint_title(tmp_path: Path) -> None:
    """Detection draft title includes the resolved C2 URL so an analyst
    looking at the rule can correlate it back to the upstream registration."""
    mod = CommandControlModule()
    context = _ctx(
        tmp_path,
        previous_step_results={
            "stage-infrastructure": {
                "artifacts": {"target": "invoice-portal.example.lab"}
            }
        },
    )
    result = mod.execute(
        {"channel": "https", "c2_endpoint_from_step": "stage-infrastructure"},
        context,
    )
    assert "invoice-portal.example.lab" in result.detection_hints["title"]
    assert result.detection_hints["network_url"] == "https://invoice-portal.example.lab/c2"


# ---------------------------------------------------------------------------
# End-to-end through the BlueFireNexus runtime
# ---------------------------------------------------------------------------


def test_enterprise_chain_c2_step_propagates_from_register_c2_domain(tmp_path: Path) -> None:
    """End-to-end: the shipped `enterprise_intrusion_chain.yaml`
    `c2-channel` step picks up its endpoint from `stage-infrastructure`
    via the new `c2_endpoint_from_step` slot.
    """
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    nexus = BlueFireNexus(str(cfg_path))
    summary = nexus.run_scenario_file("scenarios/enterprise_intrusion_chain.yaml")
    c2_step = next(
        step for step in summary["steps"] if step.get("step_id") == "c2-channel"
    )
    artifacts = c2_step.get("artifacts") or {}
    assert artifacts.get("c2_url") == "https://invoice-portal.example.lab/c2", (
        f"c2-channel step did not propagate from stage-infrastructure; "
        f"artifacts: {artifacts}"
    )
    assert artifacts.get("c2_endpoint_propagated_from_step") == "stage-infrastructure"
