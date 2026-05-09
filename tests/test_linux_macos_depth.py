"""Linux / macOS proportional-depth additions.

The Windows-first execution depth pass (PR #151) added the T1218
signed-binary proxy family. This file pins the corresponding (smaller,
proportional) Linux / macOS additions:

- ``persistence`` gains:
  - ``authorized_keys`` (T1098.004) — the canonical Unix key-based
    persistence path; defenders alert on file_event writes to
    ``~/.ssh/authorized_keys``.
  - ``systemd_user_service`` (T1543.002) — the per-user systemd unit
    pattern; distinct from the system service / launch_agent already
    in the catalog.
  - ``macos_login_item`` (T1547.015) — macOS login items / login-
    items plist persistence.
- ``discovery`` gains:
  - ``ssh_artifacts`` (T1083) — SSH artifact enumeration
    (``~/.ssh/id_*``, ``known_hosts``, ``authorized_keys``,
    ``config``); the canonical pivot precursor on every Unix-like
    host.
  - ``systemd_units`` (T1518) — per-user / system systemd unit-file
    walk.
  - ``macos_plist_artifacts`` (T1518) — LaunchAgents / LaunchDaemons /
    preferences plist enumeration.

Per the ``proportional depth`` directive, these are scoped narrowly:
the platform-specific addition only lights up where the tradecraft
actually differs from the existing Windows-shaped catalog rows.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import RunContext
from src.core.modules.impl.standard_modules import (
    DiscoveryModule,
    PersistenceModule,
    _DISCOVERY_PROFILES,
    _PERSISTENCE_PROFILES,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    out_dir = tmp_path / "run"
    out_dir.mkdir(parents=True, exist_ok=True)
    return {
        "run_context": RunContext(
            run_id="rid-test",
            output_dir=out_dir,
            config={},
            dry_run=True,
            max_runtime=60,
            allowed_subnets=[],
        ),
        "run_id": "rid-test",
        "dry_run": True,
        "allowed_subnets": [],
        "max_runtime": 60,
        "config": {},
        "previous_step_results": {},
    }


# ---------------------------------------------------------------------------
# Persistence: T1098.004 authorized_keys
# ---------------------------------------------------------------------------


def test_persistence_authorized_keys_profile_is_t1098_004() -> None:
    profile = _PERSISTENCE_PROFILES["authorized_keys"]
    assert profile["mitre"] == "T1098.004"
    assert profile["logsource"] == {"category": "file_event", "product": "linux"}
    assert ".ssh/authorized_keys" in profile["selection_value"]


def test_persistence_authorized_keys_runs_under_module(tmp_path: Path) -> None:
    mod = PersistenceModule()
    result = mod.execute(
        {"technique": "authorized_keys", "target": "lab-host"}, _ctx(tmp_path)
    )
    assert result.techniques == ["T1098.004"]
    assert result.detection_hints["persistence_technique"] == "authorized_keys"
    assert result.detection_hints["logsource"]["product"] == "linux"


def test_persistence_authorized_keys_in_class_attribute() -> None:
    """Drift invariant: the class attr unions every catalog mitre."""

    assert "T1098.004" in PersistenceModule.attack_techniques


# ---------------------------------------------------------------------------
# Persistence: T1543.002 per-user systemd unit
# ---------------------------------------------------------------------------


def test_persistence_systemd_user_service_profile_is_t1543_002() -> None:
    profile = _PERSISTENCE_PROFILES["systemd_user_service"]
    assert profile["mitre"] == "T1543.002"
    assert profile["logsource"] == {"category": "file_event", "product": "linux"}
    assert ".config/systemd/user" in profile["selection_value"]


def test_persistence_systemd_user_service_runs_under_module(tmp_path: Path) -> None:
    mod = PersistenceModule()
    result = mod.execute(
        {"technique": "systemd_user_service", "target": "lab-host"},
        _ctx(tmp_path),
    )
    assert result.techniques == ["T1543.002"]


# ---------------------------------------------------------------------------
# Persistence: T1547.015 macOS login item
# ---------------------------------------------------------------------------


def test_persistence_macos_login_item_profile_is_t1547_015() -> None:
    profile = _PERSISTENCE_PROFILES["macos_login_item"]
    assert profile["mitre"] == "T1547.015"
    assert profile["logsource"] == {"category": "file_event", "product": "macos"}


def test_persistence_macos_login_item_runs_under_module(tmp_path: Path) -> None:
    mod = PersistenceModule()
    result = mod.execute(
        {"technique": "macos_login_item", "target": "lab-host"}, _ctx(tmp_path)
    )
    assert result.techniques == ["T1547.015"]


def test_persistence_macos_login_item_does_not_collide_with_launch_agent() -> None:
    """Codex P2 fix: T1547.015 (Login Items) and T1543.001 (Launch
    Agent) are distinct macOS persistence techniques. The Login
    Items profile must anchor on a Login-Items-specific artifact
    (``backgrounditems.btm`` on Ventura+), NOT the LaunchAgents
    path the existing ``launch_agent`` profile already covers.
    Otherwise the detection draft for Login Items would silently
    overlap with launch_agent and a defender alerting on the
    overlap couldn't tell which technique fired."""

    login_item = _PERSISTENCE_PROFILES["macos_login_item"]
    launch_agent = _PERSISTENCE_PROFILES["launch_agent"]
    assert login_item["selection_value"] != launch_agent["selection_value"], (
        "macos_login_item and launch_agent share the same selection_value; "
        "the detection drafts will alias and lose technique distinguishability"
    )
    assert "LaunchAgents" not in login_item["selection_value"], (
        f"macos_login_item still anchors on LaunchAgents: "
        f"{login_item['selection_value']}"
    )
    assert "backgrounditems" in login_item["selection_value"].lower(), (
        f"macos_login_item should anchor on backgrounditems.btm "
        f"(macOS Ventura+ Login Items artifact); got "
        f"{login_item['selection_value']!r}"
    )


# ---------------------------------------------------------------------------
# Discovery: ssh_artifacts
# ---------------------------------------------------------------------------


def test_discovery_ssh_artifacts_profile_is_t1083_linux() -> None:
    profile = _DISCOVERY_PROFILES["ssh_artifacts"]
    assert profile["mitre"] == "T1083"
    assert profile["logsource"] == {"category": "file_event", "product": "linux"}


def test_discovery_ssh_artifacts_runs_under_module(tmp_path: Path) -> None:
    mod = DiscoveryModule()
    result = mod.execute(
        {
            "discovery_type": "ssh_artifacts",
            "targets": ["finance-laptop"],
            "network_touch": False,
        },
        _ctx(tmp_path),
    )
    assert result.techniques == ["T1083"]
    assert result.detection_hints["discovery_type"] == "ssh_artifacts"
    assert result.detection_hints["logsource"]["product"] == "linux"


def test_discovery_ssh_artifacts_indexes_under_file_in_chain() -> None:
    """SSH-artifact discovery must surface as a ``file`` row in the
    chain context — the produced_if predicate covers ssh_artifacts
    after the Linux/macOS depth pass."""

    from src.core.modules import build_runtime_modules
    from src.core.modules.chain import ChainContext

    registry = build_runtime_modules()
    chain = ChainContext()
    chain.record_step(
        step_id="ssh-recon",
        module="discovery",
        contract=registry["discovery"].io_contract,
        artifacts={
            "discovery_type": "ssh_artifacts",
            "targets": ["finance-laptop:~/.ssh/id_rsa", "finance-laptop:~/.ssh/known_hosts"],
            "discovered": [],
        },
    )
    by_type = chain.snapshot()["artifacts_by_type"]
    assert "file" in by_type
    # Other typed views should NOT fire for ssh_artifacts (it's not a
    # host scan / service scan / etc.)
    assert "host" not in by_type
    assert "service" not in by_type
    assert "user" not in by_type


# ---------------------------------------------------------------------------
# Discovery: systemd_units
# ---------------------------------------------------------------------------


def test_discovery_systemd_units_profile_is_t1518_linux() -> None:
    profile = _DISCOVERY_PROFILES["systemd_units"]
    assert profile["mitre"] == "T1518"
    assert profile["logsource"] == {"category": "file_event", "product": "linux"}


def test_discovery_systemd_units_runs_under_module(tmp_path: Path) -> None:
    mod = DiscoveryModule()
    result = mod.execute(
        {
            "discovery_type": "systemd_units",
            "targets": ["server-01"],
            "network_touch": False,
        },
        _ctx(tmp_path),
    )
    assert result.techniques == ["T1518"]


# ---------------------------------------------------------------------------
# Discovery: macos_plist_artifacts
# ---------------------------------------------------------------------------


def test_discovery_macos_plist_profile_is_t1518_macos() -> None:
    profile = _DISCOVERY_PROFILES["macos_plist_artifacts"]
    assert profile["mitre"] == "T1518"
    assert profile["logsource"] == {"category": "file_event", "product": "macos"}


def test_discovery_macos_plist_runs_under_module(tmp_path: Path) -> None:
    mod = DiscoveryModule()
    result = mod.execute(
        {
            "discovery_type": "macos_plist_artifacts",
            "targets": ["dev-laptop"],
            "network_touch": False,
        },
        _ctx(tmp_path),
    )
    assert result.techniques == ["T1518"]
    assert result.detection_hints["logsource"]["product"] == "macos"


# ---------------------------------------------------------------------------
# Cross-cutting: existing tests still pass
# ---------------------------------------------------------------------------


def test_persistence_class_attr_includes_all_new_techniques() -> None:
    """Drift invariant: union of catalog mitre values."""

    declared = set(PersistenceModule.attack_techniques)
    expected_subset = {"T1098.004", "T1543.002", "T1547.015"}
    assert expected_subset.issubset(declared), (
        f"new persistence techniques missing from class attr: "
        f"{expected_subset - declared}"
    )


def test_discovery_class_attr_includes_t1518_for_systemd_and_plist() -> None:
    """T1518 is the new mitre value for systemd_units +
    macos_plist_artifacts; it must be in the class attr."""

    assert "T1518" in DiscoveryModule.attack_techniques
