from pathlib import Path

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.configuration import apply_simple_preset
from src.core.models import RunContext
from src.core.safety import SafetyGate, SafetyViolation, ensure_target_allowed


def _ctx(
    dry_run: bool = True,
    allowed_subnets: list[str] | None = None,
):
    return RunContext(
        run_id="safety-test",
        output_dir=Path("output/safety-test"),
        config={},
        dry_run=dry_run,
        max_runtime=60,
        allowed_subnets=allowed_subnets if allowed_subnets is not None else ["10.0.0.0/24"],
    )


def test_safety_allows_target_in_subnet():
    gate = SafetyGate(_ctx())
    gate.ensure_safe({"target": "10.0.0.5"})


def test_safety_blocks_target_outside_subnet():
    gate = SafetyGate(_ctx())
    with pytest.raises(SafetyViolation):
        gate.ensure_safe({"target": "8.8.8.8"})


def test_safety_blocks_destructive_without_ack():
    gate = SafetyGate(_ctx())
    with pytest.raises(SafetyViolation):
        gate.ensure_safe({"destructive": True, "target": "10.0.0.7"})


# ---------------------------------------------------------------------------
# Empty allowed_subnets blocks IP targets (closes Codex P1 on PR #45)
# ---------------------------------------------------------------------------


def test_ensure_target_allowed_empty_subnets_blocks_ip_target() -> None:
    """Empty allowed_subnets must NOT silently allow any IP — that
    was the strict_local footgun. An empty list now means
    "no IP targets permitted" (consistent with the network_touch
    guard's treatment of empty allowed_subnets in non-dry-run)."""
    with pytest.raises(SafetyViolation, match="outside allowed_subnets"):
        ensure_target_allowed("8.8.8.8", [])


def test_ensure_target_allowed_empty_subnets_blocks_loopback_ip() -> None:
    """Even loopback is blocked when allowed_subnets is empty —
    callers that want loopback must enumerate it (see strict_local
    preset)."""
    with pytest.raises(SafetyViolation):
        ensure_target_allowed("127.0.0.1", [])


def test_ensure_target_allowed_empty_subnets_permits_hostnames() -> None:
    """Hostnames are bound at the module layer, not the safety layer —
    they pass through ensure_target_allowed regardless of subnet config."""
    ensure_target_allowed("lab-host", [])  # must not raise


# ---------------------------------------------------------------------------
# strict_local preset truly restricts to loopback (closes Codex P1 on PR #45)
# ---------------------------------------------------------------------------


def _strict_local_runtime(tmp_path: Path) -> BlueFireNexus:
    cfg_path = tmp_path / "config.yaml"
    cm = ConfigManager(str(cfg_path))
    cm.set("general.output_root", str(tmp_path / "output"))
    apply_simple_preset(cm, "strict_local")
    cm.save()
    return BlueFireNexus(str(cfg_path))


def test_strict_local_preset_allows_loopback_ip_target(tmp_path: Path) -> None:
    nexus = _strict_local_runtime(tmp_path)
    context = nexus._make_run_context()
    gate = SafetyGate(context)
    gate.ensure_safe({"target": "127.0.0.1"})  # must not raise


def test_strict_local_preset_blocks_non_loopback_ip_target(tmp_path: Path) -> None:
    nexus = _strict_local_runtime(tmp_path)
    context = nexus._make_run_context()
    gate = SafetyGate(context)
    with pytest.raises(SafetyViolation, match="outside allowed_subnets"):
        gate.ensure_safe({"target": "10.0.0.7"})


def test_strict_local_preset_allows_localhost_hostname(tmp_path: Path) -> None:
    """Hostnames are not subnet-checked, but `localhost` is the
    documented hostname target for strict_local."""
    nexus = _strict_local_runtime(tmp_path)
    context = nexus._make_run_context()
    gate = SafetyGate(context)
    gate.ensure_safe({"target": "localhost"})  # must not raise
