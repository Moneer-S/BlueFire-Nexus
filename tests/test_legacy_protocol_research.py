"""Focused tests for the legacy_protocol_research adapter.

The C2 pack adapter ("legacy_protocol_research") is the legacy
analogue of the standard `command_control` module. The audit in
PR #42 noted that this adapter's dedicated coverage was thin
(handful of integration assertions sprinkled across other files)
compared to its tactic_pack siblings (~10 dedicated tests each).
This file brings it in line with `test_legacy_credential_access.py`
without duplicating helper-level coverage already pinned elsewhere.

Pinned invariants:

1. Registry exposes `legacy_protocol_research` with the documented
   pack/capability defaults and the union MITRE technique surface
   (`T1071.004`, `T1572`, `T1090`).
2. With no `c2_pack` configuration, executing the adapter raises
   the documented disabled-pack runtime error (surfaced as an
   error result by `execute_operation`).
3. Each supported capability (`dns_tunneling`, `tls_fast_flux`,
   `websocket_quic`, `solana_rpc`, `network_obfuscator_legacy`)
   maps to its canonical MITRE id and transport tag.
4. Each capability's detection-hint shape includes the per-protocol
   discriminator key (DNS record type, TLS rotation count, QUIC UDP
   port, Solana instruction, obfuscation profile) so generated
   Sigma drafts vary per channel.
5. Unrecognised capabilities fall back to `dns_tunneling` rather
   than raising, matching the rest of the legacy-adapter family.
6. Endpoint validation rejects domains outside `allowed_domains`
   with a `blocked` result, but `network_obfuscator_legacy`
   (multi-hop profile) is exempt because it has no single
   endpoint to validate.
7. Emulate mode requires lab confirmation; missing acknowledgement
   surfaces an error result (mirrors PR-#1 of the legacy-adapter
   contract).
8. Emulate-mode `runtime_outcome` carries the `protocol` discriminator
   so report tables can group by which protocol ran.
9. Artifact paths for the run remain under the run's `output_dir`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.bluefire_nexus import BlueFireNexus
from src.core.config import ConfigManager
from src.core.modules.impl.legacy_packs import LegacyProtocolResearchModule
from src.core.modules.registry import build_runtime_modules


def _enable_c2_capability(
    cfg_path: Path,
    *,
    capability: str,
    mode: str,
    ack: bool,
) -> None:
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(cfg_path.parent / "output"))
    cfg.set("modules.legacy.lab_confirmation", True)
    base = f"modules.legacy.c2_pack.capabilities.{capability}"
    cfg.set("modules.legacy.c2_pack.enabled", True)
    cfg.set(f"{base}.enabled", True)
    cfg.set(f"{base}.mode", mode)
    cfg.set(f"{base}.lab_confirmation", ack)
    cfg.save()


def _baseline_cfg(tmp_path: Path) -> Path:
    cfg_path = tmp_path / "config.yaml"
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.output_root", str(tmp_path / "output"))
    cfg.save()
    return cfg_path


# ---------------------------------------------------------------------------
# Registry contract
# ---------------------------------------------------------------------------


def test_registry_includes_legacy_protocol_research() -> None:
    modules = build_runtime_modules()
    assert "legacy_protocol_research" in modules
    instance = modules["legacy_protocol_research"]
    assert isinstance(instance, LegacyProtocolResearchModule)
    assert instance.pack_name == "c2_pack"
    # Default capability before any params arrive.
    assert instance.capability_name == "dns_tunneling"
    # Class-level technique surface must cover the union of every
    # supported protocol's MITRE id so coverage tests stay accurate.
    assert set(instance.attack_techniques) == {"T1071.004", "T1572", "T1090"}


# ---------------------------------------------------------------------------
# Pack-disabled blocks the call (mirrors existing legacy-adapter contract)
# ---------------------------------------------------------------------------


def test_disabled_pack_surfaces_error_result(tmp_path: Path) -> None:
    """No c2_pack configuration => RuntimeError surfaced as error result."""
    cfg_path = _baseline_cfg(tmp_path)
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {"protocol": "dns_tunneling", "endpoint": "exfil.example.lab"},
    )
    assert result["status"] == "error"
    assert "disabled" in result["message"].lower()


# ---------------------------------------------------------------------------
# Simulate mode: per-protocol shape, no real network touch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "capability,expected_mitre,expected_transport",
    [
        ("dns_tunneling", "T1071.004", "dns"),
        ("tls_fast_flux", "T1090", "https"),
        ("websocket_quic", "T1572", "quic"),
        ("solana_rpc", "T1572", "rpc"),
        ("network_obfuscator_legacy", "T1090", "multi"),
    ],
)
def test_each_supported_capability_maps_to_canonical_mitre_and_transport(
    tmp_path: Path,
    capability: str,
    expected_mitre: str,
    expected_transport: str,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(cfg_path, capability=capability, mode="simulate", ack=False)
    nexus = BlueFireNexus(str(cfg_path))

    # network_obfuscator_legacy has no single endpoint, so don't pass one;
    # the rest receive their documented default lab endpoint.
    params: Dict[str, Any] = {"protocol": capability, "network_touch": False}
    result = nexus.execute_operation("legacy_protocol_research", params)

    assert result["status"] == "success", result.get("message")
    assert result["techniques"] == [expected_mitre]
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["protocol"] == capability
    assert payload["transport"] == expected_transport
    assert payload["mode"] == "simulate"
    # Simulate-mode runtime_outcome must explicitly say "simulated".
    runtime = payload["runtime_outcome"]
    assert runtime["status"] == "simulated"
    assert runtime["protocol"] == capability


def test_simulate_mode_unrecognized_protocol_falls_back_to_dns_tunneling(
    tmp_path: Path,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(
        cfg_path, capability="dns_tunneling", mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {"protocol": "definitely-not-a-protocol", "network_touch": False},
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    # Unrecognised request must not raise; it must fall back to the
    # documented dns_tunneling default so detection drafts still
    # have a sane shape.
    assert payload["protocol"] == "dns_tunneling"


# ---------------------------------------------------------------------------
# Per-capability detection-hint discriminators
# ---------------------------------------------------------------------------


def test_dns_tunneling_hints_include_dns_record_type(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(
        cfg_path, capability="dns_tunneling", mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "dns_tunneling",
            "dns_record_type": "AAAA",
            "endpoint": "exfil.example.lab",
            "network_touch": False,
        },
    )
    hints = result["detection_hints"]
    assert hints["dns_record_type"] == "AAAA"
    assert hints["detection"]["selection"]["dns.record_type"] == "AAAA"
    assert hints["detection"]["selection"]["legacy.capability"] == "dns_tunneling"
    assert hints["detection"]["selection"]["legacy.mode"] == "simulate"


def test_tls_fast_flux_hints_include_rotation_count_and_ja3(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(
        cfg_path, capability="tls_fast_flux", mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "tls_fast_flux",
            "rotation_count": 4,
            "tls_ja3": "771,4866,23-24,0",
            "endpoint": "https://edge.example.lab",
            "network_touch": False,
        },
    )
    hints = result["detection_hints"]
    assert hints["rotation_count"] == 4
    assert hints["tls_ja3"] == "771,4866,23-24,0"
    # Per-protocol selection key must be added.
    selection = hints["detection"]["selection"]
    assert "tls.server_name|contains" in selection


def test_websocket_quic_hints_carry_udp_port_and_alpn(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(
        cfg_path, capability="websocket_quic", mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "websocket_quic",
            "endpoint": "quic://edge.example.lab:8443",
            "alpn": "h3-29",
            "network_touch": False,
        },
    )
    hints = result["detection_hints"]
    # Port comes from the URL when not explicitly set in params.
    assert hints["udp_port"] == 8443
    assert hints["alpn"] == "h3-29"
    selection = hints["detection"]["selection"]
    assert selection["network.protocol"] == "quic"
    assert selection["network.port"] == 8443


def test_solana_rpc_hints_include_instruction_and_method(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(
        cfg_path, capability="solana_rpc", mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "solana_rpc",
            "instruction": "deploy",
            "rpc_method": "getTransaction",
            "endpoint": "https://rpc.example.lab",
            "network_touch": False,
        },
    )
    hints = result["detection_hints"]
    assert hints["instruction"] == "deploy"
    assert hints["rpc_method"] == "getTransaction"
    assert hints["detection"]["selection"]["network.application"] == "solana_rpc"


def test_network_obfuscator_legacy_hints_carry_obfuscation_profile(
    tmp_path: Path,
) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(
        cfg_path,
        capability="network_obfuscator_legacy",
        mode="simulate",
        ack=False,
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "network_obfuscator_legacy",
            "obfuscation_profile": "tor-bridge-relay",
            "network_touch": False,
        },
    )
    hints = result["detection_hints"]
    assert hints["obfuscation_profile"] == "tor-bridge-relay"
    assert hints["detection"]["selection"]["network.path"] == "obfuscated"


# ---------------------------------------------------------------------------
# Endpoint domain validation
# ---------------------------------------------------------------------------


def test_disallowed_endpoint_blocks_dns_tunneling(tmp_path: Path) -> None:
    """Endpoints outside `allowed_domains` produce a blocked result."""
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(
        cfg_path, capability="dns_tunneling", mode="simulate", ack=False
    )
    # Tighten allowed_domains so the test endpoint is provably outside.
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.safeties.allowed_domains", ["only-allowed.example.lab"])
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "dns_tunneling",
            "endpoint": "blocked.example.test",
            "network_touch": False,
        },
    )
    # _ensure_allowed runs first; if pack is enabled and endpoint is
    # blocked, blocked_result is returned (status=blocked).
    assert result["status"] == "blocked"
    assert "outside allowed legacy lab domains" in result["message"]


def test_network_obfuscator_legacy_skips_endpoint_validation(tmp_path: Path) -> None:
    """The multi-hop profile has no single endpoint to validate, so it
    must run successfully even when allowed_domains would reject the
    nominal endpoint name."""
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(
        cfg_path,
        capability="network_obfuscator_legacy",
        mode="simulate",
        ack=False,
    )
    cfg = ConfigManager(str(cfg_path))
    cfg.set("general.safeties.allowed_domains", ["only-allowed.example.lab"])
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "network_obfuscator_legacy",
            "endpoint": "anything.example.test",
            "network_touch": False,
        },
    )
    assert result["status"] == "success"


# ---------------------------------------------------------------------------
# Emulate mode: requires lab confirmation, then routes through safe_call
# ---------------------------------------------------------------------------


def test_emulate_without_ack_surfaces_error(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(
        cfg_path, capability="dns_tunneling", mode="emulate", ack=False
    )
    # Also clear master ack so emulate is genuinely missing acknowledgement.
    cfg = ConfigManager(str(cfg_path))
    cfg.set("modules.legacy.lab_confirmation", False)
    cfg.set("modules.legacy.global_lab_acknowledged", False)
    cfg.save()

    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "dns_tunneling",
            "endpoint": "exfil.example.lab",
            "network_touch": False,
        },
    )
    assert result["status"] == "error"
    assert "lab confirmation" in result["message"].lower()


def test_emulate_with_ack_returns_runtime_outcome(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(
        cfg_path, capability="dns_tunneling", mode="emulate", ack=True
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {
            "protocol": "dns_tunneling",
            "endpoint": "exfil.example.lab",
            "data_size": 64,
            "network_touch": False,
        },
    )
    assert result["status"] == "success"
    payload = result["artifacts"]["legacy"]["payload"]
    assert payload["mode"] == "emulate"
    runtime = payload["runtime_outcome"]
    assert runtime["status"] in {"success", "completed", "failure"}
    # Discriminator must be present so report tables can group by
    # which protocol ran.
    assert runtime["protocol"] == "dns_tunneling"


# ---------------------------------------------------------------------------
# Artifact paths stay under output_dir
# ---------------------------------------------------------------------------


def test_run_artifacts_remain_under_output_dir(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    _enable_c2_capability(
        cfg_path, capability="dns_tunneling", mode="simulate", ack=False
    )
    nexus = BlueFireNexus(str(cfg_path))
    result = nexus.execute_operation(
        "legacy_protocol_research",
        {"protocol": "dns_tunneling", "endpoint": "exfil.example.lab"},
    )
    assert result["status"] == "success"
    output_dir = Path(result["output_dir"]).resolve()
    for path_key in ("report_path", "risk_summary_path"):
        path_value = result.get(path_key)
        if path_value:
            assert Path(path_value).resolve().is_relative_to(output_dir)
    for output_type, output_paths in (result.get("detection_artifacts") or {}).items():
        if isinstance(output_paths, list):
            for path_str in output_paths:
                assert Path(path_str).resolve().is_relative_to(output_dir), (
                    f"{output_type} path {path_str} escaped output_dir {output_dir}"
                )
