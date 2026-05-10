"""Focused tests for the standard ``command_control`` module.

Registry-wide contract / safety / artifact-path tests cover this
module structurally. These tests cover the per-protocol fan-out
behaviour: each protocol value produces a distinct MITRE technique,
telemetry event_type, logsource, and detection selection. Pinned
specifically on the advanced C2 profiles added in the recent
batch (DGA / internal proxy / domain fronting) so a regression
that drops one of the resilience patterns surfaces immediately.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import (
    CommandControlModule,
    _COMMAND_CONTROL_PROFILES,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    return {
        "run_id": "command-control-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


@pytest.mark.parametrize(
    "protocol,expected_mitre",
    [
        ("http", "T1071.001"),
        ("https", "T1071.001"),
        ("dns", "T1071.004"),
        ("tcp", "T1095"),
        ("icmp", "T1095"),
        ("websocket", "T1071.001"),
        ("mail", "T1071.003"),
        ("web_service", "T1102"),
        ("dga", "T1568.002"),
        ("internal_proxy", "T1090.001"),
        ("domain_fronting", "T1090.004"),
    ],
)
def test_protocol_fans_out_to_correct_mitre(
    protocol: str, expected_mitre: str, tmp_path: Path
) -> None:
    mod = CommandControlModule()
    result = mod.execute(
        {"channel": protocol, "c2_url": "https://lab-c2.test/c2"},
        _ctx(tmp_path),
    )
    assert result.techniques == [expected_mitre], (
        f"{protocol} should emit {expected_mitre}, got {result.techniques}"
    )
    assert result.detection_hints["mitre_technique"] == expected_mitre


def test_dga_pins_dns_logsource_for_resilient_c2(tmp_path: Path) -> None:
    """Domain Generation Algorithm (T1568.002) is the canonical
    advanced C2 resilience pattern. The catalog must pin a DNS
    logsource so the rule fires on the burst-of-NXDOMAIN-against-
    high-entropy-subdomains pattern that defenders use to detect
    Conficker / Locky / Necurs / Emotet / Qakbot DGA traffic.

    Distinct from the bare ``dns`` profile (T1071.004) by MITRE id
    and by detection narrative -- DNS-tunneled C2 encodes data in
    subdomain queries against a fixed parent domain, while DGA
    rotates the parent domain itself.
    """

    mod = CommandControlModule()
    result = mod.execute(
        {"channel": "dga", "c2_url": "https://dga-c2.test/c2"},
        _ctx(tmp_path),
    )
    assert result.status == "success"
    assert result.techniques == ["T1568.002"]
    logsource = result.detection_hints["logsource"]
    assert logsource["category"] == "dns"
    event = result.telemetry[0]
    assert event.event_type == "command_control_dga"
    # MITRE-id distinct from the bare dns profile.
    assert result.detection_hints["mitre_technique"] != "T1071.004"


def test_internal_proxy_pins_proxy_logsource_for_intra_network_c2(
    tmp_path: Path,
) -> None:
    """Internal Proxy (T1090.001) routes C2 traffic through one or
    more compromised intermediate hosts inside the victim network.
    The catalog must pin a ``proxy`` logsource so a defender writing
    the rule catches the asymmetric-beacon-shape pattern between
    internal endpoints.
    """

    mod = CommandControlModule()
    result = mod.execute(
        {"channel": "internal_proxy", "c2_url": "https://internal-proxy.test/c2"},
        _ctx(tmp_path),
    )
    assert result.status == "success"
    assert result.techniques == ["T1090.001"]
    logsource = result.detection_hints["logsource"]
    assert logsource["category"] == "proxy"
    event = result.telemetry[0]
    assert event.event_type == "command_control_internal_proxy"


def test_domain_fronting_pins_tls_sni_mismatch_marker(tmp_path: Path) -> None:
    """Domain Fronting (T1090.004) hides the C2 endpoint behind a
    high-reputation CDN by setting the TLS SNI to a benign fronting
    domain while the HTTP Host header points at the real C2. The
    catalog must pin a network_connection logsource and the
    ``tls.sni|fronts`` selector field so a defender writing the
    rule catches the SNI/Host mismatch pattern.
    """

    mod = CommandControlModule()
    result = mod.execute(
        {
            "channel": "domain_fronting",
            "c2_url": "https://cdn.example.com/c2",
        },
        _ctx(tmp_path),
    )
    assert result.status == "success"
    assert result.techniques == ["T1090.004"]
    logsource = result.detection_hints["logsource"]
    assert logsource["category"] == "network_connection"
    detection = result.detection_hints["detection"]
    selection_keys = list(detection["selection"].keys())
    # The selector field must use a SUPPORTED Sigma modifier
    # (contains/startswith/endswith/in). The previous ``|fronts``
    # custom modifier silently downgraded to plain equality in the
    # YARA-L/SPL converters and would have emitted
    # ``tls.sni = "<c2_url>"`` (URL never matches an SNI hostname).
    # (Codex P1 on PR #177.)
    assert any(k.startswith("tls.sni") for k in selection_keys)
    assert any("|contains" in k for k in selection_keys), (
        f"selector field must use a supported Sigma modifier; "
        f"got {selection_keys}"
    )
    event = result.telemetry[0]
    assert event.event_type == "command_control_domain_fronting"


def test_dga_selector_uses_supported_sigma_modifier(tmp_path: Path) -> None:
    """Per Codex P1 on PR #177, the DGA profile must use a supported
    Sigma modifier (contains/startswith/endswith/in) rather than the
    custom ``|matches`` modifier (which silently downgrades to plain
    equality in the YARA-L/SPL converters and would emit a rule that
    never fires on real DGA traffic)."""

    mod = CommandControlModule()
    result = mod.execute(
        {"channel": "dga", "c2_url": "https://dga-c2.test/c2"}, _ctx(tmp_path)
    )
    detection = result.detection_hints["detection"]
    selection_keys = list(detection["selection"].keys())
    assert any(k.startswith("dns.question.name") for k in selection_keys)
    assert any("|contains" in k for k in selection_keys), (
        f"selector field must use a supported Sigma modifier "
        f"(``|matches`` is not supported); got {selection_keys}"
    )


def test_each_profile_emits_a_distinct_event_type(tmp_path: Path) -> None:
    """Detection-pipeline consumers can fan out on event_type."""

    mod = CommandControlModule()
    seen: set[str] = set()
    for protocol in _COMMAND_CONTROL_PROFILES:
        result = mod.execute(
            {"channel": protocol, "c2_url": "https://lab-c2.test/c2"},
            _ctx(tmp_path),
        )
        assert isinstance(result.telemetry[0], TelemetryEvent)
        seen.add(result.telemetry[0].event_type)
    assert len(seen) == len(_COMMAND_CONTROL_PROFILES), (
        f"Expected {len(_COMMAND_CONTROL_PROFILES)} distinct event types, "
        f"got {len(seen)}"
    )


def test_module_advertises_all_catalog_techniques() -> None:
    expected = {profile["mitre"] for profile in _COMMAND_CONTROL_PROFILES.values()}
    advertised = set(CommandControlModule.attack_techniques)
    assert expected.issubset(advertised), (
        f"Missing techniques on class attribute: {expected - advertised}"
    )
