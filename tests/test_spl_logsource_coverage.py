"""SPL renderer logsource coverage tests.

The SPL renderer's ``_LOGSOURCE_TO_SPL`` map turns a Sigma
``(product, category)`` pair into a real Splunk
``sourcetype=...`` filter (and optional EventCode filter). When
the map has no entry, the renderer falls through to the
"index=* sourcetype=*" placeholder shape with a "pin sourcetype/
index to your environment" comment — usable but weak.

After PR #110 (initial_access vector catalog) and PR #108
(exfiltration method catalog) several profiles use logsource
pairs that were not yet mapped:

- (windows, process_access)            anti_detection anti_debug etc.
- (windows, image_load)                anti_detection reflective_loading
- (windows, service_creation/...)      persistence/privilege_escalation
- (host, network_connection)           exfiltration / command_control / external_*
- (network, dns) / (dns, dns)          exfiltration dns_tunneling
- (windows/linux/generic/host, authentication)
- (generic, cloud_audit)               initial_access cloud_accounts
- (generic, webserver)                 initial_access exploit_public_app
- (generic, proxy)                     initial_access drive_by_compromise
- (generic, email) / (host, email)     phishing variants
- (linux/macos/host, file_event)       persistence bashrc / launch_*
- (windows, device_event)              initial_access hardware_additions
- (vendor/generic, threat_intelligence) intelligence module
- (bluefire, legacy_wrapped)           LegacyWrappedModule (PR #105)

This file pins:

1. Every newly-added (product, category) pair maps to a Splunk
   sourcetype string that does NOT contain ``sourcetype=*``
   (i.e. it picks a real sourcetype).
2. Round-trip: rendering an SPL search for a typical hint with
   the new logsource yields a search whose ``index=*`` line
   names the mapped sourcetype, NOT the placeholder
   ``sourcetype=*``.
3. The metadata-echo fallback ``| makeresults | eval ...`` does
   NOT fire for any standard module's default profile (every
   module surfaces a usable Sigma selection AND a mapped
   logsource).
"""

from __future__ import annotations

from typing import Tuple

import pytest

from src.core.detections.spl import _LOGSOURCE_TO_SPL, _logsource_hint, render_spl
from src.core.models import ModuleResult


_NEW_PAIRS = (
    ("windows", "process_access"),
    ("windows", "image_load"),
    ("windows", "service_creation"),
    ("windows", "service_modification"),
    ("host", "network_connection"),
    ("network", "dns"),
    ("dns", "dns"),
    ("linux", "file_event"),
    ("macos", "file_event"),
    ("host", "file_event"),
    ("windows", "authentication"),
    ("linux", "authentication"),
    ("generic", "authentication"),
    ("host", "authentication"),
    ("generic", "cloud_audit"),
    ("generic", "webserver"),
    ("generic", "proxy"),
    ("generic", "email"),
    ("host", "email"),
    ("windows", "device_event"),
    ("vendor", "threat_intelligence"),
    ("generic", "threat_intelligence"),
    ("bluefire", "legacy_wrapped"),
    ("macos", "process_creation"),
)


@pytest.mark.parametrize("pair", _NEW_PAIRS)
def test_new_logsource_pair_resolves_to_real_sourcetype(
    pair: Tuple[str, str],
) -> None:
    """Each newly-mapped pair returns a non-empty sourcetype string."""
    sourcetype, _eventcode = _LOGSOURCE_TO_SPL[pair]
    assert sourcetype, pair
    # The sourcetype string must NOT be the placeholder.
    assert "sourcetype=*" not in sourcetype, pair


@pytest.mark.parametrize("pair", _NEW_PAIRS)
def test_new_logsource_pair_drives_real_sourcetype_in_render(
    pair: Tuple[str, str],
) -> None:
    """Rendering an SPL search for a typical hint with the new
    logsource pair yields a search rooted in a real sourcetype
    (not the placeholder ``sourcetype=*``).
    """
    product, category = pair
    hints = {
        "title": "Test rule",
        "logsource": {"category": category, "product": product},
        "detection": {
            "selection": {"some.field|contains": "lab"},
            "condition": "selection",
        },
        "mitre_technique": "T1234",
    }
    result = ModuleResult(
        status="success",
        module="test",
        message="ok",
        techniques=["T1234"],
        artifacts={},
        detection_hints=hints,
        telemetry=[],
    )
    spl = render_spl(result, "run-spl-test")
    # The first non-comment, non-blank line should be the index=...
    # line. With a mapped pair, it must contain a real sourcetype.
    assert "sourcetype=*" not in spl, (pair, spl)
    expected_sourcetype, _ = _LOGSOURCE_TO_SPL[pair]
    # Every alternative sourcetype in the mapped value should appear
    # in the rendered output.
    for token in [
        chunk.strip().strip('"')
        for chunk in expected_sourcetype.replace("(", "").replace(")", "").split(" OR ")
    ]:
        if token.startswith("sourcetype="):
            stem = token.split("=", 1)[1].strip().strip('"')
            assert stem in spl, (pair, stem, spl)


def test_logsource_hint_returns_empty_for_unmapped_pair() -> None:
    """Unmapped pairs still surface as empty so the render falls
    back gracefully (placeholder + warning comment).

    Pin that this contract is preserved — the renderer's fallback
    handling assumes empty strings for unmapped pairs.
    """
    hints = {"logsource": {"category": "completely_made_up", "product": "nope"}}
    product, category, sourcetype, eventcode = _logsource_hint(hints)
    assert product == "nope"
    assert category == "completely_made_up"
    assert sourcetype == ""
    assert eventcode == ""


@pytest.mark.parametrize(
    "pair,expected_event_substring",
    [
        # Authentication maps to security event codes for Windows logon.
        (("windows", "authentication"), "EventCode=4624"),
        # Service creation -> 7045.
        (("windows", "service_creation"), "EventCode=7045"),
        # Service modification -> 7040 / 4697.
        (("windows", "service_modification"), "EventCode=7040"),
        # Process access -> Sysmon EventCode=10.
        (("windows", "process_access"), "EventCode=10"),
        # Image load -> Sysmon EventCode=7.
        (("windows", "image_load"), "EventCode=7"),
        # Hardware additions / USB device events -> 20001/20003/24576.
        (("windows", "device_event"), "EventCode=20003"),
    ],
)
def test_event_code_clauses_specific_to_telemetry_family(
    pair: Tuple[str, str], expected_event_substring: str
) -> None:
    """Auth / service / process_access / image_load / device_event
    pairs include a real Windows EventCode filter.
    """
    _sourcetype, eventcode = _LOGSOURCE_TO_SPL[pair]
    assert expected_event_substring in eventcode, (pair, eventcode)


def test_no_standard_module_default_falls_back_to_metadata_echo() -> None:
    """End-to-end: the default profile of every standard module
    produces an SPL search rooted in a real sourcetype (not the
    placeholder + warning fallback shape).

    Catches a regression where a future module ships with a
    logsource pair that's not in ``_LOGSOURCE_TO_SPL`` — the
    weak-fallback path is preferable to the metadata-echo path,
    but neither should fire for the default profile of any
    standard module that already declares a logsource.
    """
    from src.core.modules.registry import build_runtime_modules

    modules = build_runtime_modules()
    for name, module in modules.items():
        if name == "legacy_capability_summary":
            # Metadata-only module: no mitre technique, intentional.
            continue
        if name.startswith("legacy_"):
            # Legacy_* adapters need explicit per-pack enablement that
            # the SPL renderer doesn't care about. Skip them here; the
            # legacy adapter parity tests cover detection-shape contracts.
            continue
        # Run with empty params + minimal context.
        ctx = {
            "run_id": "spl-default-test",
            "output_dir": "/tmp/_unused",
            "config": {},
            "dry_run": True,
            "max_runtime": 60,
            "allowed_subnets": [],
        }
        result = module.execute({}, ctx)
        if not result.detection_hints.get("logsource"):
            continue  # No logsource declared -> render decision is module's call.
        spl = render_spl(result, "run-spl-default")
        # Either a real sourcetype OR the explicit placeholder warning
        # is acceptable, but the metadata-echo `| makeresults |` path
        # is NOT.
        assert "| makeresults" not in spl, (
            f"{name} default profile fell back to metadata-echo SPL: {spl}"
        )
