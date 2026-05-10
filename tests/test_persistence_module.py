"""Focused tests for the standard ``persistence`` module.

Registry-wide contract / safety tests cover the structural surface
(every persistence profile produces a typed result, no module emits
a forbidden artifact field, etc). These tests cover the per-technique
fan-out behaviour: each technique value produces a distinct MITRE
technique, telemetry event_type, logsource, and detection selection.

Pinned specifically on the Windows-first persistence profiles
(COM hijacking T1546.015, IFEO debugger T1546.012, AppInit DLLs
T1546.010) added in the recent batch so a regression that drops
one of these techniques surfaces immediately.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.models import TelemetryEvent
from src.core.modules.impl.standard_modules import (
    PersistenceModule,
    _PERSISTENCE_PROFILES,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    return {
        "run_id": "persistence-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }


@pytest.mark.parametrize(
    "technique,expected_mitre",
    [
        ("scheduled_task", "T1053.005"),
        ("cron", "T1053.003"),
        ("registry_run_key", "T1547.001"),
        ("service", "T1543.003"),
        ("launch_agent", "T1543.001"),
        ("launch_daemon", "T1543.004"),
        ("wmi_subscription", "T1546.003"),
        ("startup_folder", "T1547.001"),
        ("bashrc", "T1546.004"),
        ("bootkit", "T1542.003"),
        ("authorized_keys", "T1098.004"),
        ("systemd_user_service", "T1543.002"),
        ("macos_login_item", "T1547.015"),
        ("com_hijack", "T1546.015"),
        ("ifeo_debugger", "T1546.012"),
        ("appinit_dlls", "T1546.010"),
    ],
)
def test_technique_fans_out_to_correct_mitre(
    technique: str, expected_mitre: str, tmp_path: Path
) -> None:
    mod = PersistenceModule()
    result = mod.execute(
        {"technique": technique, "target": "lab-host"},
        _ctx(tmp_path),
    )
    assert result.techniques == [expected_mitre], (
        f"{technique} should emit {expected_mitre}, got {result.techniques}"
    )
    assert result.detection_hints["mitre_technique"] == expected_mitre


def test_com_hijack_pins_registry_event_logsource(tmp_path: Path) -> None:
    """COM hijacking (T1546.015) writes a CLSID -> InprocServer32 /
    LocalServer32 mapping under ``HKCU\\Software\\Classes\\CLSID``.
    Pin the registry_event logsource and the
    ``Software\\Classes\\CLSID\\`` substring selector so the rendered
    detection draft fires on the canonical CLSID-hijack pattern."""

    mod = PersistenceModule()
    result = mod.execute(
        {"technique": "com_hijack", "target": "lab-host"},
        _ctx(tmp_path),
    )
    hints = result.detection_hints
    assert hints["logsource"] == {
        "category": "registry_event",
        "product": "windows",
    }
    selection = hints["detection"]["selection"]
    # Selector keys/values include the CLSID substring.
    selector_key = next(iter(selection))
    assert selector_key.startswith("registry.key")
    assert "CLSID" in selection[selector_key]


def test_ifeo_debugger_pins_image_file_execution_options_path(
    tmp_path: Path,
) -> None:
    """Image File Execution Options (T1546.012) writes a ``Debugger``
    value under
    ``HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image
    File Execution Options\\<exe-name>``. Pin the registry path
    substring so the detection draft anchors on the IFEO key tree."""

    mod = PersistenceModule()
    result = mod.execute(
        {"technique": "ifeo_debugger", "target": "lab-host"},
        _ctx(tmp_path),
    )
    selection = result.detection_hints["detection"]["selection"]
    selector_key = next(iter(selection))
    assert "Image File Execution Options" in selection[selector_key]


def test_appinit_dlls_pins_exact_value_name_selector(tmp_path: Path) -> None:
    """AppInit DLLs (T1546.010) writes a value at the ``AppInit_DLLs``
    name under ``HKLM\\Software\\Microsoft\\Windows
    NT\\CurrentVersion\\Windows``. The selector must be an EXACT
    match on ``registry.value_name`` -- a ``|contains`` selector
    would also fire on the unrelated ``LoadAppInit_DLLs`` and
    ``RequireSignedAppInit_DLLs`` values."""

    mod = PersistenceModule()
    result = mod.execute(
        {"technique": "appinit_dlls", "target": "lab-host"},
        _ctx(tmp_path),
    )
    selection = result.detection_hints["detection"]["selection"]
    # Bare ``registry.value_name`` (no operator suffix) -> exact match.
    assert "registry.value_name" in selection
    assert selection["registry.value_name"] == "AppInit_DLLs"
    # The ``|contains`` form must not appear -- it would broaden to
    # ``LoadAppInit_DLLs`` and ``RequireSignedAppInit_DLLs``.
    assert "registry.value_name|contains" not in selection


def test_persistence_techniques_each_have_distinct_event_type() -> None:
    """Every persistence profile must emit a unique telemetry
    event_type so a defender summing event_types can quantify
    technique distribution per run without joining tables. Pin the
    invariant across the full catalog so a future profile addition
    that re-uses an existing event_type fails here."""

    seen: dict[str, str] = {}
    for key, profile in _PERSISTENCE_PROFILES.items():
        event_type = profile["event_type"]
        assert event_type not in seen, (
            f"event_type {event_type!r} duplicated: "
            f"{seen[event_type]!r} and {key!r}"
        )
        seen[event_type] = key


def test_persistence_techniques_have_unique_mitre_or_explicit_aliasing() -> None:
    """Each persistence profile maps to a MITRE technique. Where two
    profiles legitimately share an id (e.g. ``registry_run_key`` and
    ``startup_folder`` both T1547.001), the catalog can do so but
    the test surfaces the duplication explicitly so a future addition
    that silently re-uses an id is flagged."""

    by_mitre: dict[str, list[str]] = {}
    for key, profile in _PERSISTENCE_PROFILES.items():
        by_mitre.setdefault(profile["mitre"], []).append(key)
    duplicates = {
        mitre: keys for mitre, keys in by_mitre.items() if len(keys) > 1
    }
    # Documented allowed duplications (registry_run_key / startup_folder
    # both fall under T1547.001 -- canonical Windows autostart vector).
    expected_dups = {
        "T1547.001": ["registry_run_key", "startup_folder"],
    }
    assert duplicates == expected_dups, (
        f"unexpected MITRE duplications: {duplicates}; allowed: "
        f"{expected_dups}"
    )
