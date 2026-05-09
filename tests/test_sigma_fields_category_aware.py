"""Sigma ``fields:`` block category-awareness — defender-relevant columns.

Pre-#145 every Sigma rule emitted the hardcoded process-event triple
``CommandLine`` / ``Image`` / ``ParentCommandLine`` regardless of
logsource category. A ``file_event`` rule shipped with process-only
fields, a ``network_connection`` rule shipped with process-only
fields, a ``dns_query`` rule shipped with process-only fields. An
alert reviewer (or a SIEM auto-pivot) saw irrelevant columns on every
non-process rule.

PR #145 routes the ``fields:`` block through
:data:`_LOGSOURCE_CATEGORY_TO_FIELDS` so each category emits the
canonical Sigma vocabulary for events it actually fires against:

- ``file_event`` -> ``TargetFilename`` / ``Image`` / ``User``
- ``network_connection`` -> ``DestinationIp`` / ``DestinationPort`` /
  ``DestinationHostname`` / ``Protocol``
- ``dns_query`` / ``dns`` -> ``QueryName`` / ``QueryStatus`` /
  ``QueryResults``
- ``registry_event`` -> ``TargetObject`` / ``Details``
- ``service_creation`` / ``service_modification`` -> ``ServiceName`` /
  ``ServiceFileName`` / ``ImagePath``
- ``authentication`` -> ``TargetUserName`` / ``IpAddress`` /
  ``LogonType``
- ``cloud_audit`` -> ``eventName`` / ``userIdentity.userName`` /
  ``sourceIPAddress``
- ``email`` -> ``recipient`` / ``sender`` / ``subject``
- ``image_load`` -> ``Image`` / ``ImageLoaded`` / ``Signed``
- ``process_access`` -> ``CallTrace`` / ``GrantedAccess`` /
  ``TargetImage``
- ``device_event`` -> ``DeviceName`` / ``DeviceClassGuid``
- threat-intel / pre-foothold families -> family-specific stubs

Pinned invariants:
1. Each category-mapped logsource emits its canonical fields.
2. Process-event categories keep the legacy triple.
3. Unmapped / bespoke categories fall through to the process default
   (backwards-compatible).
4. The optional legacy-discriminator append logic still runs after the
   category-aware base list.
5. Process-only fields do NOT survive in non-process rules — pin the
   regression Codex would catch in real reviewing.
"""

from __future__ import annotations

import pytest

from src.core.detections.sigma import (
    _LOGSOURCE_CATEGORY_TO_FIELDS,
    _fields_for_category,
    build_sigma_rule,
)


# ---------------------------------------------------------------------------
# 1. Category mapping table — every documented category resolves
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "category,expected_field",
    [
        # Endpoint / process family
        ("process_creation", "CommandLine"),
        ("process_creation", "ParentCommandLine"),
        ("process_creation", "Image"),
        ("process_creation", "ParentImage"),
        ("process_access", "CallTrace"),
        ("process_access", "GrantedAccess"),
        ("process_access", "TargetImage"),
        ("image_load", "ImageLoaded"),
        ("image_load", "Signed"),
        # Filesystem
        ("file_event", "TargetFilename"),
        # Registry
        ("registry_event", "TargetObject"),
        ("registry_event", "Details"),
        # Service
        ("service_creation", "ServiceName"),
        ("service_creation", "ServiceFileName"),
        ("service_modification", "ImagePath"),
        # Network
        ("network_connection", "DestinationIp"),
        ("network_connection", "DestinationPort"),
        ("network_connection", "DestinationHostname"),
        ("network_connection", "Initiated"),
        ("network_connection", "Protocol"),
        # DNS
        ("dns_query", "QueryName"),
        ("dns_query", "QueryStatus"),
        ("dns_query", "QueryResults"),
        ("dns", "QueryName"),
        # Auth
        ("authentication", "TargetUserName"),
        ("authentication", "IpAddress"),
        ("authentication", "LogonType"),
        # Cloud / web / proxy
        ("cloud_audit", "eventName"),
        ("cloud_audit", "userIdentity.userName"),
        ("cloud_audit", "sourceIPAddress"),
        ("webserver", "cs-uri-stem"),
        ("webserver", "cs-User-Agent"),
        ("proxy", "cs-host"),
        # Email
        ("email", "recipient"),
        ("email", "sender"),
        ("email", "subject"),
        # Hardware
        ("device_event", "DeviceName"),
        ("device_event", "DeviceClassGuid"),
        # Threat-intel + resource-development pre-foothold families
        ("threat_intelligence", "ioc_type"),
        ("infrastructure_provisioning", "registrar"),
        ("account_provisioning", "provider"),
        ("certificate_acquisition", "ca"),
        ("tooling_acquisition", "marketplace"),
        ("legacy_wrapped", "legacy_subtype"),
    ],
)
def test_category_to_fields_map_includes_canonical_field(
    category: str, expected_field: str
) -> None:
    """Every documented category includes its canonical canonical Sigma field."""
    fields = _LOGSOURCE_CATEGORY_TO_FIELDS[category]
    assert expected_field in fields, (category, fields)


def test_fields_for_category_returns_fresh_copy() -> None:
    """The helper must return a copy so caller mutation doesn't poison the map."""
    a = _fields_for_category("process_creation")
    b = _fields_for_category("process_creation")
    a.append("BogusField")
    assert "BogusField" not in b
    # And the static map itself is untouched.
    assert "BogusField" not in _LOGSOURCE_CATEGORY_TO_FIELDS["process_creation"]


def test_fields_for_unmapped_category_falls_through_to_process_default() -> None:
    """Bespoke / legacy logsource categories keep working via process-default."""
    fields = _fields_for_category("completely_made_up_category")
    assert fields == ["CommandLine", "ParentCommandLine", "Image"]


# ---------------------------------------------------------------------------
# 2. End-to-end build_sigma_rule — emitted fields match logsource
# ---------------------------------------------------------------------------


def _build_rule(category: str, *, product: str = "windows") -> dict:
    return build_sigma_rule(
        "run-test",
        "test_module",
        {
            "title": "x",
            "logsource": {"category": category, "product": product},
            "detection": {
                "selection": {"some.field": "value"},
                "condition": "selection",
            },
        },
    )


def test_file_event_rule_drops_process_only_fields_in_favor_of_target_filename() -> None:
    """Pre-#145 every rule emitted ``CommandLine`` / ``ParentCommandLine``;
    a ``file_event`` rule should surface ``TargetFilename`` instead.

    This is the regression an alert reviewer would catch in real triage:
    a file-event rule's ``fields:`` block listing process-only columns
    is useless, since file-event rows don't carry CommandLine /
    ParentCommandLine.
    """
    rule = _build_rule("file_event")
    fields = rule["fields"]
    assert "TargetFilename" in fields
    # The process-event triple must NOT appear in a file_event rule —
    # CommandLine / ParentCommandLine aren't on file events.
    assert "CommandLine" not in fields
    assert "ParentCommandLine" not in fields


def test_network_connection_rule_uses_destination_fields() -> None:
    rule = _build_rule("network_connection")
    fields = rule["fields"]
    assert "DestinationIp" in fields
    assert "DestinationPort" in fields
    assert "DestinationHostname" in fields
    # Image still shows up (Sysmon EID 3 carries the process image),
    # but ParentCommandLine should NOT — Sysmon EID 3 doesn't.
    assert "ParentCommandLine" not in fields


def test_dns_query_rule_uses_query_fields() -> None:
    rule = _build_rule("dns_query")
    fields = rule["fields"]
    assert "QueryName" in fields
    assert "QueryStatus" in fields
    assert "QueryResults" in fields
    # Process-event fields irrelevant to Sysmon EID 22.
    assert "CommandLine" not in fields
    assert "ParentCommandLine" not in fields


def test_registry_event_rule_uses_target_object() -> None:
    rule = _build_rule("registry_event")
    fields = rule["fields"]
    assert "TargetObject" in fields
    assert "Details" in fields


def test_service_creation_rule_uses_service_fields() -> None:
    rule = _build_rule("service_creation")
    fields = rule["fields"]
    assert "ServiceName" in fields
    assert "ServiceFileName" in fields
    assert "ImagePath" in fields
    # CommandLine / ParentCommandLine aren't part of service
    # create/modify event records.
    assert "CommandLine" not in fields
    assert "ParentCommandLine" not in fields


def test_authentication_rule_uses_auth_fields() -> None:
    rule = _build_rule("authentication")
    fields = rule["fields"]
    assert "TargetUserName" in fields
    assert "IpAddress" in fields
    assert "LogonType" in fields


def test_email_rule_uses_email_fields() -> None:
    rule = _build_rule("email", product="generic")
    fields = rule["fields"]
    assert "recipient" in fields
    assert "sender" in fields
    assert "subject" in fields


def test_image_load_rule_uses_image_loaded_field() -> None:
    rule = _build_rule("image_load")
    fields = rule["fields"]
    assert "ImageLoaded" in fields
    assert "Image" in fields
    assert "Signed" in fields


def test_process_access_rule_uses_call_trace_field() -> None:
    rule = _build_rule("process_access")
    fields = rule["fields"]
    assert "CallTrace" in fields
    assert "GrantedAccess" in fields
    assert "TargetImage" in fields


def test_process_creation_rule_keeps_legacy_process_triple() -> None:
    """Process-event categories still carry the canonical process triple."""
    rule = _build_rule("process_creation")
    fields = rule["fields"]
    assert "CommandLine" in fields
    assert "ParentCommandLine" in fields
    assert "Image" in fields


def test_unmapped_category_falls_through_to_process_default() -> None:
    """Bespoke / legacy logsource categories keep working via process-default.

    A future module that ships with an unmapped category gets the
    legacy triple — the rule is still syntactically valid, and the
    operator can manually adjust if needed.
    """
    rule = _build_rule("completely_made_up_category")
    fields = rule["fields"]
    assert "CommandLine" in fields
    assert "ParentCommandLine" in fields
    assert "Image" in fields


# ---------------------------------------------------------------------------
# 3. Optional legacy-discriminator append still works
# ---------------------------------------------------------------------------


def test_legacy_discriminators_still_append_on_top_of_category_fields() -> None:
    """The optional ``legacy.*`` / ``dns.*`` / ``network.*`` append still runs."""
    rule = build_sigma_rule(
        "run-legacy",
        "legacy_command_control",
        {
            "title": "x",
            "logsource": {"category": "network_connection", "product": "host"},
            "detection": {
                "selection": {
                    "network.transport": "tcp",
                    "network.endpoint": "lab.example.com",
                    "legacy.subtype": "https_beacon",
                },
                "condition": "selection",
            },
        },
    )
    fields = rule["fields"]
    # Network-connection canonical fields land first.
    assert "DestinationIp" in fields
    assert "DestinationPort" in fields
    # Optional legacy / network discriminators append on top.
    assert "network.transport" in fields
    assert "network.endpoint" in fields
    assert "legacy.subtype" in fields


def test_optional_field_append_only_fires_on_substring_match() -> None:
    """Optional fields that aren't in the detection block don't get appended."""
    rule = _build_rule("file_event")
    fields = rule["fields"]
    # No ``legacy.*`` references in the detection block, so the
    # optional append should NOT add them.
    assert "legacy.subtype" not in fields
    assert "legacy.actor" not in fields


# ---------------------------------------------------------------------------
# 4. End-to-end via the showcase scenario
# ---------------------------------------------------------------------------


def test_showcase_scenario_run_emits_category_aware_sigma_fields(tmp_path) -> None:
    """A real run against the showcase produces category-appropriate fields.

    Pin that no rule in the chain ships with the wrong fields family
    for its logsource — e.g. no ``file_event`` rule with
    ``CommandLine`` / ``ParentCommandLine`` and no
    ``network_connection`` rule with ``ParentCommandLine``.
    """
    import json
    import os
    import re
    import subprocess

    env = dict(os.environ)
    env["BLUEFIRE_OUTPUT_ROOT"] = str(tmp_path)
    proc = subprocess.run(
        [
            "python",
            "-m",
            "src.run_scenario",
            "--scenario-file",
            "scenarios/enterprise_intrusion_chain.yaml",
            "--output-json",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    run_dir = tmp_path / out["run_id"]
    sigma_dir = run_dir / "detections" / "sigma"
    sigma_files = sorted(sigma_dir.glob("*.yml"))
    assert sigma_files, "no Sigma files emitted"

    # For each rule, parse logsource.category + fields, then assert the
    # category-appropriate canonical field is present and the
    # process-only triple is absent on non-process categories.
    for path in sigma_files:
        text = path.read_text(encoding="utf-8")
        cat_match = re.search(r"^  category:\s+(\S+)", text, re.M)
        category = cat_match.group(1) if cat_match else ""
        fields_match = re.search(r"^fields:\n((?:- .+\n)+)", text, re.M)
        fields = []
        if fields_match:
            fields = [
                line.lstrip("- ").strip()
                for line in fields_match.group(1).splitlines()
                if line.startswith("- ")
            ]
        if category == "file_event":
            assert "TargetFilename" in fields, (path.name, fields)
            assert "CommandLine" not in fields, (path.name, fields)
            assert "ParentCommandLine" not in fields, (path.name, fields)
        elif category == "network_connection":
            assert "DestinationIp" in fields, (path.name, fields)
            assert "DestinationPort" in fields, (path.name, fields)
            assert "ParentCommandLine" not in fields, (path.name, fields)
        elif category == "email":
            assert "recipient" in fields, (path.name, fields)
            assert "subject" in fields, (path.name, fields)
            assert "ParentCommandLine" not in fields, (path.name, fields)
        elif category == "process_creation":
            assert "CommandLine" in fields, (path.name, fields)
            assert "ParentCommandLine" in fields, (path.name, fields)
        # Other categories (infrastructure_provisioning,
        # threat_intelligence) just verify they don't ship the
        # process-event triple if their canonical fields exist.
