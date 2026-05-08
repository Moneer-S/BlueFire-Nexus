"""YARA-L per-technique discriminator upgrade.

The previous YARA-L generator emitted the same two events lines
regardless of technique:

    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path contains "<process_name>"

Every generated rule — whether the technique poked the registry,
cleared a Windows event log, opened a remote process handle, or
made a DNS query — predicated on the same UDM field. A defender
analyst would reject the rule on review.

The upgrade derives the events block from the same Sigma
``logsource`` + ``detection.selection`` the Sigma path already
consumes. This file pins the new contract so a future refactor
of either generator cannot break the cross-engine consistency.

Pinned invariants:

* Sigma logsource ``category`` maps to the matching UDM
  ``metadata.event_type`` (process_creation -> PROCESS_LAUNCH,
  file_event -> FILE_MODIFICATION, registry_event ->
  REGISTRY_MODIFICATION, process_access -> PROCESS_OPEN,
  image_load -> PROCESS_MODULE_LOAD, network_connection ->
  NETWORK_CONNECTION, dns / dns_query -> NETWORK_DNS).
* Sigma selection field/value pairs lower into UDM event
  predicates (``$e.<udm_field> = ...``) using the proper field
  for that telemetry family.
* Sigma operators (``|contains`` / ``|endswith`` /
  ``|startswith`` / ``|in`` / no-modifier exact / numeric)
  surface as YARA-L regex literals or string equality
  appropriately.
* Hints with no logsource and no selection block fall back to
  the historic substring-on-process-path predicate so legacy
  callers do not regress.
* Anti-detection per-method rules (the catalog deepening from
  the prior PR) round-trip through the YARA-L generator with
  technique-relevant UDM field paths, not the legacy
  process-path-only shape.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.detections import write_detection_artifacts
from src.core.detections.yara_l import build_yara_l_rule, generate_yara_l
from src.core.models import ModuleResult


# ---------------------------------------------------------------------------
# 1. Logsource category -> UDM event_type
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "category,expected_event_type",
    [
        ("process_creation", "PROCESS_LAUNCH"),
        ("process_access", "PROCESS_OPEN"),
        ("file_event", "FILE_MODIFICATION"),
        ("registry_event", "REGISTRY_MODIFICATION"),
        ("image_load", "PROCESS_MODULE_LOAD"),
        ("network_connection", "NETWORK_CONNECTION"),
        ("dns", "NETWORK_DNS"),
        ("dns_query", "NETWORK_DNS"),
    ],
)
def test_logsource_category_maps_to_udm_event_type(
    category: str, expected_event_type: str
) -> None:
    rule = build_yara_l_rule(
        "run-1",
        "test_module",
        {
            "mitre_technique_id": "T1000",
            "logsource": {"category": category, "product": "windows"},
        },
    )
    assert f'$e.metadata.event_type = "{expected_event_type}"' in rule


def test_unknown_category_falls_back_to_generic_event() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "test_module",
        {
            "mitre_technique_id": "T1000",
            "logsource": {"category": "definitely_not_a_real_category", "product": "windows"},
        },
    )
    assert '$e.metadata.event_type = "GENERIC_EVENT"' in rule


# ---------------------------------------------------------------------------
# 2. Sigma selection -> UDM event predicates
# ---------------------------------------------------------------------------


def _hint_with_selection(selection: Dict[str, Any], category: str = "process_creation") -> Dict[str, Any]:
    return {
        "mitre_technique_id": "T1000",
        "logsource": {"category": category, "product": "windows"},
        "detection": {"selection": selection, "condition": "selection"},
    }


def test_image_endswith_lowers_to_udm_full_path_regex() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "execution",
        _hint_with_selection({"Image|endswith": "powershell.exe"}),
    )
    assert "principal.process.file.full_path" in rule
    assert "powershell\\.exe$" in rule


def test_command_line_contains_lowers_to_udm_command_line_regex() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "execution",
        _hint_with_selection({"CommandLine|contains": "-EncodedCommand"}),
    )
    assert "$e.principal.process.command_line = /.*\\-EncodedCommand.*/ nocase" in rule


def test_target_filename_endswith_lowers_to_target_file_path() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "anti_detection",
        _hint_with_selection(
            {"TargetFilename|endswith": "\\drivers\\etc\\hosts"},
            category="file_event",
        ),
    )
    assert "$e.target.file.full_path" in rule
    assert "drivers" in rule
    assert "hosts$" in rule


def test_target_object_contains_lowers_to_registry_key() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "anti_detection",
        _hint_with_selection(
            {"TargetObject|contains": "VBoxService"},
            category="registry_event",
        ),
    )
    assert "$e.target.registry.registry_key = /.*VBoxService.*/ nocase" in rule


def test_call_trace_contains_lowers_to_principal_api_calls() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "anti_detection",
        _hint_with_selection(
            {"CallTrace|contains": "GetProcAddress"},
            category="process_access",
        ),
    )
    assert "$e.principal.process.api_calls = /.*GetProcAddress.*/ nocase" in rule


def test_image_loaded_endswith_lowers_to_target_process_full_path() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "anti_detection",
        _hint_with_selection(
            {"ImageLoaded|endswith": "\\unsigned_module.dll"},
            category="image_load",
        ),
    )
    assert "$e.target.process.file.full_path" in rule
    assert "unsigned_module\\.dll$" in rule


def test_parent_command_line_contains_lowers_to_parent_command_line() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "anti_detection",
        _hint_with_selection(
            {"ParentCommandLine|contains": "svchost.exe -k"},
        ),
    )
    assert (
        "$e.principal.process.parent_process.command_line = /.*svchost\\.exe\\ \\-k.*/ nocase"
        in rule
    )


def test_parent_image_endswith_lowers_to_parent_full_path() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "anti_detection",
        _hint_with_selection({"ParentImage|endswith": "\\explorer.exe"}),
    )
    assert "$e.principal.process.parent_process.file.full_path" in rule
    assert "explorer\\.exe$" in rule


def test_event_id_lowers_to_metadata_product_event_type() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "anti_detection",
        _hint_with_selection({"EventID": 4663}, category="file_event"),
    )
    assert "$e.metadata.product_event_type = 4663" in rule


# ---------------------------------------------------------------------------
# 3. Sigma operator semantics
# ---------------------------------------------------------------------------


def test_no_modifier_uses_string_equality() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "execution",
        _hint_with_selection({"Image": "C:\\Windows\\System32\\cmd.exe"}),
    )
    # String literal, escaped backslashes
    assert (
        '$e.principal.process.file.full_path = "C:\\\\Windows\\\\System32\\\\cmd.exe"'
        in rule
    )


def test_in_modifier_with_list_renders_anchored_alternation_regex() -> None:
    """``|in`` lists render as ``^(...)$`` to preserve list-membership
    semantics; an unanchored regex would match substrings (Codex P2)."""
    rule = build_yara_l_rule(
        "run-1",
        "execution",
        _hint_with_selection({"CommandLine|in": ["foo", "bar", "baz"]}),
    )
    assert "/^(foo|bar|baz)$/ nocase" in rule


def test_numeric_value_with_no_modifier_emits_unquoted() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "command_control",
        _hint_with_selection(
            {"network.dst_port": 9001},
            category="network_connection",
        ),
    )
    assert "$e.target.port = 9001" in rule
    assert '$e.target.port = "9001"' not in rule


def test_value_containing_regex_metacharacters_is_escaped() -> None:
    """``re.escape`` ensures dots/dollars in user values are literal."""
    rule = build_yara_l_rule(
        "run-1",
        "exfiltration",
        _hint_with_selection({"network.endpoint|contains": "exfil.example.lab"}),
    )
    # Dots must be escaped so they match literally, not "any char"
    assert "exfil\\.example\\.lab" in rule


def test_value_with_embedded_slash_is_escaped() -> None:
    """``/`` in a value would otherwise terminate the regex literal."""
    rule = build_yara_l_rule(
        "run-1",
        "exfiltration",
        _hint_with_selection({"network.endpoint|contains": "/api/v1/upload"}),
    )
    assert "\\/api\\/v1\\/upload" in rule


# ---------------------------------------------------------------------------
# 4. Fallback shape for hints with no logsource / no selection
# ---------------------------------------------------------------------------


def test_no_logsource_no_selection_keeps_legacy_fallback() -> None:
    """Existing callers with bare-meta hints stay on the historic shape."""
    rule = build_yara_l_rule(
        "run-1",
        "execution",
        {"mitre_technique_id": "T1059"},
    )
    # Historic fallback: PROCESS_LAUNCH event type
    assert '$e.metadata.event_type = "PROCESS_LAUNCH"' in rule
    # Substring-on-process-path predicate uses the module name
    # when no other identifier is present
    assert "$e.target.process.file.full_path" in rule
    assert "execution" in rule


def test_no_logsource_with_selection_still_uses_selection() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "execution",
        {
            "mitre_technique_id": "T1059",
            "detection": {"selection": {"CommandLine|contains": "-Encoded"}, "condition": "selection"},
        },
    )
    # Selection wins over the legacy fallback
    assert "$e.principal.process.command_line = /.*\\-Encoded.*/ nocase" in rule
    # Without a logsource block we still fall back to PROCESS_LAUNCH
    # because exact category was unknown.
    assert '$e.metadata.event_type = "PROCESS_LAUNCH"' in rule


# ---------------------------------------------------------------------------
# 5. Logsource block surfaces in meta for analyst review
# ---------------------------------------------------------------------------


def test_logsource_product_and_category_surface_in_meta_block() -> None:
    rule = build_yara_l_rule(
        "run-1",
        "anti_detection",
        _hint_with_selection(
            {"TargetObject|contains": "VBoxService"},
            category="registry_event",
        ),
    )
    assert 'logsource_product = "windows"' in rule
    assert 'logsource_category = "registry_event"' in rule


# ---------------------------------------------------------------------------
# 6. Per-tactic exemplars — the kind of hint a real module emits round-trips
#    through the generator with the proper UDM field for that telemetry family.
# ---------------------------------------------------------------------------


def test_log_clear_style_hint_lowers_to_command_line_predicate() -> None:
    """A log-clear-style hint (process_creation logsource, CommandLine
    selector) should land a CommandLine discriminator, not a generic
    process-path match."""
    yaral = generate_yara_l(
        "anti_detection",
        "T1070.001",
        _hint_with_selection({"CommandLine|contains": "wevtutil cl"}),
        run_id="run-exemplar-1",
    )
    assert "$e.principal.process.command_line" in yaral
    assert "wevtutil" in yaral
    assert '$e.metadata.event_type = "PROCESS_LAUNCH"' in yaral


def test_registry_style_hint_lowers_to_registry_key_predicate() -> None:
    """An anti-VM-style hint (registry_event logsource, TargetObject
    selector) should land a registry key discriminator."""
    yaral = generate_yara_l(
        "anti_detection",
        "T1497.001",
        _hint_with_selection(
            {"TargetObject|contains": "VBoxService"},
            category="registry_event",
        ),
        run_id="run-exemplar-2",
    )
    assert "$e.target.registry.registry_key" in yaral
    assert "VBoxService" in yaral
    assert '$e.metadata.event_type = "REGISTRY_MODIFICATION"' in yaral


def test_image_load_style_hint_lowers_to_target_process_path() -> None:
    """A reflective-loading-style hint (image_load logsource,
    ImageLoaded selector) should land a target.process.file.full_path
    discriminator with PROCESS_MODULE_LOAD event type."""
    yaral = generate_yara_l(
        "anti_detection",
        "T1620",
        _hint_with_selection(
            {"ImageLoaded|endswith": "\\unsigned_module.dll"},
            category="image_load",
        ),
        run_id="run-exemplar-3",
    )
    assert "$e.target.process.file.full_path" in yaral
    assert "unsigned_module" in yaral
    assert '$e.metadata.event_type = "PROCESS_MODULE_LOAD"' in yaral


def test_process_access_style_hint_lowers_to_api_calls_predicate() -> None:
    """A dynamic-api-style hint (process_access logsource, CallTrace
    selector) should land an api_calls discriminator with PROCESS_OPEN
    event type."""
    yaral = generate_yara_l(
        "anti_detection",
        "T1027.007",
        _hint_with_selection(
            {"CallTrace|contains": "GetProcAddress"},
            category="process_access",
        ),
        run_id="run-exemplar-4",
    )
    assert "$e.principal.process.api_calls" in yaral
    assert "GetProcAddress" in yaral
    assert '$e.metadata.event_type = "PROCESS_OPEN"' in yaral


# ---------------------------------------------------------------------------
# 7. End-to-end via the full engine
# ---------------------------------------------------------------------------


def test_engine_writes_yara_l_with_per_technique_predicates(tmp_path: Path) -> None:
    """The detection engine threads the hint's selection block through
    so the on-disk YARA-L rule has technique-specific discriminators."""
    result = ModuleResult(
        status="success",
        module="anti_detection",
        message="Simulated EDR API unhooking.",
        techniques=["T1562.001"],
        artifacts={},
        detection_hints={
            "title": "EDR API unhooking on host",
            "mitre_technique": "T1562.001",
            "logsource": {"category": "process_access", "product": "windows"},
            "detection": {
                "selection": {"CallTrace|contains": "ntdll.dll+"},
                "condition": "selection",
            },
        },
        telemetry=[],
    )
    artifacts = write_detection_artifacts(
        tmp_path, "run-engine-yaral", {"anti_detection": result}
    )
    yaral_path = Path(artifacts["yara_l"][0])
    body = yaral_path.read_text(encoding="utf-8")
    assert '$e.metadata.event_type = "PROCESS_OPEN"' in body
    assert "$e.principal.process.api_calls = /.*ntdll\\.dll\\+.*/ nocase" in body
    # And the meta correlation fields survive the upgrade
    assert 'run_id = "run-engine-yaral"' in body
    assert 'technique = "T1562.001"' in body


def test_engine_yaral_legacy_fallback_when_hint_has_no_selection(tmp_path: Path) -> None:
    """Legacy callers that produce a hint without ``detection.selection``
    keep the historic process-path substring predicate so detection-tooling
    that grepped against the legacy form still matches."""
    result = ModuleResult(
        status="success",
        module="legacy_capability_summary",
        message="Pack summary.",
        techniques=["T0000"],
        artifacts={},
        detection_hints={"title": "Legacy summary"},
        telemetry=[],
    )
    artifacts = write_detection_artifacts(
        tmp_path, "run-engine-fallback", {"legacy_capability_summary": result}
    )
    yaral_path = Path(artifacts["yara_l"][0])
    body = yaral_path.read_text(encoding="utf-8")
    assert "$e.target.process.file.full_path" in body


# ---------------------------------------------------------------------------
# 8. Codex-found regressions: category-aware unmapped-field fallback
#    + anchored ``|in`` regex semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "category,expected_udm",
    [
        ("file_event", "$e.target.file.full_path"),
        ("registry_event", "$e.target.registry.registry_key"),
        ("process_creation", "$e.principal.process.command_line"),
        ("process_access", "$e.principal.process.api_calls"),
        ("image_load", "$e.target.process.file.full_path"),
        ("network_connection", "$e.target.hostname"),
        ("dns", "$e.network.dns.questions.name"),
        ("email", "$e.network.email.to"),
    ],
)
def test_unmapped_field_falls_back_to_category_appropriate_udm(
    category: str, expected_udm: str
) -> None:
    """An unmapped Sigma field must NOT silently land on
    ``principal.process.command_line`` for non-process categories.

    Codex P1 finding: the previous fallback rewrote every unmapped
    selection key to ``principal.process.command_line``, which was
    nonsense inside a NETWORK_CONNECTION / FILE_MODIFICATION /
    REGISTRY_MODIFICATION rule. The fallback now picks a UDM path
    in the same telemetry family as the rule's logsource category.
    """
    rule = build_yara_l_rule(
        "run-1",
        "test_module",
        _hint_with_selection(
            {"completely_unknown_field|contains": "foo"},
            category=category,
        ),
    )
    assert expected_udm in rule, (
        f"unmapped field in {category} rule should fall back to "
        f"{expected_udm}, got:\n{rule}"
    )


@pytest.mark.parametrize(
    "shipped_field,expected_udm",
    [
        ("network.dst_host|in", "$e.target.hostname"),
        ("network.dst_host|contains", "$e.target.hostname"),
        ("network.banner_grab", "$e.network.received_bytes"),
        ("network.protocol", "$e.network.application_protocol"),
        ("network.tool", "$e.principal.process.file.full_path"),
        ("network.url|contains", "$e.target.url"),
        ("network.target|in", "$e.target.hostname"),
        ("file.extension|in", "$e.target.file.full_path"),
        ("file.action", "$e.metadata.event_subtype"),
        ("file.operation", "$e.metadata.event_subtype"),
        ("file.attributes|contains", "$e.target.file.attribute"),
        ("service.name|contains", "$e.target.resource.name"),
        ("service.image_path|contains", "$e.target.process.file.full_path"),
        ("service.action", "$e.metadata.event_subtype"),
        ("resource.kind", "$e.target.resource.resource_type"),
        ("email.recipient|contains", "$e.network.email.to"),
        ("process.image|endswith", "$e.principal.process.file.full_path"),
    ],
)
def test_shipped_module_selection_fields_have_explicit_udm_mapping(
    shipped_field: str, expected_udm: str
) -> None:
    """Every Sigma selection key actually used by a shipped standard module
    must have an explicit (not category-fallback) UDM mapping. Adding a
    new ``selection_field`` to a profile without a matching UDM entry
    silently degrades the resulting YARA-L rule into the fallback path."""
    rule = build_yara_l_rule(
        "run-1",
        "test_module",
        _hint_with_selection(
            {shipped_field: ["v1", "v2"] if shipped_field.endswith("|in") else "v"},
            category="network_connection",
        ),
    )
    assert expected_udm in rule, (
        f"shipped field '{shipped_field}' should map to {expected_udm}"
    )


def test_in_modifier_regex_is_anchored_to_prevent_substring_overmatch() -> None:
    """``|in: [evil.com, github.com]`` must NOT match ``notgithub.com``.

    Codex P2 finding: list-valued predicates were rendered as
    unanchored regex alternation (``/(a|b|c)/``), which turns
    ``|in`` into substring matching. A rule meant for an exact
    domain list would overmatch on any host containing one of the
    list values as a substring. Anchoring with ``^...$`` restores
    list-membership semantics.
    """
    rule = build_yara_l_rule(
        "run-1",
        "exfiltration",
        _hint_with_selection(
            {"network.dst_host|in": ["github.com", "evil.com"]},
            category="network_connection",
        ),
    )
    assert "/^(github\\.com|evil\\.com)$/ nocase" in rule, (
        f"|in regex must be anchored, got:\n{rule}"
    )
    # Explicitly NOT the unanchored shape that would substring-match
    assert "/(github\\.com|evil\\.com)/ nocase" not in rule


def test_in_modifier_with_single_value_still_anchored() -> None:
    """A single-value ``|in`` list is still rendered as an anchored
    regex so callers cannot accidentally rely on substring matching
    by passing a one-element list."""
    rule = build_yara_l_rule(
        "run-1",
        "exfiltration",
        _hint_with_selection(
            {"network.dst_host|in": ["evil.com"]},
            category="network_connection",
        ),
    )
    assert "/^(evil\\.com)$/ nocase" in rule


def test_in_with_dns_record_types_anchors_on_short_values() -> None:
    """Short ``|in`` values (e.g. DNS record-type codes) are
    especially prone to substring overmatch (``A`` matching
    ``AAAA`` / ``ANY`` / ``ALIAS``); the anchored regex prevents
    this."""
    rule = build_yara_l_rule(
        "run-1",
        "command_control",
        _hint_with_selection(
            {"dns.record_type|in": ["A", "AAAA", "TXT"]},
            category="dns",
        ),
    )
    assert "/^(A|AAAA|TXT)$/ nocase" in rule


# ---------------------------------------------------------------------------
# 9. |contains_any / |contains_all modifier semantics (Codex P1 follow-up)
# ---------------------------------------------------------------------------


def test_contains_any_with_list_renders_unanchored_alternation_regex() -> None:
    """``|contains_any: [a, b, c]`` is substring-OR semantics, NOT
    exact membership. The shipped legacy_packs.py hint
    ``process.command_line|contains_any: ["-enc", "-nop"]`` would
    be unsatisfiable when paired with a sibling
    ``|contains: "powershell"`` predicate if the list became
    ``= /^(-enc|-nop)$/`` - the full command line cannot be both
    exactly ``-enc`` AND contain ``powershell``.

    Codex P1 follow-up: ``|contains_any`` lists must render as
    unanchored alternation regex so each value is checked as a
    substring of the field, not the whole value.
    """
    rule = build_yara_l_rule(
        "run-1",
        "execution",
        _hint_with_selection(
            {"process.command_line|contains_any": ["-enc", "-nop"]}
        ),
    )
    # Unanchored alternation
    assert "/(\\-enc|\\-nop)/ nocase" in rule, (
        f"|contains_any list should be unanchored alternation, got:\n{rule}"
    )
    # Explicitly NOT the anchored shape (would be unsatisfiable
    # when paired with another contains predicate)
    assert "/^(\\-enc|\\-nop)$/ nocase" not in rule


def test_contains_any_with_single_value_renders_substring_regex() -> None:
    """A single-value ``|contains_any`` collapses to substring
    match rather than exact equality."""
    rule = build_yara_l_rule(
        "run-1",
        "execution",
        _hint_with_selection({"CommandLine|contains_any": "Invoke-Expression"}),
    )
    assert "/.*Invoke\\-Expression.*/ nocase" in rule


def test_contains_all_renders_separate_predicates_for_each_value() -> None:
    """``|contains_all: [a, b]`` must mean each substring is
    present (AND semantics). Render as separate predicates so the
    YARA-L engine ANDs them naturally.
    """
    rule = build_yara_l_rule(
        "run-1",
        "execution",
        _hint_with_selection(
            {"CommandLine|contains_all": ["powershell", "-EncodedCommand"]}
        ),
    )
    assert "/.*powershell.*/ nocase" in rule
    assert "/.*\\-EncodedCommand.*/ nocase" in rule


def test_legacy_packs_contains_any_hint_round_trips_without_overmatch(tmp_path: Path) -> None:
    """End-to-end regression: the shipped ``legacy_packs.py``
    `process.command_line|contains_any: ["-enc", "-nop"]` hint must
    produce a YARA-L rule that is satisfiable when combined with a
    sibling ``|contains: "powershell"`` predicate (the rule the
    legacy_packs adapter actually emits).
    """
    result = ModuleResult(
        status="success",
        module="legacy_actor_profile",
        message="Legacy actor profile prepared.",
        techniques=["T1059.001"],
        artifacts={},
        detection_hints={
            "title": "Suspicious PowerShell command line",
            "mitre_technique": "T1059.001",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {
                    "process.command_line|contains": "powershell",
                    "process.command_line|contains_any": ["-enc", "-nop"],
                },
                "condition": "selection",
            },
        },
        telemetry=[],
    )
    artifacts = write_detection_artifacts(
        tmp_path, "run-legacy-contains-any", {"legacy_actor_profile": result}
    )
    body = Path(artifacts["yara_l"][0]).read_text(encoding="utf-8")
    # |contains: "powershell" -> substring regex
    assert "/.*powershell.*/ nocase" in body
    # |contains_any: ["-enc", "-nop"] -> unanchored alternation
    assert "/(\\-enc|\\-nop)/ nocase" in body
    # Anchoring would have made the rule unsatisfiable here.
    assert "/^(\\-enc|\\-nop)$/ nocase" not in body
