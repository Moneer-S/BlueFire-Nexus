"""SPL renderer CIM translation, datamodel hint, numeric handling.

PR #143 lifted SPL from "draft / starter" emitting raw Sigma field
names (``| where Image="*powershell.exe"``) to a CIM-aware form
emitting Splunk Common Information Model field names
(``| where process_path="*powershell.exe"``). CIM is the canonical
field-normalisation layer Splunk Enterprise Security and every major
Splunk app rely on; the previous output only fired against the raw
Sysmon shape.

Pinned invariants:

1. Each documented Sigma field translates to its canonical CIM field.
2. Modifier semantics (``contains`` / ``startswith`` / ``endswith``)
   survive the translation — wildcards land on the CIM field, not on
   the original Sigma field.
3. Lists become ``IN (...)`` clauses against the CIM field.
4. Numeric CIM fields (``dest_port`` / ``src_port``) emit unquoted
   predicates so Splunk's numeric range / ``tstats`` semantics keep
   working.
5. The CIM datamodel hint comment surfaces for mapped logsource
   pairs and is suppressed for unmapped pairs (no fake datamodel).
6. Unmapped Sigma fields fall through to the verbatim name so the
   rule stays syntactically valid.
"""

from __future__ import annotations

import pytest

from src.core.detections.spl import (
    _CIM_NUMERIC_FIELDS,
    _LOGSOURCE_TO_DATAMODEL,
    _SIGMA_FIELD_TO_CIM,
    _cim_field,
    _datamodel_for,
    _is_numeric_value,
    render_spl,
)
from src.core.models import ModuleResult


# ---------------------------------------------------------------------------
# 1. Sigma field -> CIM field name translation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sigma_field,expected_cim",
    [
        # Endpoint.Processes
        ("Image", "process_path"),
        ("CommandLine", "process"),
        ("ParentImage", "parent_process_path"),
        ("ParentCommandLine", "parent_process"),
        ("User", "user"),
        ("process.image", "process_path"),
        ("process.name", "process_name"),
        ("process.command_line", "process"),
        ("process.parent_command_line", "parent_process"),
        ("process.parent.command_line", "parent_process"),
        ("target.process.name", "process_name"),
        # Endpoint.Filesystem
        ("TargetFilename", "file_path"),
        ("file.path", "file_path"),
        ("file.name", "file_name"),
        ("file.extension", "file_extension"),
        ("file.action", "action"),
        ("file.operation", "action"),
        # Endpoint.Registry
        ("TargetObject", "registry_path"),
        ("registry.key", "registry_path"),
        ("registry.key.path", "registry_path"),
        # Endpoint.Services
        ("service.name", "service"),
        ("service.image_path", "file_path"),
        ("service.action", "action"),
        # Authentication.Authentication
        ("user.name", "user"),
        ("user.domain", "dest_nt_domain"),
        ("user.windows_domain", "dest_nt_domain"),
        ("event.action", "action"),
        # Network_Traffic.All_Traffic
        ("network.dst_port", "dest_port"),
        ("network.dst_host", "dest"),
        ("network.dst_hostname", "dest"),
        ("network.dst_ip", "dest_ip"),
        ("network.dst_country", "dest_country"),
        ("network.target", "dest"),
        ("network.transport", "transport"),
        ("network.protocol", "app"),
        ("network.url", "url"),
        # Network_Resolution.DNS
        ("dns.question.name", "query"),
        ("dns.record_type", "record_type"),
        # Web.Web
        ("http.url", "url"),
        ("http.user_agent", "http_user_agent"),
        ("http.method", "http_method"),
        # Email.All_Email
        ("email.recipient", "recipient"),
        ("email.subject", "subject"),
        ("email.url", "url"),
        ("email.attachment.extension", "file_name"),
        ("email.sender.service", "src_user"),
        # Threat_Intelligence
        ("threat.actor", "threat_group"),
        ("threat.ttp_focus", "threat_category"),
        ("threat.ioc_class", "ioc_type"),
        ("threat.cve_pattern", "cve"),
        ("threat.domain_pattern", "domain"),
        ("threat.network_pattern", "src"),
    ],
)
def test_sigma_field_translates_to_cim(
    sigma_field: str, expected_cim: str
) -> None:
    """Every documented Sigma field name maps to its canonical CIM field."""
    assert _cim_field(sigma_field) == expected_cim
    # The mapping table itself must agree.
    assert _SIGMA_FIELD_TO_CIM[sigma_field] == expected_cim


def test_unmapped_sigma_field_falls_through_to_verbatim() -> None:
    """Unmapped Sigma fields pass through unchanged — the rule stays valid.

    The renderer intentionally does not pick a category-keyed default
    because SPL accepts any field name in a ``where`` clause; falling
    through means the operator can manually rename when no CIM field
    exists.
    """
    assert _cim_field("file.entropy") == "file.entropy"
    assert _cim_field("custom.bluefire_artifact") == "custom.bluefire_artifact"
    assert _cim_field("call.callee.user") == "call.callee.user"


def test_image_loaded_falls_through_unmapped() -> None:
    """Sysmon EventCode=7 ``ImageLoaded`` has no canonical CIM equivalent.

    CIM's ``process_path`` represents the EXECUTING process
    executable, not a loaded module. Mapping ``ImageLoaded`` onto
    ``process_path`` would silently rewrite image-load (Sysmon EC=7)
    detections into executable-name matches and miss the intended
    events. Codex P1 finding on PR #143; pin the verbatim
    pass-through so a future refactor can't reintroduce the
    semantically-wrong rewrite.
    """
    assert _cim_field("ImageLoaded") == "ImageLoaded"
    assert "ImageLoaded" not in _SIGMA_FIELD_TO_CIM
    spl = render_spl(
        _result(
            {"ImageLoaded|endswith": "\\unsigned_module.dll"},
            category="image_load",
        ),
        "run-imageloaded-1",
    )
    # Verbatim pass-through is the right answer — no rewrite to
    # process_path. CIM-after-Sysmon extractions preserve the
    # ImageLoaded field, so the rule is still defensible.
    assert '| where ImageLoaded="*\\unsigned_module.dll"' in spl
    assert "process_path" not in spl.split("CIM datamodel hint")[1] if "CIM datamodel hint" in spl else True


def test_file_extension_maps_to_cim_file_extension() -> None:
    """``file.extension`` -> CIM ``file_extension``, NOT ``file_name``.

    Sigma's ``file.extension|in`` carries just the suffix (``.locked``,
    ``.enc``); the CIM canonical field for that is ``file_extension``.
    The previous mapping onto ``file_name`` turned extension-IN
    selections into full-name-equality checks that almost never match
    a real filename — false negatives across the impact
    data_encryption profile. Codex P1 finding on PR #143.
    """
    assert _cim_field("file.extension") == "file_extension"
    spl = render_spl(
        _result(
            {"file.extension|in": [".locked", ".enc", ".crypt"]},
            category="file_event",
        ),
        "run-file-ext-1",
    )
    assert '| where file_extension IN (".locked", ".enc", ".crypt")' in spl
    # The previous (wrong) mapping must NOT survive.
    assert "file_name IN " not in spl


# ---------------------------------------------------------------------------
# 2. End-to-end SPL render uses CIM names with modifiers preserved
# ---------------------------------------------------------------------------


def _result(selection: dict, *, product: str = "windows", category: str = "process_creation") -> ModuleResult:
    return ModuleResult(
        status="success",
        module="execution",
        message="ok",
        techniques=["T1000"],
        artifacts={},
        detection_hints={
            "title": "test",
            "logsource": {"product": product, "category": category},
            "detection": {"selection": selection, "condition": "selection"},
        },
        telemetry=[],
    )


def test_render_endpoint_process_uses_cim_process_path_and_process() -> None:
    """``Image|endswith`` -> ``process_path``; ``CommandLine|contains`` -> ``process``.

    Wildcard semantics from the modifier survive the field translation.
    """
    spl = render_spl(
        _result(
            {
                "Image|endswith": "rundll32.exe",
                "CommandLine|contains": "javascript:",
            }
        ),
        "run-cim-1",
    )
    assert '| where process_path="*rundll32.exe"' in spl
    assert '| where process="*javascript:*"' in spl
    # The raw Sigma fields are gone — CIM-only environments can match.
    assert "where Image=" not in spl
    assert "where CommandLine=" not in spl


def test_render_dns_uses_cim_query_and_record_type() -> None:
    """``dns.question.name`` -> ``query`` (Network_Resolution.DNS canonical)."""
    spl = render_spl(
        _result(
            {
                "dns.question.name|contains": "exfil.lab",
                "dns.record_type": "TXT",
            },
            product="dns",
            category="dns_query",
        ),
        "run-cim-2",
    )
    assert '| where query="*exfil.lab*"' in spl
    assert '| where record_type="TXT"' in spl
    assert "where dns.question.name=" not in spl


def test_render_network_traffic_uses_cim_dest_and_transport() -> None:
    """``network.dst_host|contains`` -> ``dest``; ``network.transport`` -> ``transport``."""
    spl = render_spl(
        _result(
            {
                "network.dst_host|contains": "beacon.lab",
                "network.transport": "tcp",
            },
            category="network_connection",
        ),
        "run-cim-3",
    )
    assert '| where dest="*beacon.lab*"' in spl
    assert '| where transport="tcp"' in spl


def test_render_email_uses_cim_recipient_and_subject() -> None:
    """``email.recipient`` / ``email.subject`` -> CIM ``recipient`` / ``subject``."""
    spl = render_spl(
        _result(
            {
                "email.recipient|contains": "@example.lab",
                "email.subject|contains": "wire transfer",
            },
            product="generic",
            category="email",
        ),
        "run-cim-4",
    )
    assert '| where recipient="*@example.lab*"' in spl
    assert '| where subject="*wire transfer*"' in spl


def test_render_web_proxy_uses_cim_url_and_user_agent() -> None:
    """``http.url`` -> ``url``; ``http.user_agent`` -> ``http_user_agent``."""
    spl = render_spl(
        _result(
            {
                "http.url|contains": "/admin",
                "http.user_agent|contains": "BlueFire",
            },
            product="generic",
            category="webserver",
        ),
        "run-cim-5",
    )
    assert '| where url="*/admin*"' in spl
    assert '| where http_user_agent="*BlueFire*"' in spl


def test_render_authentication_uses_cim_user_and_domain() -> None:
    """``user.name`` -> ``user``; ``user.domain`` -> ``dest_nt_domain``."""
    spl = render_spl(
        _result(
            {
                "user.name|contains": "svc-",
                "user.domain": "EXAMPLE",
            },
            product="windows",
            category="authentication",
        ),
        "run-cim-6",
    )
    assert '| where user="*svc-*"' in spl
    assert '| where dest_nt_domain="EXAMPLE"' in spl


def test_render_filesystem_uses_cim_file_path_and_action() -> None:
    """``TargetFilename`` -> ``file_path``; ``file.action`` -> ``action``."""
    spl = render_spl(
        _result(
            {
                "TargetFilename|endswith": ".lnk",
                "file.action": "create",
            },
            category="file_event",
        ),
        "run-cim-7",
    )
    assert '| where file_path="*.lnk"' in spl
    assert '| where action="create"' in spl


def test_render_registry_uses_cim_registry_path() -> None:
    """``TargetObject`` / ``registry.key`` -> ``registry_path``."""
    spl = render_spl(
        _result(
            {
                "TargetObject|contains": "\\Run\\",
                "registry.key|endswith": "\\Image File Execution Options",
            },
            category="registry_event",
        ),
        "run-cim-8",
    )
    # Both fields collapse onto registry_path; both clauses appear.
    assert '| where registry_path="*\\Run\\*"' in spl
    assert '| where registry_path="*\\Image File Execution Options"' in spl
    # The raw Sigma fields are gone.
    assert "where TargetObject=" not in spl
    assert "where registry.key=" not in spl


# ---------------------------------------------------------------------------
# 3. Numeric value handling for numeric CIM fields
# ---------------------------------------------------------------------------


def test_numeric_dest_port_emits_unquoted_predicate() -> None:
    """``network.dst_port: 443`` -> ``dest_port=443`` (unquoted, numeric semantics)."""
    spl = render_spl(
        _result(
            {"network.dst_port": 443},
            category="network_connection",
        ),
        "run-num-1",
    )
    assert "| where dest_port=443" in spl
    # The previous behaviour of quoting numeric values must NOT survive.
    assert '| where dest_port="443"' not in spl


def test_numeric_dest_port_string_digit_also_unquoted() -> None:
    """Sigma authors often write ports as digit-only strings; still numeric."""
    spl = render_spl(
        _result(
            {"network.dst_port": "8443"},
            category="network_connection",
        ),
        "run-num-2",
    )
    assert "| where dest_port=8443" in spl


def test_numeric_dest_port_list_emits_unquoted_in_clause() -> None:
    """List of numeric ports -> ``dest_port IN (80, 443, 8443)``."""
    spl = render_spl(
        _result(
            {"network.dst_port": [80, 443, 8443]},
            category="network_connection",
        ),
        "run-num-3",
    )
    assert "| where dest_port IN (80, 443, 8443)" in spl
    # No quoting around the integer alternation.
    assert '| where dest_port IN ("80", "443", "8443")' not in spl


def test_numeric_field_with_modifier_keeps_quotes() -> None:
    """Modifier semantics force quoting (``dest_port|startswith: 44`` -> wildcard)."""
    spl = render_spl(
        _result(
            {"network.dst_port|startswith": "44"},
            category="network_connection",
        ),
        "run-num-4",
    )
    # With a modifier the value is rendered as a wildcarded string —
    # numeric short-circuit only fires for plain equality.
    assert '| where dest_port="44*"' in spl


def test_is_numeric_value_helper_rejects_bool_and_floats() -> None:
    """``_is_numeric_value`` must not treat bool / float as numeric.

    ``bool`` is a Python int subclass, so a naive ``isinstance(v, int)``
    check would let ``True`` round-trip as ``1``. The helper guards
    against that. Floats are excluded too so version strings like
    ``"1.0"`` (parsed elsewhere as floats) keep their quoted form.
    """
    assert _is_numeric_value(443)
    assert _is_numeric_value("443")
    assert _is_numeric_value("-1")
    assert not _is_numeric_value(True)
    assert not _is_numeric_value(False)
    assert not _is_numeric_value(1.5)
    assert not _is_numeric_value("1.0")
    assert not _is_numeric_value("443/tcp")
    assert not _is_numeric_value("")
    assert not _is_numeric_value(None)


def test_numeric_field_set_includes_dest_port_and_src_port() -> None:
    """The numeric field set must include the canonical CIM port fields."""
    assert "dest_port" in _CIM_NUMERIC_FIELDS
    assert "src_port" in _CIM_NUMERIC_FIELDS


# ---------------------------------------------------------------------------
# 4. CIM datamodel hint comment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "product,category,expected_datamodel",
    [
        ("windows", "process_creation", "Endpoint.Processes"),
        ("linux", "process_creation", "Endpoint.Processes"),
        ("windows", "process_access", "Endpoint.Processes"),
        ("windows", "image_load", "Endpoint.Processes"),
        ("windows", "service_creation", "Endpoint.Services"),
        ("windows", "service_modification", "Endpoint.Services"),
        ("windows", "network_connection", "Network_Traffic.All_Traffic"),
        ("windows", "dns_query", "Network_Resolution.DNS"),
        ("dns", "dns_query", "Network_Resolution.DNS"),
        ("windows", "file_event", "Endpoint.Filesystem"),
        ("windows", "registry_event", "Endpoint.Registry"),
        ("windows", "authentication", "Authentication.Authentication"),
        ("generic", "cloud_audit", "Change.All_Changes"),
        ("generic", "webserver", "Web.Web"),
        ("generic", "proxy", "Web.Web"),
        ("generic", "email", "Email.All_Email"),
    ],
)
def test_datamodel_for_returns_canonical_splunk_cim_datamodel(
    product: str, category: str, expected_datamodel: str
) -> None:
    """Each mapped logsource pair surfaces the canonical CIM datamodel."""
    assert _datamodel_for(product, category) == expected_datamodel
    assert _LOGSOURCE_TO_DATAMODEL[(product, category)] == expected_datamodel


def test_datamodel_for_unmapped_pair_returns_empty() -> None:
    """Unmapped logsource pair -> empty string; renderer suppresses the hint."""
    assert _datamodel_for("vendor", "threat_intelligence") == ""
    assert _datamodel_for("bluefire", "legacy_wrapped") == ""
    assert _datamodel_for("nonexistent", "fake_category") == ""


def test_render_includes_datamodel_hint_for_mapped_logsource() -> None:
    """The CIM datamodel hint comment surfaces in the rendered SPL header."""
    spl = render_spl(
        _result({"Image|endswith": "x.exe"}, category="process_creation"),
        "run-dm-1",
    )
    assert "CIM datamodel hint: Endpoint.Processes" in spl
    # The hint is positioned in the header (before the index= line).
    header_section = spl.split("\nindex=", 1)[0]
    assert "CIM datamodel hint" in header_section
    # And it points operators at tstats acceleration.
    assert "tstats summariesonly=t" in spl
    assert "from datamodel=" in spl


def test_render_suppresses_datamodel_hint_for_unmapped_logsource() -> None:
    """No CIM datamodel hint surfaces when the logsource pair is unmapped.

    Threat-intel / legacy-wrapped families have no canonical CIM
    datamodel; emitting a hint would mislead operators toward a
    nonexistent acceleration pattern.
    """
    spl = render_spl(
        _result(
            {"threat.actor": "APT-X"},
            product="vendor",
            category="threat_intelligence",
        ),
        "run-dm-2",
    )
    assert "CIM datamodel hint" not in spl


# ---------------------------------------------------------------------------
# 5. Selection comment now signals CIM, not "field-name to environment"
# ---------------------------------------------------------------------------


def test_selection_comment_signals_cim() -> None:
    """The selection-clauses preamble comment now references CIM directly."""
    spl = render_spl(
        _result({"Image|endswith": "x.exe"}, category="process_creation"),
        "run-comment-1",
    )
    assert "Splunk CIM field names" in spl
    # The previous, vaguer "adjust field names" wording is gone — the
    # rule is now CIM-aware so the operator only adjusts when their
    # environment isn't CIM-normalised.
    assert "adjust field names to your environment" not in spl
