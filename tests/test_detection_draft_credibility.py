"""Detection draft credibility — pre-rc1 polish gate.

Two release-candidate polish bugs were caught during the fresh-
clone Windows smoke run and are pinned here so they cannot
regress:

1. **YARA-L stale ``run_id``.** The detection engine wrote real
   run ids into the Sigma rule but the YARA-L rule next to it
   carried ``meta.run_id = "manual"`` regardless. A defender
   correlating Sigma <-> YARA-L drafts on ``run_id`` could not.
   ``generate_yara_l`` now accepts a keyword-only ``run_id``;
   the engine passes the real value.

2. **SPL was a metadata echo, not a search.** ``render_spl``
   emitted ``| makeresults | eval ...`` only, which round-tripped
   the run metadata but never touched any data source. The
   upgraded renderer uses the Sigma logsource block to map onto
   common Splunk sourcetypes (``WinEventLog:Security`` /
   ``Sysmon`` / ``linux_audit`` / ``stream:dns`` / ...), surfaces
   the Sigma selection clause as ``where`` filters, attributes
   the search to the run via ``eval``, and aggregates with
   ``stats``. A leading multi-line backtick comment block makes
   the draft status explicit so the operator knows to refine
   ``index=`` / ``sourcetype=`` before deploying.

Pinned invariants:

- YARA-L ``meta.run_id`` matches the engine's run id.
- SPL output for a hint with a logsource block is **not** the
  legacy ``| makeresults | eval ...`` shape.
- SPL output carries the ``DRAFT detection search`` header so
  the dashboard / docs cannot oversell maturity.
- SPL output for a hint **without** a logsource block falls
  back to the legacy ``| makeresults | eval ...`` shape so
  existing tooling that consumes the metadata-echo format keeps
  working — but the draft header still surfaces.
- The legacy field eval contract (``risk_score=...`` /
  ``risk_severity=...`` / ``legacy_subtype=...``) is preserved
  in both shapes so detection-enrichment tests keep passing.
- The ``write_detection_artifacts`` engine threads the same
  ``run_id`` into both the Sigma path AND the YARA-L path so
  the two stay in lockstep.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.core.detections import write_detection_artifacts
from src.core.detections.spl import render_spl
from src.core.detections.yara_l import build_yara_l_rule, generate_yara_l
from src.core.models import ModuleResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result_with_logsource() -> ModuleResult:
    return ModuleResult(
        status="success",
        module="execution",
        message="Loader executed.",
        techniques=["T1059"],
        artifacts={},
        detection_hints={
            "title": "BlueFire execution",
            "mitre_technique": "T1059",
            "logsource": {"product": "windows", "category": "process_creation"},
            "detection": {
                "selection": {
                    "Image|endswith": "powershell.exe",
                    "CommandLine|contains": "-EncodedCommand",
                },
                "condition": "selection",
            },
        },
        telemetry=[],
    )


def _result_without_logsource() -> ModuleResult:
    return ModuleResult(
        status="success",
        module="legacy_capability_summary",
        message="Pack summary captured.",
        techniques=["T0000"],
        artifacts={},
        detection_hints={
            "title": "Legacy summary",
            # No logsource block; no detection.selection. The SPL
            # generator must fall back to the metadata-echo shape
            # so existing tooling keeps working.
        },
        telemetry=[],
    )


# ---------------------------------------------------------------------------
# 1. YARA-L run_id: real value lands in meta.run_id
# ---------------------------------------------------------------------------


def test_yara_l_meta_run_id_uses_real_run_id() -> None:
    """``generate_yara_l`` must thread the engine's run id, not "manual"."""
    yaral = generate_yara_l(
        "execution",
        "T1059",
        {"mitre_technique_id": "T1059"},
        run_id="run-2026-05-07-real",
    )
    assert 'run_id = "run-2026-05-07-real"' in yaral
    assert 'run_id = "manual"' not in yaral


def test_yara_l_engine_threads_run_id_through(tmp_path: Path) -> None:
    """End-to-end: engine call sites pass real run id, not ``"manual"``."""
    artifacts = write_detection_artifacts(
        tmp_path,
        "run-engine-2026-05-07",
        {"execution": _result_with_logsource()},
    )
    yaral_path = Path(artifacts["yara_l"][0])
    body = yaral_path.read_text(encoding="utf-8")
    assert 'run_id = "run-engine-2026-05-07"' in body
    # The historical "manual" placeholder must not survive a
    # real engine invocation.
    assert 'run_id = "manual"' not in body


def test_yara_l_unspecified_run_id_falls_back_to_manual() -> None:
    """Out-of-tree callers that omit ``run_id`` keep the historical default."""
    yaral = generate_yara_l(
        "execution",
        "T1059",
        {"mitre_technique_id": "T1059"},
    )
    # Backwards-compat: callers that don't pass run_id still see
    # the historical ``"manual"`` value rather than KeyError.
    assert 'run_id = "manual"' in yaral


def test_yara_l_run_id_matches_sigma_run_id(tmp_path: Path) -> None:
    """Sigma + YARA-L emitted in the same engine call carry the same run id.

    The original bug shipped because the two paths drifted: Sigma
    pulled real run id from the orchestrator, YARA-L hardcoded
    ``"manual"``. Pin the lockstep contract so a future refactor
    can't reintroduce the drift.
    """
    artifacts = write_detection_artifacts(
        tmp_path,
        "run-lockstep-2026-05-07",
        {"execution": _result_with_logsource()},
    )
    sigma_text = Path(artifacts["sigma"][0]).read_text(encoding="utf-8")
    yaral_text = Path(artifacts["yara_l"][0]).read_text(encoding="utf-8")
    # Sigma rule id encodes the run id (sanitised); the YARA-L
    # meta block should carry the same string verbatim.
    assert "run-lockstep-2026-05-07" in sigma_text
    assert 'run_id = "run-lockstep-2026-05-07"' in yaral_text


# ---------------------------------------------------------------------------
# 2. SPL upgrade: real-feeling search, draft header, honest framing
# ---------------------------------------------------------------------------


def test_spl_with_logsource_uses_real_sourcetype_hint() -> None:
    """Sigma logsource(windows/process_creation) maps to WinEventLog:Security + Sysmon."""
    spl = render_spl(_result_with_logsource(), "run-spl-1")
    # Real-feeling: references actual Splunk sourcetypes.
    assert 'sourcetype="WinEventLog:Security"' in spl
    assert 'sourcetype="Sysmon"' in spl
    # The new shape also references EventCode (4688/1 for process_creation).
    assert "EventCode=4688" in spl or "EventCode=1" in spl
    # Crucially, it is NOT just the legacy metadata-echo shape.
    assert not spl.lstrip("` -").lstrip().startswith("| makeresults")


def test_spl_carries_draft_header_so_dashboard_cannot_oversell() -> None:
    """Every generated SPL flags itself as DRAFT in a comment header."""
    spl = render_spl(_result_with_logsource(), "run-spl-2")
    assert "DRAFT detection search" in spl
    assert "Adjust index=" in spl
    assert "sourcetype=" in spl


def test_spl_renders_selection_clauses_from_sigma_detection_block() -> None:
    """Sigma selection becomes SPL ``where`` clauses against CIM field names.

    Previously the renderer emitted the raw Sigma field name as the
    SPL ``where`` field (``| where Image="*powershell.exe"``) which
    fired only on raw Sysmon EventCode=1 events. After PR #143 the
    renderer translates Sigma fields onto Splunk CIM canonical names
    (``Image|endswith`` -> ``process_path``, ``CommandLine|contains``
    -> ``process``) so the same generated rule fires across every
    CIM-normalised Endpoint sourcetype (Sysmon-after-CIM-extractions,
    CrowdStrike Falcon, Carbon Black, defender-for-endpoint, etc.).
    """
    spl = render_spl(_result_with_logsource(), "run-spl-3")
    # Sigma ``Image|endswith`` -> CIM ``process_path``, leading wildcard preserved.
    assert '| where process_path="*powershell.exe"' in spl
    # Sigma ``CommandLine|contains`` -> CIM ``process``, both wildcards preserved.
    assert '| where process="*-EncodedCommand*"' in spl
    # The raw Sigma field names must NOT survive the CIM translation —
    # otherwise CIM-only environments (Splunk ES) would not match the rule.
    assert '| where Image=' not in spl
    assert '| where CommandLine=' not in spl


def test_spl_emits_run_attribution_evals() -> None:
    """``eval run_id="..." module="..." technique="..."`` survives the upgrade."""
    spl = render_spl(_result_with_logsource(), "run-spl-4")
    assert 'run_id="run-spl-4"' in spl
    assert 'module="execution"' in spl
    assert 'technique="T1059"' in spl


def test_spl_aggregates_with_stats_clause() -> None:
    """The upgraded SPL ends in a ``stats count by ...`` aggregation."""
    spl = render_spl(_result_with_logsource(), "run-spl-5")
    assert "| stats count by" in spl
    assert "run_id, module, technique" in spl


def test_spl_without_logsource_falls_back_to_metadata_echo() -> None:
    """No logsource + no selection => legacy ``| makeresults | eval`` shape.

    Existing tooling that consumed the metadata-echo SPL keeps
    working. The leading draft header still surfaces so even the
    fallback shape is honest about its draft status.
    """
    spl = render_spl(_result_without_logsource(), "run-spl-fallback")
    assert "| makeresults | eval" in spl
    assert "DRAFT detection search" in spl


def test_spl_legacy_field_eval_contract_preserved(tmp_path: Path) -> None:
    """``risk_score=`` / ``risk_severity=`` / ``legacy_subtype=`` still surface.

    The detection-risk-enrichment test already pins this contract;
    duplicate it here so a future refactor of either generator
    cannot break it from one direction without breaking the other.
    """
    result = ModuleResult(
        status="success",
        module="legacy_protocol_research",
        message="Legacy protocol prepared.",
        techniques=["T1071.004"],
        artifacts={
            "legacy": {
                "pack": "c2_pack",
                "capability": "dns_tunneling",
                "mode": "emulate",
                "payload": {
                    "protocol": "dns_tunneling",
                    "transport": "dns",
                    "endpoint": "exfil.example.lab",
                    "legacy_subtype": "dns_tunneling",
                },
            }
        },
        detection_hints={
            "title": "Legacy protocol DNS",
            "mitre_technique": "T1071.004",
            "detection": {
                "selection": {
                    "network.transport": "dns",
                    "network.endpoint|contains": "example.lab",
                },
                "condition": "selection",
            },
        },
        telemetry=[],
    )
    artifacts = write_detection_artifacts(
        tmp_path, "run-legacy-1", {"legacy_protocol_research": result}
    )
    spl = Path(artifacts["spl"][0]).read_text(encoding="utf-8")
    assert 'risk_score="' in spl
    assert 'risk_severity="' in spl
    assert 'legacy_subtype="' in spl


# ---------------------------------------------------------------------------
# 3. Logsource->SPL mapping coverage
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "product,category,expected_substr",
    [
        ("windows", "process_creation", 'sourcetype="WinEventLog:Security"'),
        ("linux", "process_creation", 'sourcetype="linux_audit"'),
        ("windows", "network_connection", 'sourcetype="Sysmon"'),
        ("windows", "dns_query", "EventCode=22"),
        ("dns", "dns_query", 'sourcetype="stream:dns"'),
        ("windows", "file_event", "EventCode=11"),
        ("windows", "registry_event", "EventCode=12"),
    ],
)
def test_spl_logsource_mapping_covers_common_sigma_categories(
    product: str, category: str, expected_substr: str
) -> None:
    result = ModuleResult(
        status="success",
        module="m",
        message="",
        techniques=["T1000"],
        artifacts={},
        detection_hints={
            "logsource": {"product": product, "category": category},
        },
        telemetry=[],
    )
    spl = render_spl(result, "run-mapping")
    assert expected_substr in spl, (
        f"expected {expected_substr!r} in SPL for {product}/{category}, "
        f"got:\n{spl}"
    )


# ---------------------------------------------------------------------------
# 4. Build-level YARA-L invariant (used by tests outside this module)
# ---------------------------------------------------------------------------


def test_build_yara_l_rule_signature_unchanged() -> None:
    """``build_yara_l_rule`` is the canonical entry point; signature stable."""
    rule = build_yara_l_rule(
        "run-canonical",
        "execution",
        {"mitre_technique_id": "T1059", "risk_severity": "high", "risk_score": 80},
    )
    assert "run_id = \"run-canonical\"" in rule
    assert "technique = \"T1059\"" in rule
    assert "risk_severity = \"high\"" in rule
    assert "risk_score = \"80\"" in rule
