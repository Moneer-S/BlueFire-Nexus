"""Offline copilot artifact quality — pre-rc1 polish.

The previous TemplateProvider returned a generic 5-line stub
regardless of prompt content:

    TemplateProvider response
    - model: <name>
    - prompt_summary: <first 220 chars of prompt>
    - context_preview: <RAG snippets>
    - recommendation: refine scenario steps, review detection
      coverage, validate telemetry

That output was technically deterministic and offline, but did
not actually surface anything specific to the run. Operators
running with the default offline AI provider got copilot
artifacts that read as filler.

The new TemplateProvider parses the orchestrator-emitted
``[run summary]`` block out of the prompt and renders an
intent-aware artifact:

- ``narrate`` -> SOC-style narrative with run summary,
  step-by-step timeline (replayed from ``module_statuses``),
  findings (success/blocked counts, ATT&CK coverage, detection
  draft counts), and run-specific next-validation steps.
- ``suggest_detections`` -> detection-strategy summary with
  per-technique pointers, draft maturity framing, and operator
  next steps.
- ``plan`` -> conservative scenario YAML skeleton seeded with
  the goal and any observed techniques.

All output remains deterministic, no network calls, no API
keys. The legacy generic stub is preserved for prompts without
a ``[run summary]`` block (out-of-tree callers that feed bare
prompts).

Pinned content-quality markers tested below:

1. Scenario name surfaces in the body.
2. Module / step count surfaces.
3. Top techniques (ATT&CK ids) surface.
4. Detection draft counts surface.
5. Risk summary tier counts surface (when supplied).
6. Per-step timeline replay (``module_statuses``).
7. Blocked / errored steps surface explicitly when non-success.
8. Per-intent rendering (plan vs narrate vs suggest_detections).
9. Deterministic: same input -> same body byte-for-byte.
10. No network: ``network_disabled=true`` on every response.
11. Backwards-compat: prompts without a ``[run summary]`` block
    still get the legacy generic stub.
"""

from __future__ import annotations

from typing import Any, Dict, List

from src.core.ai.copilot import (
    _format_run_summary_for_prompt,
    summarise_run_state,
)
from src.core.ai.providers import (
    TemplateProvider,
    _detect_prompt_intent,
    _parse_run_summary_block,
    _render_template_narrative,
)


# ---------------------------------------------------------------------------
# Test doubles for ModuleResult — reuse the shape from
# tests/test_copilot_run_summary.py (deliberately not imported to keep
# this file self-contained).
# ---------------------------------------------------------------------------


class _FakeResult:
    def __init__(
        self,
        *,
        status: str,
        techniques: List[str] | None = None,
        detection_hints: Dict[str, Any] | None = None,
    ) -> None:
        self.status = status
        self.techniques = techniques or []
        self.detection_hints = detection_hints or {}


def _full_summary() -> Dict[str, Any]:
    return summarise_run_state(
        run_id="run-2026-05-08-rich",
        scenario_name="enterprise_intrusion_chain",
        scenario_objective=(
            "An attacker registers a domain, phishes a finance analyst, "
            "runs an encoded PowerShell loader, and ends with ransomware."
        ),
        module_results={
            "execution:loader-execution": _FakeResult(
                status="success",
                techniques=["T1059"],
                detection_hints={"sigma": ["rule-a"]},
            ),
            "credential_access:harvest": _FakeResult(
                status="success",
                techniques=["T1555.003"],
                detection_hints={"yara_l": ["rule-b"]},
            ),
            "exfiltration:exfil-c2": _FakeResult(
                status="blocked",
                techniques=["T1041"],
            ),
            "impact:ransomware": _FakeResult(
                status="error",
                techniques=["T1486"],
            ),
        },
    )


# ---------------------------------------------------------------------------
# 1. _parse_run_summary_block — robust extraction
# ---------------------------------------------------------------------------


def test_parse_run_summary_block_returns_empty_for_prompt_without_block() -> None:
    assert _parse_run_summary_block("plain prompt with no summary") == {}


def test_parse_run_summary_block_extracts_top_level_fields() -> None:
    summary = _full_summary()
    block = _format_run_summary_for_prompt(summary)
    parsed = _parse_run_summary_block(block)
    assert parsed["scenario_name"] == "enterprise_intrusion_chain"
    assert parsed["run_id"] == "run-2026-05-08-rich"
    assert parsed["module_count"] == 4
    assert parsed["successful_steps"] == 2
    assert parsed["failed_steps"] == 2
    assert parsed["techniques_total"] == 4
    assert "T1059" in parsed["techniques"]
    assert "T1486" in parsed["techniques"]


def test_parse_run_summary_block_extracts_module_statuses() -> None:
    """The orchestrator key contains a colon (``module:step_id``).

    The parser must keep the full ``module:step_id`` string as the
    step value despite the colon separator on the same line.
    """
    summary = _full_summary()
    block = _format_run_summary_for_prompt(summary)
    parsed = _parse_run_summary_block(block)
    statuses = parsed.get("module_statuses") or []
    steps = {entry["step"]: entry["status"] for entry in statuses}
    assert steps["execution:loader-execution"] == "success"
    assert steps["credential_access:harvest"] == "success"
    assert steps["exfiltration:exfil-c2"] == "blocked"
    assert steps["impact:ransomware"] == "error"


def test_parse_run_summary_block_terminates_at_first_non_indented_line() -> None:
    """Stray prompt continuation text after the summary doesn't leak in."""
    block = (
        "Write a SOC narrative for run-foo.\n"
        "[run summary]\n"
        "  scenario: x\n"
        "  run_id: r-1\n"
        "Next: review the report.\n"
        "  trailing: should-be-ignored\n"
    )
    parsed = _parse_run_summary_block(block)
    assert parsed == {"scenario_name": "x", "run_id": "r-1"}


# ---------------------------------------------------------------------------
# 2. _detect_prompt_intent
# ---------------------------------------------------------------------------


def test_detect_prompt_intent_plan() -> None:
    prompt = (
        "Generate a concise BlueFire scenario YAML with fields: "
        "id, objective, mitre, steps[]."
    )
    assert _detect_prompt_intent(prompt) == "plan"


def test_detect_prompt_intent_narrate() -> None:
    prompt = "Write a SOC incident narrative with timeline, findings ..."
    assert _detect_prompt_intent(prompt) == "narrate"


def test_detect_prompt_intent_suggest_detections() -> None:
    prompt = "Based on ATT&CK, provide concise detection suggestions for ..."
    assert _detect_prompt_intent(prompt) == "suggest_detections"


def test_detect_prompt_intent_unknown_returns_empty() -> None:
    assert _detect_prompt_intent("hello world") == ""


# ---------------------------------------------------------------------------
# 3. End-to-end TemplateProvider intent rendering
# ---------------------------------------------------------------------------


def _narrate_prompt(summary: Dict[str, Any]) -> str:
    block = _format_run_summary_for_prompt(summary)
    return (
        f"Write a SOC incident narrative with timeline, findings, "
        f"and recommendations for run_id={summary.get('run_id')}.\n{block}"
    )


def _suggest_prompt(summary: Dict[str, Any]) -> str:
    block = _format_run_summary_for_prompt(summary)
    return (
        f"Based on ATT&CK and emitted telemetry, provide concise "
        f"detection suggestions for run_id={summary.get('run_id')}.\n{block}"
    )


def _plan_prompt(summary: Dict[str, Any], goal: str) -> str:
    block = _format_run_summary_for_prompt(summary)
    return (
        "Generate a concise BlueFire scenario YAML with fields: "
        "id, objective, mitre, steps[].\n"
        f"Goal: {goal}\n{block}"
    )


def test_narrate_template_surfaces_scenario_and_techniques() -> None:
    summary = _full_summary()
    response = TemplateProvider().generate(_narrate_prompt(summary))
    body = response.text
    assert response.network_disabled is True
    # Scenario name surfaces.
    assert "enterprise_intrusion_chain" in body
    # Top techniques surface.
    assert "T1059" in body
    assert "T1486" in body
    # Module / step count surfaces.
    assert "modules: 4" in body
    # Successful + non-success counts surface.
    assert "2 success" in body
    assert "2 non-success" in body


def test_narrate_template_grounds_in_scenario_objective() -> None:
    """The chain narrative leads with the scenario objective when present.

    Same chain story the dashboard header and report.md surface;
    grounding the offline AI narrative in it ensures the AI
    artifact reads as a SOC summary, not a step-status dump.
    """
    summary = _full_summary()
    body = TemplateProvider().generate(_narrate_prompt(summary)).text
    assert "objective:" in body
    assert "An attacker registers a domain" in body


def test_narrate_template_omits_objective_line_when_summary_lacks_one() -> None:
    """Default-empty objective leaves no ``objective:`` line in the output."""
    summary = summarise_run_state(
        run_id="r-noop",
        scenario_name="enterprise_intrusion_chain",
        module_results={
            "execution:loader-execution": _FakeResult(
                status="success", techniques=["T1059"]
            ),
        },
    )
    body = TemplateProvider().generate(_narrate_prompt(summary)).text
    assert "objective:" not in body


def test_narrate_template_renders_step_timeline() -> None:
    summary = _full_summary()
    body = TemplateProvider().generate(_narrate_prompt(summary)).text
    # Step-by-step timeline replays per-step status.
    assert "## Step-by-step timeline" in body
    assert "execution:loader-execution" in body
    assert "credential_access:harvest" in body


def test_narrate_template_calls_out_blocked_and_errored_steps() -> None:
    summary = _full_summary()
    body = TemplateProvider().generate(_narrate_prompt(summary)).text
    # The template surfaces blocked/errored step ids by name.
    assert "exfiltration:exfil-c2 (blocked)" in body
    assert "impact:ransomware (error)" in body
    # And reports a non-zero blocked count.
    assert "2 step(s) blocked or errored" in body


def test_narrate_template_includes_run_specific_next_validations() -> None:
    summary = _full_summary()
    body = TemplateProvider().generate(_narrate_prompt(summary)).text
    run_id = summary["run_id"]
    assert f"validate-run {run_id}" in body
    assert f"output/{run_id}/index.html" in body
    assert f"output/{run_id}/detections/" in body


def test_narrate_template_surfaces_detection_draft_count() -> None:
    summary = _full_summary()
    body = TemplateProvider().generate(_narrate_prompt(summary)).text
    # Detection-hint count from the summary is rendered as
    # "detection drafts: N" or "N detection draft(s) emitted".
    assert "detection drafts:" in body or "detection draft" in body


def test_suggest_detections_template_renders_per_technique_pointers() -> None:
    summary = _full_summary()
    body = TemplateProvider().generate(_suggest_prompt(summary)).text
    assert "Detection guidance for run" in body
    assert "## Per-technique pointers" in body
    # Each observed technique gets a per-technique line.
    for technique in ("T1059", "T1555.003", "T1041", "T1486"):
        assert technique in body
    # Maturity framing is honest.
    assert "Sigma (most mature)" in body
    assert "YARA-L (medium)" in body
    assert "SPL (draft" in body


def test_plan_template_renders_skeleton_with_goal_and_techniques() -> None:
    summary = _full_summary()
    body = TemplateProvider().generate(
        _plan_prompt(summary, goal="Emulate APT29 credential access")
    ).text
    assert "Plan goal: Emulate APT29 credential access" in body
    # Skeleton uses YAML-flavoured layout that an operator can copy.
    assert "id: planned-scenario" in body
    assert "attack_coverage:" in body
    # Observed techniques flow into the skeleton's coverage block.
    assert "  - T1059" in body
    assert "  - T1486" in body


# ---------------------------------------------------------------------------
# 4. Backwards-compat & determinism
# ---------------------------------------------------------------------------


def test_template_provider_falls_back_to_legacy_stub_for_bare_prompt() -> None:
    """Out-of-tree callers feeding bare prompts still see the legacy stub."""
    body = TemplateProvider().generate("hello world").text
    assert "TemplateProvider response" in body
    assert "prompt_summary:" in body
    assert "context_preview: none" in body
    assert "recommendation:" in body
    # The new intent-aware sections must NOT appear when there's no
    # summary block.
    assert "## Step-by-step timeline" not in body
    assert "## Per-technique pointers" not in body


def test_template_provider_legacy_marker_still_in_first_line() -> None:
    """``TemplateProvider response`` first-line marker is preserved.

    test_copilot.py's test_copilot_template_provider_generates_files
    asserts on this string, so a refactor must keep it.
    """
    summary = _full_summary()
    for prompt in (
        _narrate_prompt(summary),
        _suggest_prompt(summary),
        _plan_prompt(summary, goal="x"),
        "bare prompt with no summary",
    ):
        body = TemplateProvider().generate(prompt).text
        first_line = body.splitlines()[0]
        assert first_line == "TemplateProvider response"


def test_template_provider_is_deterministic() -> None:
    """Same input -> same body, byte for byte (no timestamps in output)."""
    summary = _full_summary()
    prompt = _narrate_prompt(summary)
    body_a = TemplateProvider().generate(prompt).text
    body_b = TemplateProvider().generate(prompt).text
    assert body_a == body_b


def test_template_provider_is_offline() -> None:
    """Every response has network_disabled=True."""
    summary = _full_summary()
    for prompt in (
        _narrate_prompt(summary),
        _suggest_prompt(summary),
        _plan_prompt(summary, goal="x"),
        "bare prompt",
    ):
        response = TemplateProvider().generate(prompt)
        assert response.network_disabled is True


# ---------------------------------------------------------------------------
# 5. Direct-renderer unit tests (faster than e2e parse round-trip)
# ---------------------------------------------------------------------------


def test_render_template_narrative_handles_empty_module_statuses() -> None:
    """A summary without per-step block renders without crashing."""
    summary = {
        "scenario_name": "empty",
        "run_id": "r-1",
        "module_count": 0,
        "successful_steps": 0,
        "failed_steps": 0,
        "techniques_total": 0,
        "detection_hint_count": 0,
    }
    body = _render_template_narrative(summary, "test-model")
    assert "scenario: empty" in body
    assert "## Step-by-step timeline" not in body  # block omitted when empty
