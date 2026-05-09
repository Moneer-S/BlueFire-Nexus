"""AI copilot orchestration for planning, narration, and detection suggestions.

Phase 3: every artifact written by the copilot now carries a
machine-readable metadata header (provider / model / generated_at /
network_disabled / fallback_used) and the dict returned by
:meth:`AICopilot.plan` / :meth:`AICopilot.narrate` /
:meth:`AICopilot.suggest_detections` includes the same metadata so
downstream report renderers and operators can attribute output and
spot degraded runs without re-parsing the file.

Phase 4: prompt shaping. ``narrate`` and ``suggest_detections``
optionally accept a ``run_summary`` mapping built by
:func:`summarise_run_state` (or by the orchestrator) so the prompt
carries scenario name, module-level status counts, technique
totals, and detection-hint coverage. The summary is intentionally
compact and field-typed (no free-form module ``message`` text) so
it cannot be used as a prompt-injection vector by an upstream
module's output. The same summary lands in the artifact metadata
header so operators can see the run context at a glance.

Fallback wiring: when ``modules.ai.fallback_provider`` is set to a
known canonical name different from the primary provider, the
copilot wraps the primary in a :class:`FallbackChainProvider` so a
primary failure transparently retries via the fallback. The
fallback marker (``fallback_used: true``) appears in both the file
header and the returned dict, plus the original primary error is
recorded in the response metadata.

No AI output ever triggers execution. Artifacts are text-only and
read by humans / report renderers; nothing in this module evals,
imports, or otherwise activates content produced by a provider.
"""

from __future__ import annotations

import copy
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, Optional

from ..configuration import get_ai_config
from .fallback import FallbackChainProvider
from .providers import LLMProvider, ProviderFactory
from .rag import RAGIndex
from .types import ProviderResponse


def _build_provider_chain(config: Mapping[str, Any]) -> LLMProvider:
    """Build the primary provider, optionally wrapped with a fallback chain.

    Fallback is opt-in. It only fires when ``fallback_provider`` is
    set to a known canonical name AND the canonicalised name
    differs from the canonicalised primary provider (so an alias
    pair like ``provider: claude`` + ``fallback_provider:
    anthropic`` is correctly recognised as a no-op rather than
    wrapping a single backend in a self-fallback chain).

    The fallback provider is rebuilt by re-running
    :func:`get_ai_config` against a copy of the FULL config with
    ``modules.ai.provider`` swapped to the fallback name. This
    triggers the ``ai_providers.<fallback>`` block merge so the
    fallback gets its own ``api_base``, ``model``, ``api_key_env``,
    and ``provider_settings`` instead of inheriting the primary's.

    Closes Codex P1 from PR #55: previous version cloned ``ai_cfg``
    and only changed ``provider``, so a config like ``provider:
    openai`` + ``fallback_provider: anthropic`` left the fallback
    instance configured with OpenAI's ``api_base`` / ``model`` /
    ``api_key`` instead of Anthropic's.

    Closes Codex P2 from PR #55: the no-op guard now compares
    canonical names, so alias pairs do not wrap an unnecessary
    fallback chain that would mark every degraded run with
    ``fallback_used`` for what is actually the same backend.
    """
    primary_ai_cfg = get_ai_config(config)
    primary = ProviderFactory.from_ai_config(primary_ai_cfg)

    fallback_name = str(primary_ai_cfg.get("fallback_provider") or "").strip()
    if not fallback_name:
        return primary

    primary_canonical = ProviderFactory.normalise_name(primary_ai_cfg.get("provider"))
    fallback_canonical = ProviderFactory.normalise_name(fallback_name)
    if not fallback_canonical or fallback_canonical == primary_canonical:
        return primary

    # Re-resolve the fallback through get_ai_config so the
    # `ai_providers.<fallback>` block is merged correctly. Working
    # from a deep copy of the original config keeps the primary's
    # resolved view untouched.
    #
    # Clear the primary-specific keys (`model` / `api_base` /
    # `api_key_env`) on the rebuilt `modules.ai`. Otherwise
    # `get_ai_config` would treat the primary's values as already-
    # set and the `ai_providers.<fallback>` block would not be able
    # to populate them — that was the original Codex P1 finding
    # (PR #55): the fallback inherited the primary's endpoint /
    # model / key instead of the fallback vendor's own settings.
    base = copy.deepcopy(dict(config) if isinstance(config, Mapping) else {})
    modules = base.setdefault("modules", {})
    if not isinstance(modules, dict):
        modules = {}
        base["modules"] = modules
    ai_section = modules.setdefault("ai", {})
    if not isinstance(ai_section, dict):
        ai_section = {}
        modules["ai"] = ai_section
    ai_section["provider"] = fallback_canonical
    # Drop primary-vendor identifiers so the fallback's
    # `ai_providers.<fallback>` block populates them.
    for primary_specific_key in ("model", "api_base", "api_key_env"):
        ai_section[primary_specific_key] = ""
    # The fallback should not itself trigger another fallback —
    # clear the field on the rebuilt config so a misconfigured
    # cycle (fallback_provider pointing at a chain) cannot recurse.
    ai_section["fallback_provider"] = ""

    fallback_ai_cfg = get_ai_config(base)
    fallback = ProviderFactory.from_ai_config(fallback_ai_cfg)
    return FallbackChainProvider(primary=primary, fallback=fallback)


def _utc_now_isoformat() -> str:
    """Return the current UTC timestamp in ``YYYY-MM-DDTHH:MM:SSZ`` form.

    Centralised so tests can monkey-patch a deterministic value
    without reaching into ``datetime`` directly.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Run-state summary: builds a compact prompt-safe view of the run
# ---------------------------------------------------------------------------


# Header keys derived from a run summary that we surface in the
# artifact frontmatter. Listed explicitly to keep the YAML header
# stable and to avoid leaking arbitrary mapping keys into the file.
#
# ``scenario_objective`` is the YAML scenario's narrative summary
# (PR #118 polish; PR #119 plumbed it through the manifest). The
# offline copilot's narrative artifact reads it from the run
# summary so the rendered prose is grounded in the chain story
# rather than just step-status counts. Empty when the scenario
# has no objective, so the artifact header degrades cleanly for
# legacy / single-module runs.
_RUN_SUMMARY_HEADER_KEYS: tuple[str, ...] = (
    "scenario_name",
    "scenario_objective",
    "run_id",
    "module_count",
    "successful_steps",
    "failed_steps",
    "techniques_total",
    "detection_hint_count",
)


def summarise_run_state(
    *,
    run_id: str,
    scenario_name: Optional[str] = None,
    scenario_objective: Optional[str] = None,
    module_results: Optional[Mapping[str, Any]] = None,
    detection_summary: Optional[Mapping[str, Any]] = None,
    step_objectives: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Build a compact, prompt-safe summary of a completed run.

    The orchestrator calls this with the post-run ``module_results``
    dict (a mapping of step-key -> :class:`ModuleResult`-like object,
    which has ``status`` / ``techniques`` / ``detection_hints``
    attributes) and the rendered ``detection_summary`` mapping so the
    copilot can shape better prompts than "run_id=<x>".

    The optional ``scenario_objective`` (PR #118 / #119 / #120
    chain) is the scenario YAML's narrative summary — the same
    text the dashboard surfaces in its header and the markdown
    report renders as the "Scenario objective" section. Including
    it here grounds the offline copilot's narrative artifact in
    the chain story rather than just step-status counts. The
    summariser stores it stripped (no leading/trailing whitespace)
    and capped at 1000 chars to keep prompt budget bounded; longer
    objectives suffix-truncate with an ellipsis so the model still
    sees "this is more than what fits".

    The optional ``step_objectives`` (PR #144) maps step-key
    (``"<module>:<step_id>"``) to the per-step ``objective:`` text
    declared in the scenario YAML. Each entry surfaces inline in the
    per-step ``module_statuses`` block so the offline copilot's
    template can build a chain narrative grounded in the operator's
    "why" for each step, not just status counts. Same trusted-field
    treatment as ``scenario_objective``.

    Intentional restrictions:

    - **No free-form ``message`` text** — only field-typed status
      counts and technique IDs land in the summary. A compromised /
      malicious upstream module cannot inject prompt content via
      its ``ModuleResult.message`` because that field is not read.
    - **Counts, not contents** — detection-hint *count* per step
      is included; the hint *content* is not. The point is to give
      the copilot context, not to forward arbitrary upstream text.
    - **Deterministic shape** — every key listed in
      ``_RUN_SUMMARY_HEADER_KEYS`` is always present so artifact
      metadata headers stay schema-stable.
    - **Scenario objective is a TRUSTED field** — it comes from the
      scenario YAML the operator authored, not from a module's
      runtime output, so the prompt-injection guard that excludes
      ``ModuleResult.message`` does not apply to it. The same
      reasoning extends to per-step objectives.
    """
    statuses: Counter[str] = Counter()
    techniques: list[str] = []
    detection_hint_count = 0
    module_status_pairs: list[tuple[str, str]] = []

    for step_key, result in (module_results or {}).items():
        status = str(getattr(result, "status", "unknown") or "unknown")
        statuses[status] += 1
        module_status_pairs.append((str(step_key), status))
        for technique in (getattr(result, "techniques", []) or []):
            if technique:
                techniques.append(str(technique))
        hints = getattr(result, "detection_hints", None) or {}
        if isinstance(hints, Mapping):
            detection_hint_count += sum(
                len(value) if isinstance(value, (list, tuple, set)) else 1
                for value in hints.values()
            )

    if detection_summary:
        # ``detection_summary`` is a dict[step_key, dict[detection_kind, path]].
        # Count distinct detection drafts across every step + kind pair so
        # the summary reflects actual report-rendered coverage, not just
        # the largest single-step entry. Use ``max(running_total,
        # cumulative_entries)`` against the running ``detection_hint_count``
        # because either source can underrepresent the truth: modules can
        # emit hints that the report-renderer filters, and the
        # report-renderer can include drafts the modules did not surface
        # via ``detection_hints``. Taking the larger of the two cumulative
        # sums avoids both kinds of undercount.
        cumulative_entries = sum(
            len(entry)
            for entry in detection_summary.values()
            if isinstance(entry, Mapping)
        )
        detection_hint_count = max(detection_hint_count, cumulative_entries)

    successful_steps = statuses.get("success", 0)
    failed_steps = sum(
        statuses.get(state, 0)
        for state in ("failure", "blocked", "error", "partial_success")
    )

    # Per-step objective lookup table — keys match the ``step``
    # values in ``module_status_pairs`` so each entry can attach its
    # operator-authored "why" line. Empty values are dropped so the
    # rendered prompt block stays compact.
    #
    # Embedded newlines (from YAML literal blocks like ``objective: |``
    # with multi-paragraph text) MUST be collapsed before they reach
    # the prompt formatter — otherwise the multi-line value writes
    # continuation lines without the leading indent that
    # ``_parse_run_summary_block`` requires, the parser exits the
    # ``[run summary]`` block at the first non-indented line, and
    # later steps silently disappear from ``module_statuses``. Same
    # collapse the scenario-level objective uses; capped at 240 chars
    # with ellipsis so a long literal block doesn't dominate the
    # prompt budget.
    objective_by_step: Dict[str, str] = {}
    if step_objectives:
        for raw_step_key, raw_text in step_objectives.items():
            collapsed = " ".join(str(raw_text or "").split())
            if collapsed:
                objective_by_step[str(raw_step_key)] = (
                    collapsed
                    if len(collapsed) <= 240
                    else collapsed[:239].rstrip() + "…"
                )

    module_status_entries: list[Dict[str, str]] = []
    for step, status in module_status_pairs:
        entry: Dict[str, str] = {"step": step, "status": status}
        objective_text = objective_by_step.get(step)
        if objective_text:
            entry["objective"] = objective_text
        module_status_entries.append(entry)

    return {
        "scenario_name": str(scenario_name) if scenario_name else "",
        "scenario_objective": _normalise_objective(scenario_objective),
        "run_id": str(run_id),
        "module_count": len(module_status_pairs),
        "module_statuses": module_status_entries,
        "successful_steps": successful_steps,
        "failed_steps": failed_steps,
        "techniques_total": len(techniques),
        # Sorted, de-duplicated, capped so a noisy step cannot dominate
        # the prompt or the artifact header.
        "techniques": sorted(set(techniques))[:32],
        "detection_hint_count": detection_hint_count,
    }


# Maximum scenario_objective length surfaced to the prompt /
# artifact header. Objective is operator-authored YAML, so this
# is a budget cap, not a security guard. Long objectives
# suffix-truncate with an ellipsis so the prompt sees "more than
# what fits" rather than silently losing the tail.
_MAX_OBJECTIVE_CHARS: int = 1000


def _normalise_objective(scenario_objective: Optional[str]) -> str:
    """Render the scenario objective for prompt / header inclusion.

    Mirrors the markdown report's paragraph normalisation: collapses
    multi-line YAML literal blocks into single-line prose by
    replacing newlines with spaces and squeezing repeated
    whitespace, then strips leading/trailing whitespace and caps
    the length at ``_MAX_OBJECTIVE_CHARS`` with an ellipsis suffix.
    """
    if not scenario_objective:
        return ""
    raw = str(scenario_objective).strip()
    if not raw:
        return ""
    # Collapse all whitespace runs (incl. newlines) into single
    # spaces so the rendered single-line prose flows.
    collapsed = " ".join(raw.split())
    if len(collapsed) <= _MAX_OBJECTIVE_CHARS:
        return collapsed
    return collapsed[: _MAX_OBJECTIVE_CHARS - 1].rstrip() + "…"


def _format_run_summary_for_prompt(run_summary: Mapping[str, Any]) -> str:
    """Render the summary as a compact text block for prompt inclusion.

    Field-by-field rendering with stable line ordering so the
    template provider's deterministic output stays stable across
    runs with the same summary. The block stays small (counts, not
    full content) so token budget is preserved for the actual
    prompt.
    """
    lines: list[str] = ["[run summary]"]
    scenario_name = run_summary.get("scenario_name") or ""
    if scenario_name:
        lines.append(f"  scenario: {scenario_name}")
    scenario_objective = run_summary.get("scenario_objective") or ""
    if scenario_objective:
        # The objective is single-line by construction (the
        # summariser collapses multi-paragraph YAML literals into
        # one line), so it lands cleanly under the indented summary
        # block. The template provider's ``narrate`` intent reads
        # this line to ground the rendered narrative in the chain
        # story.
        lines.append(f"  objective: {scenario_objective}")
    run_id = run_summary.get("run_id") or ""
    if run_id:
        lines.append(f"  run_id: {run_id}")
    module_count = run_summary.get("module_count")
    if isinstance(module_count, int):
        lines.append(f"  module_count: {module_count}")
    successful_steps = run_summary.get("successful_steps")
    failed_steps = run_summary.get("failed_steps")
    if isinstance(successful_steps, int) or isinstance(failed_steps, int):
        lines.append(
            f"  steps: {successful_steps or 0} success / {failed_steps or 0} non-success"
        )
    techniques_total = run_summary.get("techniques_total")
    if isinstance(techniques_total, int):
        lines.append(f"  techniques_observed: {techniques_total}")
    techniques = run_summary.get("techniques") or []
    if isinstance(techniques, Iterable):
        listed = ", ".join(str(t) for t in techniques if t)
        if listed:
            lines.append(f"  technique_ids: {listed}")
    detection_count = run_summary.get("detection_hint_count")
    if isinstance(detection_count, int):
        lines.append(f"  detection_hints: {detection_count}")
    # Per-step status block — capped so a long scenario cannot
    # dominate the prompt. The deterministic offline template
    # parses this block to render a plain-English timeline replay
    # without needing access to the structured summary directly.
    module_statuses = run_summary.get("module_statuses") or []
    if isinstance(module_statuses, list) and module_statuses:
        capped = module_statuses[:16]
        lines.append("  module_statuses:")
        for entry in capped:
            if not isinstance(entry, Mapping):
                continue
            step = str(entry.get("step", "")).splitlines()[0][:120]
            status = str(entry.get("status", "")).splitlines()[0][:32]
            if not step:
                continue
            lines.append(f"    - {step}: {status}")
            # Per-step objective (PR #144) — surfaced inline as a
            # sub-bullet so the offline template can pick up the
            # operator's "why" without changing the existing parsing
            # contract for status entries. One-line, single-paragraph
            # form because the summariser already capped width.
            objective = str(entry.get("objective") or "").strip()
            if objective:
                lines.append(f"      objective: {objective}")
        if len(module_statuses) > 16:
            lines.append(
                f"    ... (+{len(module_statuses) - 16} more steps not shown)"
            )
    return "\n".join(lines)


def _format_artifact_header(
    response: ProviderResponse,
    *,
    generated_at: str,
    run_summary: Optional[Mapping[str, Any]] = None,
) -> str:
    """Build the YAML-front-matter-style metadata header.

    Format is intentionally readable both as Markdown frontmatter
    and as a plain-text preamble so the same header works for
    ``.md`` and ``.txt`` artifacts without a per-format renderer.

    When ``run_summary`` is supplied, a fixed subset of summary
    keys (``_RUN_SUMMARY_HEADER_KEYS``) flows into the header so
    operators can see scenario context at a glance without opening
    ``report.md`` separately. The schema stays stable because only
    the listed keys are emitted; arbitrary summary keys are
    ignored.
    """
    lines = [
        "---",
        f"provider: {response.provider}",
        f"model: {response.model}",
        f"generated_at: {generated_at}",
        f"network_disabled: {str(response.network_disabled).lower()}",
        f"fallback_used: {str(response.fallback_used).lower()}",
    ]
    if response.fallback_used:
        primary_name = response.metadata.get("primary_provider")
        if primary_name:
            lines.append(f"primary_provider: {primary_name}")
        primary_error = response.metadata.get("primary_error")
        if primary_error:
            # Single-line error blurb so the header stays parseable.
            lines.append(f"primary_error: {str(primary_error).splitlines()[0][:200]}")
    if response.error:
        lines.append(f"error: {str(response.error).splitlines()[0][:200]}")
    if response.finish_reason:
        lines.append(f"finish_reason: {response.finish_reason}")
    if isinstance(run_summary, Mapping):
        for key in _RUN_SUMMARY_HEADER_KEYS:
            value = run_summary.get(key)
            if value is None or value == "":
                continue
            # Strip newlines so a string value cannot break out of
            # the YAML front matter.
            rendered = str(value).splitlines()[0][:200] if isinstance(value, str) else value
            lines.append(f"{key}: {rendered}")
    lines.append("---")
    lines.append("")  # blank line separating header from body
    return "\n".join(lines)


def _build_artifact_dict(
    *,
    output_path: Path,
    response: ProviderResponse,
    body: str,
    generated_at: str,
    run_summary: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Return the dict shape published by every public copilot method.

    Keeps the legacy ``path`` / ``content`` keys (back-compat with
    callers that only consume those) and adds the per-response
    metadata. ``content`` is the BODY actually written to disk
    (header excluded, but placeholder included when the provider
    returned empty text), so API consumers see exactly what the
    file contains without re-reading it.

    When ``run_summary`` is supplied, a copy is exposed under the
    ``run_summary`` key so callers that consume the dict directly
    (e.g. report renderers) can attribute output to scenario
    context without re-reading the file. The copy is defensive so
    downstream mutations cannot leak back into the orchestrator's
    summary.

    Closes Codex P2 from PR #55: previous version returned
    ``content=response.text`` (empty on failure) while the file
    contained the operator-facing placeholder, hiding failure
    details from callers that did not re-open the file.
    """
    payload: Dict[str, Any] = {
        "path": str(output_path),
        "content": body,
        "provider": response.provider,
        "model": response.model,
        "generated_at": generated_at,
        "network_disabled": response.network_disabled,
        "fallback_used": response.fallback_used,
        "error": response.error,
    }
    if isinstance(run_summary, Mapping):
        # Defensive deep-copy: the orchestrator's summary dict is
        # mutable and may be re-used across calls. Copying keeps the
        # returned payload independent of subsequent mutations.
        payload["run_summary"] = copy.deepcopy(dict(run_summary))
    return payload


class AICopilot:
    """Config-driven AI copilot with deterministic keyless fallback."""

    def __init__(self, config: Dict[str, Any], run_dir: Path) -> None:
        self.config = config
        self.run_dir = run_dir
        # Route through the central helper so the copilot picks up the
        # documented AI-config shape (api_key_env / timeout / max_tokens
        # / provider_settings / temperature / fallback_provider) and
        # the `ai_providers.<name>` block flow-through without re-
        # implementing the merge here.
        ai_cfg = get_ai_config(config)
        self.ai_config: Dict[str, Any] = dict(ai_cfg)
        self.enabled = bool(ai_cfg.get("enabled", False))
        # Pass the FULL config (not just ai_cfg) so the fallback
        # branch can re-resolve its own ai_providers.<fallback>
        # block. See _build_provider_chain for details.
        self.provider: LLMProvider = _build_provider_chain(config)

        project_root = Path.cwd()
        self.rag = RAGIndex(
            [
                project_root / "README.md",
                project_root / "docs" / "ARCHITECTURE.md",
                run_dir / "report.md",
            ]
        )

    def _ask(self, prompt: str, extra_context: Optional[list[str]] = None) -> ProviderResponse:
        """Issue a single generation request and return the rich response.

        Returns the full :class:`ProviderResponse` (not just text) so
        callers can attribute output, render the metadata header, and
        spot fallback paths without re-querying the provider.
        """
        context = self.rag.search(prompt, limit=5)
        if extra_context:
            context.extend(extra_context)
        return self.provider.generate(prompt, context=context)

    def _write_artifact(
        self,
        response: ProviderResponse,
        output_path: Path,
        *,
        run_summary: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        generated_at = _utc_now_isoformat()
        header = _format_artifact_header(
            response, generated_at=generated_at, run_summary=run_summary
        )
        # Body is the model text. When the provider returned an error
        # without text (e.g. transport failure with no fallback),
        # surface a clear placeholder so the artifact is still
        # informative for the operator.
        body = response.text or (
            "[no content returned by provider; see header for details]"
        )
        output_path.write_text(header + body, encoding="utf-8")
        # Pass `body` so the returned dict's `content` matches what is
        # actually on disk (placeholder included on error paths).
        return _build_artifact_dict(
            output_path=output_path,
            response=response,
            body=body,
            generated_at=generated_at,
            run_summary=run_summary,
        )

    def _maybe_summary_block(
        self, run_summary: Optional[Mapping[str, Any]]
    ) -> Optional[str]:
        """Return the formatted summary block when one is supplied.

        Centralised so every public method shapes prompts the same
        way: ``None`` means "no extra context"; a non-empty mapping
        means "render and append".
        """
        if not isinstance(run_summary, Mapping) or not run_summary:
            return None
        return _format_run_summary_for_prompt(run_summary)

    def plan(
        self,
        goal: str,
        *,
        run_summary: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate scenario YAML from natural language goal.

        ``run_summary`` is optional; when set it lands both in the
        prompt body and the artifact metadata header so the
        generated plan can reference (or contrast against) the
        currently-observed state of the project.
        """
        summary_block = self._maybe_summary_block(run_summary)
        prompt_parts = [
            "Generate a concise BlueFire scenario YAML with fields: "
            "id, objective, mitre, steps[].",
            f"Goal: {goal}",
        ]
        if summary_block:
            prompt_parts.append(summary_block)
        prompt = "\n".join(prompt_parts)
        response = self._ask(prompt)
        output_path = self.run_dir / "copilot_plan.txt"
        return self._write_artifact(response, output_path, run_summary=run_summary)

    def narrate(
        self,
        run_id: str,
        *,
        run_summary: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate SOC-style run narrative.

        ``run_summary`` is optional but recommended; the orchestrator
        in ``bluefire_nexus`` builds and passes it for every scenario
        run so the narrative reflects the actual modules executed,
        techniques observed, and detection coverage. Call sites that
        do not have a summary in hand (e.g. ad-hoc tooling) can
        continue to call ``narrate(run_id)`` and the prompt falls
        back to the legacy minimal form.
        """
        summary_block = self._maybe_summary_block(run_summary)
        prompt_parts = [
            "Write a SOC incident narrative with timeline, findings, and recommendations "
            f"for run_id={run_id}."
        ]
        if summary_block:
            prompt_parts.append(summary_block)
        prompt = "\n".join(prompt_parts)
        response = self._ask(prompt)
        output_path = self.run_dir / "copilot_narrative.md"
        return self._write_artifact(response, output_path, run_summary=run_summary)

    def suggest_detections(
        self,
        run_id: str,
        metadata: Mapping[str, Any] | None = None,
        *,
        run_summary: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate detection strategy summary for current run."""
        summary_block = self._maybe_summary_block(run_summary)
        prompt_parts = [
            "Based on ATT&CK and emitted telemetry, provide concise detection suggestions "
            f"for run_id={run_id}, including Sigma, YARA-L, and SPL guidance."
        ]
        if summary_block:
            prompt_parts.append(summary_block)
        prompt = "\n".join(prompt_parts)
        response = self._ask(prompt, [f"metadata={dict(metadata or {})}"])
        output_path = self.run_dir / "copilot_detections.md"
        return self._write_artifact(response, output_path, run_summary=run_summary)
