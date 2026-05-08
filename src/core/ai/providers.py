"""AI provider abstractions with deterministic offline fallback.

Phase 1 contract:

- :class:`LLMProvider` Protocol exposes both the legacy
  ``complete(prompt, context) -> str`` text-only path AND the new
  rich ``generate(prompt, *, context, options) -> ProviderResponse``
  path. ``complete()`` is the back-compat shim — every concrete
  provider implements ``generate()`` and the default ``complete()``
  returns ``self.generate(...).text``.
- :class:`ProviderFactory` is the single dispatch point. It honours
  alias normalisation (``google -> gemini``, ``xai -> grok``,
  ``claude -> anthropic``) so docs and config files can use the
  vendor-friendly name and still hit the canonical registry entry.
- :func:`ProviderFactory.register_provider` is the Phase 2 hook —
  real backends (HTTP transport, SDK wrappers) plug in by
  registering a factory function for a canonical name. Phase 1
  ships only the keyless stub for every known remote name; nothing
  in this module makes network calls.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Protocol

from .types import ProviderOptions, ProviderResponse


class LLMProvider(Protocol):
    """Common provider contract for copilot use."""

    name: str
    model: str

    def complete(self, prompt: str, context: list[str] | None = None) -> str:
        """Legacy text-only entry point.

        Concrete providers may implement this directly or as a thin
        wrapper around :meth:`generate` returning ``.text``.
        """
        ...

    def generate(
        self,
        prompt: str,
        *,
        context: list[str] | None = None,
        options: ProviderOptions | None = None,
    ) -> ProviderResponse:
        """Rich entry point with structured response and per-call options."""
        ...


def _parse_run_summary_block(prompt: str) -> Dict[str, Any]:
    """Extract structured fields from the ``[run summary]`` prompt block.

    The orchestrator builds a deterministic ``[run summary]`` block
    via ``copilot._format_run_summary_for_prompt``. Parsing it back
    out lets the offline template render a useful run-specific
    artifact (scenario name, technique ids, per-step timeline,
    detection counts) instead of the generic stub.

    The parser is intentionally tolerant: lines that don't match
    the documented shape are skipped, missing fields fall back to
    sensible defaults, and the ``module_statuses`` sub-block is
    only consumed when explicitly indented under its key. Returns
    an empty dict when no ``[run summary]`` block is present.
    """
    if "[run summary]" not in prompt:
        return {}
    summary: Dict[str, Any] = {}
    techniques: list[str] = []
    statuses: list[Dict[str, str]] = []
    in_summary = False
    in_statuses = False
    for raw_line in prompt.splitlines():
        if raw_line.strip() == "[run summary]":
            in_summary = True
            continue
        if not in_summary:
            continue
        if not raw_line.startswith(" "):
            # Block ends at the first non-indented line after
            # ``[run summary]`` — keeps stray prompt continuation
            # text from leaking into parsed values.
            break
        if in_statuses:
            stripped = raw_line.lstrip()
            if not stripped.startswith("-"):
                # End of the statuses sub-block (any non-list line
                # at the same indent terminates it).
                in_statuses = False
            else:
                # Shape: ``- step_id: status``. ``step_id`` can
                # itself contain a colon (orchestrator key
                # ``module:step_id``), so partition on the LAST
                # colon to keep the full step string intact.
                payload = stripped.lstrip("-").strip()
                if ":" in payload:
                    step, _, status = payload.rpartition(":")
                    statuses.append(
                        {"step": step.strip(), "status": status.strip()}
                    )
                continue
        line = raw_line.strip()
        if line.startswith("module_statuses"):
            in_statuses = True
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key == "scenario":
            summary["scenario_name"] = value
        elif key == "objective":
            # The orchestrator collapses multi-paragraph YAML
            # objectives into a single line before formatting them
            # into the prompt block, so we can read it back as one
            # field. The narrative renderer uses this to ground
            # the rendered prose in the chain story.
            summary["scenario_objective"] = value
        elif key == "run_id":
            summary["run_id"] = value
        elif key == "module_count":
            try:
                summary["module_count"] = int(value)
            except ValueError:
                pass
        elif key == "steps":
            # Shape: "X success / Y non-success".
            summary["steps_summary"] = value
            try:
                parts = value.split("/")
                summary["successful_steps"] = int(parts[0].split()[0])
                summary["failed_steps"] = int(parts[1].split()[0])
            except (IndexError, ValueError):
                pass
        elif key == "techniques_observed":
            try:
                summary["techniques_total"] = int(value)
            except ValueError:
                pass
        elif key == "technique_ids":
            techniques = [t.strip() for t in value.split(",") if t.strip()]
        elif key == "detection_hints":
            try:
                summary["detection_hint_count"] = int(value)
            except ValueError:
                pass
    if techniques:
        summary["techniques"] = techniques
    if statuses:
        summary["module_statuses"] = statuses
    return summary


def _detect_prompt_intent(prompt: str) -> str:
    """Return ``plan`` / ``narrate`` / ``suggest_detections`` / ``""``.

    The copilot's three public methods build distinct prompt
    prefixes — detect them so the template renders an appropriate
    structure rather than a generic blob.
    """
    head = prompt[:240].lower()
    if "scenario yaml" in head or "generate a concise bluefire scenario" in head:
        return "plan"
    if "soc incident narrative" in head or "soc-style run narrative" in head:
        return "narrate"
    if "detection suggestions" in head or "detection guidance" in head:
        return "suggest_detections"
    return ""


def _format_blocked_steps(summary: Mapping[str, Any]) -> list[str]:
    """List the step ids whose status is non-success, capped at 8."""
    statuses = summary.get("module_statuses") or []
    if not isinstance(statuses, list):
        return []
    blocked: list[str] = []
    for entry in statuses:
        if not isinstance(entry, Mapping):
            continue
        status = str(entry.get("status", "")).lower()
        if status in {"success", ""}:
            continue
        step = str(entry.get("step", ""))
        if step:
            blocked.append(f"{step} ({status})")
    return blocked[:8]


def _render_template_narrative(summary: Mapping[str, Any], model: str) -> str:
    """Plain-English SOC narrative from a parsed run summary."""
    scenario = summary.get("scenario_name") or "(unspecified scenario)"
    objective = str(summary.get("scenario_objective") or "").strip()
    run_id = summary.get("run_id") or "(unknown run id)"
    module_count = summary.get("module_count")
    successful = summary.get("successful_steps", 0)
    failed = summary.get("failed_steps", 0)
    technique_ids = summary.get("techniques") or []
    techniques_total = summary.get("techniques_total", len(technique_ids))
    detection_hint_count = summary.get("detection_hint_count", 0)
    statuses = summary.get("module_statuses") or []
    blocked = _format_blocked_steps(summary)

    lines: list[str] = [
        "TemplateProvider response",
        f"- model: {model}",
        "- mode: offline (deterministic template, no network)",
        "",
        "# Run summary",
        f"- scenario: {scenario}",
    ]
    if objective:
        # Surface the operator-authored chain narrative immediately
        # below the scenario name so a defender reading the
        # offline copilot artifact sees the chain story before the
        # technical detail. Same wording the dashboard header and
        # markdown report's "Scenario objective" section use.
        lines.append(f"- objective: {objective}")
    lines.append(f"- run_id: {run_id}")
    if isinstance(module_count, int):
        lines.append(
            f"- modules: {module_count} "
            f"({successful} success / {failed} non-success)"
        )
    if technique_ids:
        listed = ", ".join(technique_ids[:24])
        more = "" if len(technique_ids) <= 24 else f" (+{len(technique_ids) - 24} more)"
        lines.append(f"- techniques observed ({techniques_total}): {listed}{more}")
    elif isinstance(techniques_total, int) and techniques_total:
        lines.append(f"- techniques observed: {techniques_total}")
    lines.append(f"- detection drafts: {detection_hint_count}")

    if statuses:
        lines.append("")
        lines.append("## Step-by-step timeline")
        for index, entry in enumerate(statuses[:16], start=1):
            if not isinstance(entry, Mapping):
                continue
            step = entry.get("step", "")
            status = entry.get("status", "")
            lines.append(f"{index}. {step} -> {status}")
        if len(statuses) > 16:
            lines.append(f"... (+{len(statuses) - 16} more steps not shown)")

    lines.append("")
    lines.append("## Findings")
    if isinstance(successful, int):
        lines.append(f"- {successful} step(s) completed successfully.")
    if blocked:
        lines.append(
            f"- {len(blocked)} step(s) blocked or errored: "
            + ", ".join(blocked)
        )
    elif isinstance(failed, int) and failed == 0:
        lines.append("- 0 step(s) blocked or errored.")
    if technique_ids:
        lines.append(
            f"- ATT&CK coverage: {', '.join(technique_ids[:8])}"
            + ("..." if len(technique_ids) > 8 else "")
        )
    if isinstance(detection_hint_count, int) and detection_hint_count > 0:
        lines.append(
            f"- {detection_hint_count} detection draft(s) emitted across "
            "Sigma / YARA-L / SPL."
        )

    lines.append("")
    lines.append("## Suggested next validations")
    if blocked:
        lines.append(
            f"- Re-run with `show-run {run_id}` and inspect message text "
            "for each blocked step."
        )
    lines.append(
        f"- Run `validate-run {run_id}` to confirm bundle completeness."
    )
    lines.append(
        f"- Open output/{run_id}/index.html to review the run dashboard."
    )
    lines.append(
        f"- Inspect output/{run_id}/detections/ for per-engine drafts; "
        "Sigma and YARA-L derive technique-specific discriminators from "
        "the module hint, SPL stays draft / starter."
    )
    if technique_ids:
        lines.append(
            "- For each technique observed, confirm at least one detection "
            "draft fires on representative production telemetry."
        )
    return "\n".join(lines) + "\n"


def _render_template_detections(summary: Mapping[str, Any], model: str) -> str:
    """Detection-strategy summary from a parsed run summary."""
    scenario = summary.get("scenario_name") or "(unspecified scenario)"
    run_id = summary.get("run_id") or "(unknown run id)"
    technique_ids = summary.get("techniques") or []
    techniques_total = summary.get("techniques_total", len(technique_ids))
    detection_hint_count = summary.get("detection_hint_count", 0)

    lines: list[str] = [
        "TemplateProvider response",
        f"- model: {model}",
        "- mode: offline (deterministic template, no network)",
        "",
        f"# Detection guidance for run {run_id}",
        f"- scenario: {scenario}",
        f"- techniques observed: {techniques_total}",
        f"- detection drafts: {detection_hint_count}",
        "- detection draft maturity:"
        " Sigma (most mature), YARA-L (medium), SPL (draft / starter).",
    ]
    if technique_ids:
        lines.append("")
        lines.append("## Per-technique pointers")
        for technique in technique_ids[:12]:
            lines.append(
                f"- {technique}: review the Sigma rule's logsource block; "
                "tune the SPL `where` clauses for your environment "
                "(default sourcetype mapping is in the rule's leading "
                "DRAFT comment)."
            )
        if len(technique_ids) > 12:
            lines.append(
                f"... (+{len(technique_ids) - 12} more techniques not shown)"
            )
    lines.append("")
    lines.append("## Operator next steps")
    lines.append(
        f"- Open output/{run_id}/detections/ to inspect per-technique drafts."
    )
    lines.append(
        "- Treat Sigma drafts as the most reusable starting point; "
        "YARA-L and SPL drafts typically need per-environment field tuning."
    )
    lines.append(
        "- Validate every draft against representative production telemetry "
        "before deploying as a production detection."
    )
    return "\n".join(lines) + "\n"


def _render_template_plan(summary: Mapping[str, Any], goal: str, model: str) -> str:
    """Scenario-skeleton plan from a parsed run summary."""
    technique_ids = summary.get("techniques") or []
    scenario = summary.get("scenario_name") or "planned-scenario"

    lines: list[str] = [
        "TemplateProvider response",
        f"- model: {model}",
        "- mode: offline (deterministic template, no network)",
        "",
        f"# Plan goal: {goal[:200]}",
        "",
        "# Suggested scenario skeleton (review before deploying)",
        "id: planned-scenario",
        f"name: {scenario}",
        "objective: |",
        f"  Generated by the offline template provider for goal: {goal[:120]}.",
        "  Refine objective, scope, and module composition before running.",
        "attack_coverage:",
    ]
    if technique_ids:
        for technique in technique_ids[:16]:
            lines.append(f"  - {technique}")
    else:
        lines.append("  - T0000  # add observed or target techniques")
    lines.append("steps:")
    lines.append("  - id: step-1")
    lines.append("    name: First scenario step")
    lines.append("    module: discovery  # adapt module to the technique")
    lines.append("    params:")
    lines.append("      network_touch: false")
    lines.append("")
    lines.append("# Notes")
    lines.append(
        "- This skeleton is intentionally conservative (network_touch=false, "
        "no remote AI). Adjust per-step params for the technique you want to emulate."
    )
    return "\n".join(lines) + "\n"


def _render_template_generic(prompt: str, context_preview: str, model: str) -> str:
    """Legacy generic stub — preserved for prompts without a run summary."""
    scrubbed = prompt.replace("[REDACTED]", "***").replace("\n", " ").strip()
    return (
        "TemplateProvider response\n"
        f"- model: {model}\n"
        f"- prompt_summary: {scrubbed[:220]}\n"
        f"- context_preview: {context_preview or 'none'}\n"
        "- recommendation: refine scenario steps, review detection coverage,"
        " validate telemetry\n"
    )


@dataclass
class TemplateProvider:
    """Deterministic, no-network offline provider.

    The template provider intentionally accepts ``options`` for
    interface parity with the remote backends but ignores fields
    like ``temperature`` and ``max_tokens`` that have no meaning
    for a deterministic local renderer. ``options.metadata`` is
    forwarded onto the response so per-call tags survive.

    Output strategy:

    - When the prompt carries a ``[run summary]`` block (the
      orchestrator's :func:`copilot._format_run_summary_for_prompt`
      injects one for every scenario run), the provider parses
      out scenario name / run id / step count / techniques /
      detection counts / per-step status and renders an
      intent-aware artifact (SOC narrative for ``narrate``,
      detection-strategy summary for ``suggest_detections``,
      scenario skeleton for ``plan``).
    - When no summary is present, the legacy generic stub
      (``prompt_summary`` + ``context_preview`` + a one-line
      recommendation) is returned, so out-of-tree callers that
      only feed bare prompts keep working.

    Output remains deterministic: the same input prompt produces
    the same body, byte for byte, so unit tests and report
    rendering can rely on it.
    """

    model: str = "template-default"
    name: str = "template"

    def complete(self, prompt: str, context: list[str] | None = None) -> str:
        return self.generate(prompt, context=context).text

    def generate(
        self,
        prompt: str,
        *,
        context: list[str] | None = None,
        options: ProviderOptions | None = None,
    ) -> ProviderResponse:
        context_preview = " | ".join((context or [])[:2])[:220]
        summary = _parse_run_summary_block(prompt)
        if summary:
            intent = _detect_prompt_intent(prompt)
            if intent == "narrate":
                text = _render_template_narrative(summary, self.model)
            elif intent == "suggest_detections":
                text = _render_template_detections(summary, self.model)
            elif intent == "plan":
                # The plan-intent prompt's first line carries the goal.
                goal_line = ""
                for line in prompt.splitlines():
                    stripped = line.strip()
                    if stripped.lower().startswith("goal:"):
                        goal_line = stripped[5:].strip()
                        break
                text = _render_template_plan(summary, goal_line, self.model)
            else:
                # Run summary present but intent is unknown — render
                # narrative as the safest default since it surfaces
                # all the structured fields.
                text = _render_template_narrative(summary, self.model)
        else:
            text = _render_template_generic(prompt, context_preview, self.model)
        metadata: Dict[str, Any] = {}
        if options is not None and options.metadata:
            metadata.update(options.metadata)
        return ProviderResponse(
            text=text,
            provider=self.name,
            model=self.model,
            finish_reason="stop",
            network_disabled=True,
            metadata=metadata,
        )


@dataclass
class OpenAICompatibleProvider:
    """Vendor-neutral keyless stub for any recognised remote provider name.

    Despite the legacy class name, this is **not** an OpenAI-specific
    implementation — it is the placeholder used for every supported
    remote provider name (openai, anthropic, gemini, grok, ollama,
    llama.cpp, lm-studio, openai_compatible) until Phase 2 wires real
    backends in via :meth:`ProviderFactory.register_provider`. Its
    ``generate()`` (and therefore ``complete()``) method intentionally
    makes no outbound calls and works without an API key, so the
    local-first baseline stays offline even when an operator selects
    a remote provider.

    ``provider_settings`` carries the raw ``ai_providers.<name>`` sub-
    block (see ``core.configuration.get_ai_config``) so a future
    backend can opt into vendor-specific keys (organisation IDs,
    region pins, request-headers) without changing the factory
    contract.
    """

    name: str
    model: str
    endpoint: str = ""
    api_key: str = ""
    provider_settings: Dict[str, Any] = field(default_factory=dict)

    def complete(self, prompt: str, context: list[str] | None = None) -> str:
        return self.generate(prompt, context=context).text

    def generate(
        self,
        prompt: str,
        *,
        context: list[str] | None = None,
        options: ProviderOptions | None = None,
    ) -> ProviderResponse:
        # Security-first default: avoid outbound calls unless an
        # explicit code path is added later (see Phase 2 HTTP backend
        # registration via ProviderFactory.register_provider).
        _ = context
        text = (
            f"{self.name} provider configured with model={self.model}. "
            "Network completion is intentionally disabled by default.\n"
            f"prompt_summary: {prompt[:220]}"
        )
        metadata: Dict[str, Any] = {"endpoint": self.endpoint}
        if self.provider_settings:
            metadata["provider_settings_keys"] = sorted(self.provider_settings)
        if options is not None and options.metadata:
            metadata.update(dict(options.metadata))
        return ProviderResponse(
            text=text,
            provider=self.name,
            model=self.model,
            finish_reason="stop",
            network_disabled=True,
            metadata=metadata,
        )


# ---------------------------------------------------------------------------
# Provider registry + factory
# ---------------------------------------------------------------------------


# Type of a registered provider factory. Receives the resolved
# AI-config dict (output of ``core.configuration.get_ai_config``)
# plus the already-normalised canonical provider name + model + the
# resolved API key (env-resolved by the factory) and returns an
# ``LLMProvider``-compatible instance.
ProviderFactoryFn = Callable[..., "LLMProvider"]


class ProviderFactory:
    """Build a provider from config while preserving user choice.

    Phase 2 backends register themselves via :meth:`register_provider`,
    which overrides the default keyless-stub behaviour for a
    canonical name. Phase 1 ships only the stub.
    """

    OFFLINE_NAMES = {"none", "template", ""}

    # Canonical remote-provider names. Aliases below resolve to one
    # of these. Adding a new canonical name means adding it here AND
    # (if it has a real backend) registering a factory via
    # ``register_provider``.
    _CANONICAL_REMOTE_NAMES = (
        "openai",
        "anthropic",
        "gemini",
        "grok",
        "ollama",
        "openai_compatible",
        "llama.cpp",
        "lm-studio",
    )

    # Operator-friendly alias -> canonical mapping. Keep this small;
    # only add aliases that are commonly used in the wild.
    _ALIASES = {
        "google": "gemini",
        "google_gemini": "gemini",
        "xai": "grok",
        "x.ai": "grok",
        "claude": "anthropic",
    }

    # Set of recognised remote names (canonical + aliases). Kept as
    # a public attribute for back-compat with tests that probe the
    # set directly.
    SUPPORTED_REMOTE = set(_CANONICAL_REMOTE_NAMES) | set(_ALIASES.keys())

    # Mapping of canonical name -> factory. Phase 1 leaves every
    # remote slot bound to the keyless stub; Phase 2 overrides
    # specific entries via ``register_provider``.
    _REGISTRY: Dict[str, ProviderFactoryFn] = {}

    @classmethod
    def normalise_name(cls, provider_name: str | None) -> str:
        """Return the canonical provider name for ``provider_name``.

        Lower-cases, strips whitespace, and applies alias resolution.
        Unknown names pass through unchanged so the caller can decide
        whether to fall back to the template provider.
        """
        canonical = (provider_name or "template").lower().strip()
        return cls._ALIASES.get(canonical, canonical)

    @classmethod
    def known_canonical_names(cls) -> tuple[str, ...]:
        """Canonical (non-alias) provider names recognised by the factory."""
        return ("template",) + cls._CANONICAL_REMOTE_NAMES

    @classmethod
    def register_provider(
        cls,
        canonical_name: str,
        factory: ProviderFactoryFn,
    ) -> None:
        """Register a real backend factory for a canonical provider name.

        Phase 2 entry point. The registered factory replaces the
        default keyless-stub behaviour for this canonical name. The
        factory is called with keyword arguments matching what
        :meth:`from_ai_config` resolves: ``provider``, ``model``,
        ``api_base``, ``api_key``, ``provider_settings`` (and any
        future fields). Implementations should accept ``**kwargs`` for
        forward-compat.

        Raises ``ValueError`` for unknown canonical names so typos in
        Phase 2 wiring fail loudly.
        """
        canonical = canonical_name.lower().strip()
        if canonical not in cls._CANONICAL_REMOTE_NAMES and canonical != "template":
            allowed = ", ".join(cls.known_canonical_names())
            raise ValueError(
                f"register_provider: {canonical_name!r} is not a known canonical "
                f"name. Expected one of: {allowed}"
            )
        cls._REGISTRY[canonical] = factory

    @staticmethod
    def build(provider_name: str, model: str, cfg: Mapping[str, Any]) -> LLMProvider:
        provider_key = ProviderFactory.normalise_name(provider_name)
        if provider_key in ProviderFactory.OFFLINE_NAMES:
            return TemplateProvider(model=model or "template-default")
        if provider_key in ProviderFactory._CANONICAL_REMOTE_NAMES:
            return OpenAICompatibleProvider(
                name=provider_key,
                model=model or "default",
                endpoint=str(cfg.get("api_base", "") or cfg.get("endpoint", "")),
                api_key=str(cfg.get("api_key", "")),
            )
        return TemplateProvider(model="template-default")

    @staticmethod
    def from_ai_config(ai_config: Mapping[str, Any]) -> LLMProvider:
        """Build a provider from the resolved ``get_ai_config`` output.

        Consumes the documented AI-config shape (provider, model,
        api_base, api_key_env, provider_settings) so callers no longer
        need to hand-marshal raw ``modules.ai`` dict reads. Honours the
        same provider/offline-fallback rules as :meth:`build`, plus:

        - ``api_key_env``: when set, the matching environment variable
          is read at construction time and passed as ``api_key``. The
          env var lookup is the *only* effect — a missing env var
          becomes an empty ``api_key`` rather than raising. No
          environment is touched when ``api_key_env`` is empty.
        - ``provider_settings``: forwarded to
          :class:`OpenAICompatibleProvider` (or to a Phase 2 backend
          registered via :meth:`register_provider`) so vendor-
          specific config can flow through without re-plumbing the
          factory.
        - Alias names (``google``, ``xai``, ``claude``) are normalised
          to their canonical equivalents (``gemini``, ``grok``,
          ``anthropic``) before dispatch.
        - Garbage / non-mapping input falls back to
          :class:`TemplateProvider` rather than raising.

        No network calls. No SDK imports. Safe to call when the
        runtime is in offline / template mode.
        """
        if not isinstance(ai_config, Mapping):
            return TemplateProvider(model="template-default")

        provider_key = ProviderFactory.normalise_name(ai_config.get("provider"))
        model = str(ai_config.get("model") or "default")

        if provider_key in ProviderFactory.OFFLINE_NAMES:
            return TemplateProvider(model=model or "template-default")

        if provider_key not in ProviderFactory._CANONICAL_REMOTE_NAMES:
            return TemplateProvider(model="template-default")

        api_key_env = str(ai_config.get("api_key_env") or "").strip()
        api_key = os.environ.get(api_key_env, "") if api_key_env else ""

        provider_settings_raw = ai_config.get("provider_settings")
        provider_settings: Dict[str, Any] = (
            dict(provider_settings_raw)
            if isinstance(provider_settings_raw, Mapping)
            else {}
        )
        api_base = str(ai_config.get("api_base") or "")

        # Phase 2 hook: a registered factory replaces the default
        # keyless stub for this canonical name. The registered
        # factory MUST accept the documented kwargs and may accept
        # **kwargs for forward-compat.
        registered = ProviderFactory._REGISTRY.get(provider_key)
        if registered is not None:
            return registered(
                provider=provider_key,
                model=model,
                api_base=api_base,
                api_key=api_key,
                provider_settings=provider_settings,
                ai_config=dict(ai_config),
            )

        return OpenAICompatibleProvider(
            name=provider_key,
            model=model,
            endpoint=api_base,
            api_key=api_key,
            provider_settings=provider_settings,
        )
